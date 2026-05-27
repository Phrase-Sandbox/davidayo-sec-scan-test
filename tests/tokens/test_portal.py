"""Tests for the ``/portal/*`` self-service routes.

Covers the three flows that matter for shipping PR 3:

- Browser self-service (``GET /``, ``POST /tokens``, ``POST /tokens/revoke``)
- CLI browser-callback (``GET /cli/login`` consent → ``POST /cli/login/complete``
  → 303 to loopback with the token in the query string)
- X-Userinfo decoding: missing / malformed headers 401; valid headers resolve
  the right ``PhraseUser``; ``ADMIN_LOCAL_BYPASS`` returns a fake admin so
  local-dev works without an Okta proxy.
"""

from __future__ import annotations

import base64
import json
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from security_scanner.tokens import registry as token_registry
from security_scanner.tokens.db import Base
from security_scanner.tokens.models import AuditEvent, AuditEventType, LocalScanToken
from security_scanner.tokens.portal import router as portal_router


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    # ADMIN_LOCAL_BYPASS=false so the X-Userinfo path is exercised by
    # default. Individual tests flip it back on as needed.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("USE_TOKEN_REGISTRY", "true")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://x:x@x:5432/x")
    monkeypatch.setenv("ADMIN_GROUP_NAME", "security-scanner-admins")
    monkeypatch.setenv("ADMIN_LOCAL_BYPASS", "false")
    monkeypatch.setenv("GITHUB_APP_ID", "1")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", "-----BEGIN PRIVATE KEY-----")
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_ID", "Iv1.test")
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_SECRET", "secret")
    monkeypatch.setenv("PHRASE_SCAN_TOKEN", "ci-gate-token")


@pytest.fixture
async def session_factory(monkeypatch):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(
        "security_scanner.tokens.portal.get_session_factory", lambda: factory
    )
    try:
        yield factory
    finally:
        await engine.dispose()


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(portal_router)
    # follow_redirects=False so we can assert the 303 → loopback hop.
    return TestClient(app, follow_redirects=False)


def _userinfo(email: str, *, groups: list[str] | None = None) -> str:
    payload = {
        "sub": email,
        "email": email,
        "name": email.split("@")[0],
        "groups": groups or [],
    }
    return base64.b64encode(json.dumps(payload).encode()).decode()


# --- X-Userinfo decoding -----------------------------------------------------


def test_portal_index_401_without_userinfo(client):
    r = client.get("/portal/")
    assert r.status_code == 401
    assert "X-Userinfo" in r.json()["detail"]


def test_portal_index_401_with_garbage_userinfo(client):
    r = client.get("/portal/", headers={"X-Userinfo": "@@@not-base64@@@"})
    assert r.status_code == 401


def test_portal_index_401_with_userinfo_missing_email(client):
    payload = base64.b64encode(json.dumps({"sub": "x", "groups": []}).encode()).decode()
    r = client.get("/portal/", headers={"X-Userinfo": payload})
    assert r.status_code == 401


def test_portal_index_accepts_padding_optional_base64(client, session_factory):
    # Same payload, stripped of trailing '=' padding.
    raw = _userinfo("dave@phrase.com").rstrip("=")
    r = client.get("/portal/", headers={"X-Userinfo": raw})
    assert r.status_code == 200
    assert "dave@phrase.com" in r.text


def test_admin_local_bypass_redirects_admin_to_admin_panel(client, session_factory, monkeypatch):
    """Admin users hitting /portal/ should be redirected to /admin/tokens."""
    monkeypatch.setenv("ADMIN_LOCAL_BYPASS", "true")
    r = client.get("/portal/", follow_redirects=False)
    # Admins are redirected to their panel; the bypass user has admin group membership.
    assert r.status_code == 302
    assert r.headers["location"] == "/admin/tokens"


# --- Self-service flow -------------------------------------------------------


async def test_index_shows_no_token_then_issue_then_active(client, session_factory):
    headers = {"X-Userinfo": _userinfo("alice@phrase.com")}

    r = client.get("/portal/", headers=headers)
    assert r.status_code == 200
    assert "don" in r.text and "active token" in r.text.lower()

    r = client.post("/portal/tokens", headers=headers)
    assert r.status_code == 200
    # The plaintext token appears exactly once in the response.
    assert "phs_local_tok-" in r.text
    # And not in a URL (would land in browser history).
    assert "?token=" not in r.text

    r = client.get("/portal/", headers=headers)
    assert r.status_code == 200
    assert "active token" in r.text.lower()

    async with session_factory() as session:
        rows = (await session.execute(select(LocalScanToken))).scalars().all()
        events = (
            (
                await session.execute(
                    select(AuditEvent).where(
                        AuditEvent.event_type == AuditEventType.token_issued
                    )
                )
            )
            .scalars()
            .all()
        )
    assert len(rows) == 1
    assert rows[0].user_email == "alice@phrase.com"
    assert len(events) == 1


async def test_rotate_preserves_token_id_prefix(client, session_factory):
    headers = {"X-Userinfo": _userinfo("bob@phrase.com")}

    r1 = client.post("/portal/tokens", headers=headers)
    assert r1.status_code == 200
    r2 = client.post("/portal/tokens", headers=headers)
    assert r2.status_code == 200

    async with session_factory() as session:
        rows = (
            (
                await session.execute(
                    select(LocalScanToken).order_by(LocalScanToken.issued_at)
                )
            )
            .scalars()
            .all()
        )
        events = (
            (await session.execute(select(AuditEvent))).scalars().all()
        )
    assert len(rows) == 2
    # Same token_id prefix preserved across rotation — audit continuity.
    assert rows[0].token_id == rows[1].token_id
    # First row got revoked, second is active.
    assert rows[0].revoked_at is not None
    assert rows[1].revoked_at is None

    types = sorted(e.event_type.value for e in events)
    assert "token_issued" in types
    assert "token_rotated" in types


async def test_revoke_marks_active_token_revoked(client, session_factory):
    headers = {"X-Userinfo": _userinfo("carol@phrase.com")}
    client.post("/portal/tokens", headers=headers)

    r = client.post("/portal/tokens/revoke", headers=headers)
    assert r.status_code == 200
    assert "Token revoked." in r.text

    async with session_factory() as session:
        row = (await session.execute(select(LocalScanToken))).scalar_one()
    assert row.revoked_at is not None
    assert row.revoked_by == "self"


def test_revoke_with_no_active_token_is_friendly(client, session_factory):
    headers = {"X-Userinfo": _userinfo("dave@phrase.com")}
    r = client.post("/portal/tokens/revoke", headers=headers)
    assert r.status_code == 200
    assert "No active token" in r.text


# --- CLI browser-callback ----------------------------------------------------


def test_cli_consent_renders_with_hostname_and_port(client, session_factory):
    headers = {"X-Userinfo": _userinfo("eve@phrase.com")}
    r = client.get(
        "/portal/cli/login",
        params={"callback_port": 8765, "hostname": "eve-mbp"},
        headers=headers,
    )
    assert r.status_code == 200
    assert "eve-mbp" in r.text
    assert "8765" in r.text


def test_cli_consent_rejects_low_port(client, session_factory):
    headers = {"X-Userinfo": _userinfo("eve@phrase.com")}
    r = client.get(
        "/portal/cli/login",
        params={"callback_port": 80, "hostname": "eve-mbp"},
        headers=headers,
    )
    # FastAPI's Query(ge=1024) returns 422.
    assert r.status_code == 422


def test_cli_consent_rejects_bad_hostname(client, session_factory):
    headers = {"X-Userinfo": _userinfo("eve@phrase.com")}
    r = client.get(
        "/portal/cli/login",
        params={"callback_port": 8765, "hostname": "evil; curl evil.com"},
        headers=headers,
    )
    assert r.status_code == 400


async def test_cli_complete_issues_and_redirects_to_loopback(
    client, session_factory
):
    headers = {"X-Userinfo": _userinfo("frank@phrase.com")}
    r = client.post(
        "/portal/cli/login/complete",
        data={"callback_port": "8765", "hostname": "frank-mbp"},
        headers=headers,
    )
    assert r.status_code == 303
    parsed = urlparse(r.headers["location"])
    assert parsed.scheme == "http"
    assert parsed.hostname == "127.0.0.1"
    assert parsed.port == 8765
    qs = parse_qs(parsed.query)
    assert "token" in qs
    assert qs["token"][0].startswith("phs_local_tok-")

    # And a token row was created.
    async with session_factory() as session:
        row = (await session.execute(select(LocalScanToken))).scalar_one()
    assert row.user_email == "frank@phrase.com"
    assert token_registry.parse_token(qs["token"][0])[0] == row.token_id
