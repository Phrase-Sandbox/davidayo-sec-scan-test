"""Tests for the Okta OIDC SSO routes (/portal/oauth/init and /portal/oauth/callback)."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from security_scanner.tokens.db import Base
from security_scanner.tokens.models import User, UserRole
from security_scanner.tokens.okta import router as okta_router

_ADMIN_GROUP = "security-scanner-admins"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("USE_TOKEN_REGISTRY", "true")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://x:x@x:5432/x")
    monkeypatch.setenv("ADMIN_GROUP_NAME", _ADMIN_GROUP)
    monkeypatch.setenv("ADMIN_LOCAL_BYPASS", "false")
    monkeypatch.setenv("GITHUB_APP_ID", "1")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", "-----BEGIN PRIVATE KEY-----")
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_ID", "Iv1.test")
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_SECRET", "secret")
    monkeypatch.setenv("PHRASE_SCAN_TOKEN", "ci-gate-token")
    monkeypatch.setenv("SCANNER_ENCRYPTION_KEY", "xHNLN3iy0J83h8gAWBzBvjMdLmevdkyKNzXX5O_YdJI=")
    # Okta config
    monkeypatch.setenv("OKTA_DOMAIN", "test.okta.com")
    monkeypatch.setenv("OKTA_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("OKTA_CLIENT_SECRET", "test-client-secret")
    monkeypatch.setenv("OKTA_REDIRECT_URI", "https://scanner.test/portal/oauth/callback")
    monkeypatch.setenv("OKTA_EMAIL_DOMAIN", "phrase.com")
    monkeypatch.setenv("PROTECTED_ADMIN_EMAILS", "admin@phrase.com")
    monkeypatch.setenv("LOCAL_PORTAL_PASSWORD", "")


@pytest.fixture
async def session_factory(monkeypatch):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr("security_scanner.tokens.okta.get_session_factory", lambda: factory)
    monkeypatch.setattr("security_scanner.tokens.auth.get_session_factory", lambda: factory)
    try:
        yield factory
    finally:
        await engine.dispose()


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(okta_router)
    return TestClient(app, follow_redirects=False)


def _make_claims(
    email: str = "user@phrase.com", sub: str = "okta-sub-123", nonce: str = "test-nonce"
) -> dict:
    return {
        "email": email,
        "sub": sub,
        "name": "Test User",
        "email_verified": True,
        "nonce": nonce,
    }


# ---------------------------------------------------------------------------
# /portal/oauth/init
# ---------------------------------------------------------------------------


def test_okta_init_redirects_to_okta(client):
    r = client.get("/portal/oauth/init")
    assert r.status_code == 302
    location = r.headers["location"]
    assert "test.okta.com" in location
    assert "response_type=code" in location
    assert "okta_oauth_state" in r.headers.get("set-cookie", "")


def test_okta_init_503_when_not_configured(client, monkeypatch):
    monkeypatch.setenv("OKTA_DOMAIN", "")
    r = client.get("/portal/oauth/init")
    assert r.status_code == 503


# ---------------------------------------------------------------------------
# /portal/oauth/callback — CSRF validation
# ---------------------------------------------------------------------------


def test_okta_callback_missing_state_cookie(client):
    r = client.get("/portal/oauth/callback", params={"code": "abc", "state": "xyz"})
    assert r.status_code == 400
    assert "OAuth state" in r.text


def test_okta_callback_wrong_state(client):
    from security_scanner.tokens.okta import _pack_state

    cookie = _pack_state("correct-state", "nonce-123")
    client.cookies.set("okta_oauth_state", cookie)
    r = client.get("/portal/oauth/callback", params={"code": "abc", "state": "WRONG-STATE"})
    assert r.status_code == 400
    assert "mismatch" in r.text.lower() or "state" in r.text.lower()


# ---------------------------------------------------------------------------
# /portal/oauth/callback — successful provisioning
# ---------------------------------------------------------------------------


async def test_okta_callback_provisions_new_user(client, session_factory):
    from security_scanner.tokens.okta import _pack_state

    state = "test-state-abc"
    nonce = "test-nonce-xyz"
    cookie = _pack_state(state, nonce)
    client.cookies.set("okta_oauth_state", cookie)

    claims = _make_claims(nonce=nonce)

    with (
        patch(
            "security_scanner.tokens.okta._exchange_code",
            new=AsyncMock(return_value="fake.id.token"),
        ),
        patch("security_scanner.tokens.okta._validate_id_token", return_value=claims),
    ):
        r = client.get("/portal/oauth/callback", params={"code": "auth-code", "state": state})

    assert r.status_code == 302
    assert r.headers["location"] == "/portal/"
    assert "portal_session" in r.headers.get("set-cookie", "")

    async with session_factory() as sess:
        user = await sess.get(User, "user@phrase.com")
    assert user is not None
    assert user.okta_user_id == "okta-sub-123"
    assert user.auth_provider == "okta"
    assert user.role == UserRole.user


async def test_okta_callback_protected_admin_provisioned_as_admin(client, session_factory):
    from security_scanner.tokens.okta import _pack_state

    state = "state-admin"
    nonce = "nonce-admin"
    cookie = _pack_state(state, nonce)
    client.cookies.set("okta_oauth_state", cookie)
    claims = _make_claims(email="admin@phrase.com", sub="admin-sub-999", nonce=nonce)

    with (
        patch(
            "security_scanner.tokens.okta._exchange_code",
            new=AsyncMock(return_value="fake.id.token"),
        ),
        patch("security_scanner.tokens.okta._validate_id_token", return_value=claims),
    ):
        r = client.get("/portal/oauth/callback", params={"code": "auth-code", "state": state})

    assert r.status_code == 302
    async with session_factory() as sess:
        user = await sess.get(User, "admin@phrase.com")
    assert user.role == UserRole.admin


async def test_okta_callback_updates_existing_okta_user(client, session_factory):
    from datetime import UTC, datetime

    from security_scanner.tokens.okta import _pack_state

    # Pre-create an existing Okta user
    async with session_factory() as sess:
        sess.add(
            User(
                email="user@phrase.com",
                okta_user_id="okta-sub-123",
                auth_provider="okta",
                role=UserRole.user,
                is_active=True,
                created_at=datetime.now(UTC),
            )
        )
        await sess.commit()

    state = "state-update"
    nonce = "nonce-update"
    client.cookies.set("okta_oauth_state", _pack_state(state, nonce))
    claims = _make_claims(nonce=nonce)

    with (
        patch(
            "security_scanner.tokens.okta._exchange_code",
            new=AsyncMock(return_value="fake.id.token"),
        ),
        patch("security_scanner.tokens.okta._validate_id_token", return_value=claims),
    ):
        r = client.get("/portal/oauth/callback", params={"code": "auth-code", "state": state})

    assert r.status_code == 302
    # Only one user row — not duplicated
    async with session_factory() as sess:
        rows = (await sess.execute(select(User))).scalars().all()
    assert len(rows) == 1


def test_okta_callback_rejects_wrong_domain(client, session_factory):
    from security_scanner.tokens.okta import _pack_state

    state = "state-bad"
    nonce = "nonce-bad"
    client.cookies.set("okta_oauth_state", _pack_state(state, nonce))
    claims = _make_claims(email="hacker@evil.com", nonce=nonce)

    with (
        patch(
            "security_scanner.tokens.okta._exchange_code",
            new=AsyncMock(return_value="fake.id.token"),
        ),
        patch("security_scanner.tokens.okta._validate_id_token", return_value=claims),
    ):
        r = client.get("/portal/oauth/callback", params={"code": "auth-code", "state": state})

    assert r.status_code == 403


async def test_okta_callback_rejects_local_account_conflict(client, session_factory):
    from datetime import UTC, datetime

    from security_scanner.tokens.okta import _pack_state

    # Pre-create a LOCAL user with the same email
    async with session_factory() as sess:
        sess.add(
            User(
                email="user@phrase.com",
                auth_provider="local",
                role=UserRole.user,
                is_active=True,
                created_at=datetime.now(UTC),
            )
        )
        await sess.commit()

    state = "state-conflict"
    nonce = "nonce-conflict"
    client.cookies.set("okta_oauth_state", _pack_state(state, nonce))
    claims = _make_claims(nonce=nonce)

    with (
        patch(
            "security_scanner.tokens.okta._exchange_code",
            new=AsyncMock(return_value="fake.id.token"),
        ),
        patch("security_scanner.tokens.okta._validate_id_token", return_value=claims),
    ):
        r = client.get("/portal/oauth/callback", params={"code": "auth-code", "state": state})

    assert r.status_code == 409
