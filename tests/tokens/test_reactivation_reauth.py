"""Tests for reactivation-forced reauthentication.

When an admin reactivates a previously deactivated user, any existing portal
session cookies issued before the reactivation must be rejected — the user
must re-authenticate to get a new session.
"""
from __future__ import annotations

import base64
import json
import time
from datetime import UTC, datetime

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from security_scanner.tokens.admin_panel import router as admin_router
from security_scanner.tokens.auth import _SESSION_COOKIE, sign_portal_session
from security_scanner.tokens.db import Base
from security_scanner.tokens.models import User, UserRole
from security_scanner.tokens.portal import router as portal_router


@pytest.fixture(autouse=True)
def _env(monkeypatch):
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
    monkeypatch.setenv("SCANNER_ENCRYPTION_KEY", "xHNLN3iy0J83h8gAWBzBvjMdLmevdkyKNzXX5O_YdJI=")
    monkeypatch.setenv("OKTA_EMAIL_DOMAIN", "")
    monkeypatch.setenv("PROTECTED_ADMIN_EMAILS", "admin@example.com")
    monkeypatch.setenv("LOCAL_PORTAL_PASSWORD", "test-password")


@pytest.fixture
async def session_factory(monkeypatch):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False)
    for mod in (
        "security_scanner.tokens.portal",
        "security_scanner.tokens.admin_panel",
        "security_scanner.tokens.auth",
    ):
        monkeypatch.setattr(f"{mod}.get_session_factory", lambda: factory)
    # Seed the admin user so require_admin finds role=admin in the DB.
    async with factory() as session:
        session.add(User(
            email="admin@example.com",
            role=UserRole.admin,
            is_active=True,
            created_at=datetime.now(UTC),
        ))
        await session.commit()
    try:
        yield factory
    finally:
        await engine.dispose()


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(portal_router)
    app.include_router(admin_router)
    return TestClient(app, follow_redirects=False)


def _admin_headers() -> dict:
    payload = base64.b64encode(
        json.dumps({
            "sub": "admin@example.com",
            "email": "admin@example.com",
            "name": "Admin",
            "groups": ["security-scanner-admins"],
        }).encode()
    ).decode()
    return {"X-Userinfo": payload}


async def test_reactivate_sets_last_reactivation_at(client, session_factory):
    """Reactivating a user must stamp last_reactivation_at."""
    async with session_factory() as sess:
        sess.add(User(
            email="alice@example.com",
            auth_provider="local",
            role=UserRole.user,
            is_active=False,
            created_at=datetime.now(UTC),
        ))
        await sess.commit()

    r = client.post("/admin/users/alice%40example.com/reactivate",
                    headers=_admin_headers())
    assert r.status_code == 200

    async with session_factory() as sess:
        u = await sess.get(User, "alice@example.com")
    assert u.last_reactivation_at is not None
    assert u.is_active is True


async def test_old_session_rejected_after_reactivation(client, session_factory):
    """A session cookie issued before reactivation must be rejected."""
    now = datetime.now(UTC)
    before_reactivation = time.time() - 10  # 10 seconds ago

    async with session_factory() as sess:
        u = User(
            email="bob@example.com",
            auth_provider="local",
            role=UserRole.user,
            is_active=True,
            created_at=now,
            # last_reactivation_at = 5 seconds ago (AFTER the old session)
            last_reactivation_at=datetime.fromtimestamp(before_reactivation + 5, tz=UTC),
        )
        sess.add(u)
        await sess.commit()

    # Create a session cookie that was issued 10 seconds ago (before reactivation)
    # We need to manually craft the payload with the old timestamp
    from security_scanner.tokens.auth import _SESSION_TTL, _get_fernet
    old_payload = json.dumps({
        "e": "bob@example.com",
        "n": "Bob",
        "x": int(before_reactivation) + _SESSION_TTL,
        "t": int(before_reactivation),  # issued BEFORE last_reactivation_at
        "a": "local",
    }).encode()
    old_cookie = _get_fernet().encrypt(old_payload).decode()

    # Set cookie on the client instance to avoid deprecation / routing issues
    client.cookies.set(_SESSION_COOKIE, old_cookie)
    r = client.get("/portal/", headers={"Accept": "text/html"})
    client.cookies.clear()
    # Should redirect to login (session invalidated)
    assert r.status_code in (302, 401)


async def test_new_session_allowed_after_reactivation(client, session_factory):
    """A session issued AFTER reactivation must be allowed."""
    reactivation_time = time.time() - 10  # reactivated 10 seconds ago

    async with session_factory() as sess:
        u = User(
            email="carol@example.com",
            auth_provider="local",
            role=UserRole.user,
            is_active=True,
            created_at=datetime.now(UTC),
            last_reactivation_at=datetime.fromtimestamp(reactivation_time, tz=UTC),
        )
        sess.add(u)
        await sess.commit()

    # Cookie issued AFTER reactivation (now = reactivation + 10s, so session_issued_at > last_reactivation_at)
    new_cookie = sign_portal_session("carol@example.com", "Carol", auth_provider="local")
    client.cookies.set(_SESSION_COOKIE, new_cookie)
    r = client.get("/portal/", headers={"Accept": "text/html"})
    client.cookies.clear()
    assert r.status_code == 200


def test_reauth_check_skipped_for_x_userinfo(client, session_factory):
    """X-Userinfo path has no session_issued_at → reauth check is skipped."""
    payload = base64.b64encode(
        json.dumps({
            "sub": "dave@example.com",
            "email": "dave@example.com",
            "name": "Dave",
            "groups": [],
        }).encode()
    ).decode()
    # Even without a DB user or any reactivation_at, X-Userinfo always resolves
    r = client.get("/portal/", headers={"X-Userinfo": payload, "Accept": "text/html"})
    # Should be 200 (user will be provisioned lazily or returns portal content)
    assert r.status_code in (200, 302)  # 302 if redirect to token page, 200 if portal
