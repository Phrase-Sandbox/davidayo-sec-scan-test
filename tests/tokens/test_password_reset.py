"""Tests for the super-admin force-password-reset flow and per-user bcrypt passwords."""
from __future__ import annotations

import base64
import json
from datetime import UTC, datetime

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from security_scanner.tokens.admin_panel import router as admin_router
from security_scanner.tokens.auth import _SESSION_COOKIE, sign_portal_session
from security_scanner.tokens.db import Base
from security_scanner.tokens.models import User, UserRole
from security_scanner.tokens.portal import _hash_password
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
    monkeypatch.setenv("OKTA_EMAIL_DOMAIN", "")  # no domain restriction for these tests
    monkeypatch.setenv("PROTECTED_ADMIN_EMAILS", "superadmin@example.com")
    monkeypatch.setenv("LOCAL_PORTAL_PASSWORD", "shared-test-password")


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
            email="superadmin@example.com",
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
            "sub": "superadmin@example.com",
            "email": "superadmin@example.com",
            "name": "Super Admin",
            "groups": ["security-scanner-admins"],
        }).encode()
    ).decode()
    return {"X-Userinfo": payload}


async def _make_local_user(session_factory, email: str = "alice@example.com",
                           must_change: bool = False, pw_hash: bytes | None = None) -> None:
    async with session_factory() as sess:
        sess.add(User(
            email=email,
            auth_provider="local",
            role=UserRole.user,
            is_active=True,
            created_at=datetime.now(UTC),
            must_change_password=must_change,
            password_hash=pw_hash,
        ))
        await sess.commit()


# ---------------------------------------------------------------------------
# Admin force-password-reset
# ---------------------------------------------------------------------------

async def test_force_reset_sets_flag_and_clears_hash(client, session_factory):
    """POST /admin/users/{email}/force-password-reset → must_change_password=True, password_hash=None."""
    pw_hash = _hash_password("old-secure-password")
    await _make_local_user(session_factory, pw_hash=pw_hash)

    r = client.post("/admin/users/alice%40example.com/force-password-reset",
                    headers=_admin_headers())
    assert r.status_code == 200

    async with session_factory() as sess:
        u = await sess.get(User, "alice@example.com")
    assert u.must_change_password is True
    assert u.password_hash is None


async def test_force_reset_rejected_for_okta_users(client, session_factory):
    """Force-reset must reject Okta-auth users (they reset via Okta)."""
    async with session_factory() as sess:
        sess.add(User(
            email="okta-user@example.com",
            auth_provider="okta",
            okta_user_id="sub-xyz",
            role=UserRole.user,
            is_active=True,
            created_at=datetime.now(UTC),
        ))
        await sess.commit()

    r = client.post("/admin/users/okta-user%40example.com/force-password-reset",
                    headers=_admin_headers())
    assert r.status_code == 400
    assert "Okta" in r.json()["detail"]


# ---------------------------------------------------------------------------
# must_change_password redirect on login
# ---------------------------------------------------------------------------

async def test_login_with_must_change_redirects(client, session_factory):
    """Logging in when must_change_password=True must redirect to /portal/change-password."""
    await _make_local_user(session_factory, must_change=True)
    r = client.post("/portal/login",
                    data={"email": "alice@example.com",
                          "password": "shared-test-password",
                          "next": "/portal/"})
    assert r.status_code == 302
    assert r.headers["location"] == "/portal/change-password"


# ---------------------------------------------------------------------------
# /portal/change-password
# ---------------------------------------------------------------------------

async def test_change_password_stores_bcrypt_hash(client, session_factory):
    """POST /portal/change-password → bcrypt hash stored, flag cleared."""
    await _make_local_user(session_factory, must_change=True)
    session_cookie = sign_portal_session("alice@example.com", "Alice", auth_provider="local")

    r = client.post(
        "/portal/change-password",
        data={"new_password": "supersecure-new-pw", "confirm_password": "supersecure-new-pw"},
        cookies={_SESSION_COOKIE: session_cookie},
    )
    assert r.status_code == 302
    assert r.headers["location"] == "/portal/"

    async with session_factory() as sess:
        u = await sess.get(User, "alice@example.com")
    assert u.password_hash is not None
    assert u.must_change_password is False


async def test_change_password_rejects_short(client, session_factory):
    await _make_local_user(session_factory)
    session_cookie = sign_portal_session("alice@example.com", "Alice", auth_provider="local")

    r = client.post(
        "/portal/change-password",
        data={"new_password": "short", "confirm_password": "short"},
        cookies={_SESSION_COOKIE: session_cookie},
    )
    assert r.status_code == 422
    assert "12 characters" in r.text


async def test_change_password_rejects_mismatch(client, session_factory):
    await _make_local_user(session_factory)
    session_cookie = sign_portal_session("alice@example.com", "Alice", auth_provider="local")

    r = client.post(
        "/portal/change-password",
        data={"new_password": "supersecure-pw-1", "confirm_password": "supersecure-pw-2"},
        cookies={_SESSION_COOKIE: session_cookie},
    )
    assert r.status_code == 422
    assert "do not match" in r.text.lower()


# ---------------------------------------------------------------------------
# Per-user bcrypt hash priority over env var
# ---------------------------------------------------------------------------

async def test_per_user_hash_verified_not_env_var(client, session_factory):
    """When a user has a password_hash, it takes priority over LOCAL_PORTAL_PASSWORD."""
    personal_pw = "my-personal-secure-pass"
    pw_hash = _hash_password(personal_pw)
    await _make_local_user(session_factory, pw_hash=pw_hash)

    # Correct personal password → success
    r = client.post("/portal/login",
                    data={"email": "alice@example.com",
                          "password": personal_pw,
                          "next": "/portal/"})
    assert r.status_code == 302
    assert "/portal/" in r.headers["location"]

    # Shared env-var password → fail (personal hash takes priority)
    r2 = client.post("/portal/login",
                     data={"email": "alice@example.com",
                           "password": "shared-test-password",
                           "next": "/portal/"})
    assert r2.status_code == 401
