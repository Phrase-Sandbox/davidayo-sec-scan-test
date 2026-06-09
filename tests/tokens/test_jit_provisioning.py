"""Tests for JIT (just-in-time) user provisioning on first gateway login.

When a user authenticates via the X-Userinfo header (Launchpad APISIX gateway)
and has no existing DB row, _jit_provision_user is called to create one so
admins can reach /admin/ immediately — no "issue a token first" workaround needed.

Role assignment logic tested:
- Regular users get role=user
- Emails in PROTECTED_ADMIN_EMAILS get role=admin
- Users in ADMIN_GROUP_NAME Okta group get role=admin
- Group admin wins even without PROTECTED_ADMIN_EMAILS

Idempotency:
- Second request for the same user does NOT create a duplicate row.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

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
    monkeypatch.setenv("OKTA_EMAIL_DOMAIN", "")  # disabled so any email works
    monkeypatch.setenv("PROTECTED_ADMIN_EMAILS", "superadmin@example.com")
    monkeypatch.setenv("LOCAL_PORTAL_PASSWORD", "")


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
    try:
        yield factory
    finally:
        await engine.dispose()


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(portal_router)
    return TestClient(app, follow_redirects=False)


def _userinfo_header(email: str, name: str = "Test User", groups: list[str] | None = None) -> dict:
    """Build an X-Userinfo header with the given claims."""
    claims = {
        "sub": f"okta-{email}",
        "email": email,
        "name": name,
        "groups": groups or [],
        "email_verified": True,
    }
    encoded = base64.b64encode(json.dumps(claims).encode()).decode()
    return {"X-Userinfo": encoded, "Accept": "text/html"}


# ---------------------------------------------------------------------------
# Role assignment on first login
# ---------------------------------------------------------------------------


async def test_jit_provisions_new_user_as_user_role(client, session_factory):
    """Unknown email via X-Userinfo → created in DB with role=user."""
    r = client.get("/portal/", headers=_userinfo_header("newuser@example.com"))
    assert r.status_code in (200, 302)  # 302 if redirected to token issue page

    async with session_factory() as sess:
        u = await sess.get(User, "newuser@example.com")

    assert u is not None, "JIT provisioning should have created a DB row"
    assert u.role == UserRole.user
    assert u.is_active is True
    assert u.auth_provider == "okta"
    assert u.display_name == "Test User"


async def test_jit_provisions_protected_admin_as_admin(client, session_factory):
    """Email in PROTECTED_ADMIN_EMAILS → created in DB with role=admin."""
    r = client.get("/portal/", headers=_userinfo_header("superadmin@example.com", "Super Admin"))
    assert r.status_code in (200, 302)

    async with session_factory() as sess:
        u = await sess.get(User, "superadmin@example.com")

    assert u is not None
    assert u.role == UserRole.admin, "Protected admin should be provisioned as admin"
    assert u.auth_provider == "okta"


async def test_jit_provisions_group_admin_as_admin(client, session_factory):
    """Member of ADMIN_GROUP_NAME → created in DB with role=admin."""
    r = client.get(
        "/portal/",
        headers=_userinfo_header(
            "groupadmin@example.com",
            "Group Admin",
            groups=["security-scanner-admins", "Engineering"],
        ),
    )
    assert r.status_code in (200, 302)

    async with session_factory() as sess:
        u = await sess.get(User, "groupadmin@example.com")

    assert u is not None
    assert u.role == UserRole.admin, "ADMIN_GROUP_NAME member should be provisioned as admin"


async def test_jit_regular_user_with_unrelated_group(client, session_factory):
    """User with groups not matching ADMIN_GROUP_NAME → role=user."""
    r = client.get(
        "/portal/",
        headers=_userinfo_header(
            "regulardev@example.com",
            "Regular Dev",
            groups=["Engineering", "DevTeam"],
        ),
    )
    assert r.status_code in (200, 302)

    async with session_factory() as sess:
        u = await sess.get(User, "regulardev@example.com")

    assert u is not None
    assert u.role == UserRole.user


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


async def test_jit_provision_is_idempotent(client, session_factory):
    """Second request for the same email does NOT create a duplicate row."""
    headers = _userinfo_header("idempotent@example.com")

    # First visit
    r1 = client.get("/portal/", headers=headers)
    assert r1.status_code in (200, 302)

    # Second visit
    r2 = client.get("/portal/", headers=headers)
    assert r2.status_code in (200, 302)

    # Exactly one DB row
    from sqlalchemy import func, select

    async with session_factory() as sess:
        count = (
            await sess.execute(select(func.count()).where(User.email == "idempotent@example.com"))
        ).scalar_one()

    assert count == 1, "Idempotent: second visit must NOT create a duplicate row"


# ---------------------------------------------------------------------------
# Pre-existing user is not overwritten
# ---------------------------------------------------------------------------


async def test_existing_user_not_reprovisioned(client, session_factory):
    """If user already has a DB row, JIT provisioning is skipped entirely."""
    # Pre-seed user as admin (already in DB)
    async with session_factory() as sess:
        sess.add(
            User(
                email="existing@example.com",
                auth_provider="local",
                role=UserRole.admin,
                is_active=True,
                created_at=datetime.now(UTC),
            )
        )
        await sess.commit()

    # Login via X-Userinfo (which would provision as role=user, no groups)
    r = client.get("/portal/", headers=_userinfo_header("existing@example.com"))
    assert r.status_code in (200, 302)

    # Role must not have been changed by JIT provisioning
    async with session_factory() as sess:
        u = await sess.get(User, "existing@example.com")

    assert u.role == UserRole.admin, (
        "Existing admin role must not be overwritten by JIT provisioning"
    )
    assert u.auth_provider == "local", "Existing auth_provider must not be overwritten"
