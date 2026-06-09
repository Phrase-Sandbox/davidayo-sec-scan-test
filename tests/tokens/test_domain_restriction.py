"""Tests for the @phrase.com email domain restriction (OKTA_EMAIL_DOMAIN)."""

from __future__ import annotations

import base64
import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from security_scanner.tokens.db import Base
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
    monkeypatch.setenv("PROTECTED_ADMIN_EMAILS", "admin@phrase.com")
    monkeypatch.setenv("LOCAL_PORTAL_PASSWORD", "test-password")


@pytest.fixture
async def session_factory(monkeypatch):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr("security_scanner.tokens.portal.get_session_factory", lambda: factory)
    monkeypatch.setattr("security_scanner.tokens.auth.get_session_factory", lambda: factory)
    try:
        yield factory
    finally:
        await engine.dispose()


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(portal_router)
    return TestClient(app, follow_redirects=False)


def _x_userinfo(email: str) -> dict:
    payload = base64.b64encode(
        json.dumps({"sub": email, "email": email, "name": "Test", "groups": []}).encode()
    ).decode()
    return {"X-Userinfo": payload}


# ---------------------------------------------------------------------------
# X-Userinfo gateway path
# ---------------------------------------------------------------------------


def test_x_userinfo_blocked_when_domain_set(client, session_factory, monkeypatch):
    """@other.com email via X-Userinfo must be rejected when OKTA_EMAIL_DOMAIN=phrase.com."""
    monkeypatch.setenv("OKTA_EMAIL_DOMAIN", "phrase.com")
    r = client.get("/portal/", headers=_x_userinfo("hacker@evil.com"), follow_redirects=False)
    assert r.status_code == 403
    assert "phrase.com" in r.json()["detail"]


def test_x_userinfo_allowed_when_restriction_off(client, session_factory, monkeypatch):
    """When OKTA_EMAIL_DOMAIN is empty, any domain is allowed."""
    monkeypatch.setenv("OKTA_EMAIL_DOMAIN", "")
    r = client.get("/portal/", headers=_x_userinfo("user@other.com"))
    assert r.status_code == 200


def test_x_userinfo_phrase_com_always_allowed(client, session_factory, monkeypatch):
    """@phrase.com emails must pass the domain check."""
    monkeypatch.setenv("OKTA_EMAIL_DOMAIN", "phrase.com")
    r = client.get("/portal/", headers=_x_userinfo("dev@phrase.com"))
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# Local password path
# ---------------------------------------------------------------------------


def test_local_login_blocked_when_domain_set(client, session_factory, monkeypatch):
    """Local login with @other.com must be rejected when OKTA_EMAIL_DOMAIN=phrase.com."""
    monkeypatch.setenv("OKTA_EMAIL_DOMAIN", "phrase.com")
    r = client.post(
        "/portal/login",
        data={"email": "user@other.com", "password": "test-password", "next": "/portal/"},
    )
    assert r.status_code == 403


def test_local_login_allowed_when_restriction_off(client, session_factory, monkeypatch):
    """When OKTA_EMAIL_DOMAIN='', any email domain is accepted for local login."""
    monkeypatch.setenv("OKTA_EMAIL_DOMAIN", "")
    r = client.post(
        "/portal/login",
        data={"email": "user@other.com", "password": "test-password", "next": "/portal/"},
    )
    # Should succeed (302 redirect to portal), not 403
    assert r.status_code == 302
