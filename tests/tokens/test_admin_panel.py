"""Tests for the ``/admin/*`` admin panel routes."""

from __future__ import annotations

import base64
import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from security_scanner.tokens import registry as token_registry
from security_scanner.tokens.admin_panel import router as admin_router
from security_scanner.tokens.db import Base
from security_scanner.tokens.models import AuditEvent, AuditEventType, LocalScanToken

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


@pytest.fixture
async def session_factory(monkeypatch):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(
        "security_scanner.tokens.admin_panel.get_session_factory", lambda: factory
    )
    try:
        yield factory
    finally:
        await engine.dispose()


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(admin_router)
    return TestClient(app)


def _userinfo(email: str, *, groups: list[str] | None = None) -> str:
    payload = {"sub": email, "email": email, "name": email.split("@")[0], "groups": groups or []}
    return base64.b64encode(json.dumps(payload).encode()).decode()


def _admin_headers(email: str = "admin@phrase.com") -> dict[str, str]:
    return {"X-Userinfo": _userinfo(email, groups=[_ADMIN_GROUP])}


def _user_headers(email: str = "alice@phrase.com") -> dict[str, str]:
    return {"X-Userinfo": _userinfo(email)}


# --- Auth -------------------------------------------------------------------


def test_admin_tokens_401_without_userinfo(client):
    r = client.get("/admin/tokens")
    assert r.status_code == 401


def test_admin_tokens_403_without_group(client, session_factory):
    r = client.get("/admin/tokens", headers=_user_headers())
    assert r.status_code == 403


def test_admin_tokens_200_for_admin(client, session_factory):
    r = client.get("/admin/tokens", headers=_admin_headers())
    assert r.status_code == 200
    assert "Token registry" in r.text


# --- List / filter ----------------------------------------------------------


async def test_admin_tokens_lists_issued_tokens(client, session_factory):
    async with session_factory() as session:
        await token_registry.issue_or_rotate_for_user(
            session, user_email="alice@phrase.com"
        )
        await token_registry.issue_or_rotate_for_user(
            session, user_email="bob@phrase.com"
        )
        await session.commit()

    r = client.get("/admin/tokens", headers=_admin_headers())
    assert r.status_code == 200
    assert "alice@phrase.com" in r.text
    assert "bob@phrase.com" in r.text


async def test_admin_tokens_filter_by_user(client, session_factory):
    async with session_factory() as session:
        await token_registry.issue_or_rotate_for_user(session, user_email="alice@phrase.com")
        await token_registry.issue_or_rotate_for_user(session, user_email="bob@phrase.com")
        await session.commit()

    r = client.get("/admin/tokens?user=alice", headers=_admin_headers())
    assert r.status_code == 200
    assert "alice@phrase.com" in r.text
    assert "bob@phrase.com" not in r.text


# --- Revoke -----------------------------------------------------------------


async def test_admin_revoke_marks_token_revoked(client, session_factory):
    async with session_factory() as session:
        issued = await token_registry.issue_or_rotate_for_user(
            session, user_email="alice@phrase.com"
        )
        await session.commit()

    r = client.post(
        f"/admin/tokens/{issued.token_id}/revoke", headers=_admin_headers()
    )
    assert r.status_code == 200
    assert "revoked" in r.text.lower()

    async with session_factory() as session:
        row = (await session.execute(select(LocalScanToken))).scalar_one()
    assert row.revoked_at is not None
    assert row.revoked_by == "admin@phrase.com"


async def test_admin_revoke_unknown_token_is_friendly(client, session_factory):
    r = client.post("/admin/tokens/tok-deadbeef0000/revoke", headers=_admin_headers())
    assert r.status_code == 200
    assert "No active token" in r.text


def test_admin_revoke_rejects_malformed_token_id(client, session_factory):
    r = client.post("/admin/tokens/not-a-token-id/revoke", headers=_admin_headers())
    assert r.status_code == 200
    assert "No active token" in r.text


# --- Force-rotate -----------------------------------------------------------


async def test_admin_force_rotate_shows_plaintext_once(client, session_factory):
    async with session_factory() as session:
        issued = await token_registry.issue_or_rotate_for_user(
            session, user_email="alice@phrase.com"
        )
        await session.commit()
    original_token_id = issued.token_id

    r = client.post(
        f"/admin/tokens/{original_token_id}/force-rotate", headers=_admin_headers()
    )
    assert r.status_code == 200
    assert "phs_local_tok-" in r.text
    # token_id prefix preserved across rotation
    assert original_token_id in r.text

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
        events = (await session.execute(select(AuditEvent))).scalars().all()
    assert len(rows) == 2
    assert rows[0].revoked_at is not None
    assert rows[1].revoked_at is None
    types = {e.event_type for e in events}
    assert AuditEventType.admin_force_rotate in types


async def test_admin_force_rotate_404_for_unknown(client, session_factory):
    r = client.post(
        "/admin/tokens/tok-deadbeef0000/force-rotate", headers=_admin_headers()
    )
    assert r.status_code == 404


# --- Audit log viewer -------------------------------------------------------


async def test_admin_audit_lists_events(client, session_factory):
    async with session_factory() as session:
        await token_registry.issue_or_rotate_for_user(session, user_email="alice@phrase.com")
        await session.commit()

    r = client.get("/admin/audit", headers=_admin_headers())
    assert r.status_code == 200
    assert "alice@phrase.com" in r.text
    assert "token_issued" in r.text


async def test_admin_audit_filter_by_event_type(client, session_factory):
    async with session_factory() as session:
        await token_registry.issue_or_rotate_for_user(session, user_email="alice@phrase.com")
        await token_registry.issue_or_rotate_for_user(session, user_email="alice@phrase.com")
        await session.commit()

    r = client.get(
        "/admin/audit?event_type=token_rotated", headers=_admin_headers()
    )
    assert r.status_code == 200
    assert "token_rotated" in r.text


def test_admin_audit_400_on_unknown_event_type(client, session_factory):
    r = client.get("/admin/audit?event_type=not_a_real_event", headers=_admin_headers())
    assert r.status_code == 400


def test_admin_audit_403_for_non_admin(client, session_factory):
    r = client.get("/admin/audit", headers=_user_headers())
    assert r.status_code == 403


# --- Org settings: Slack webhook + data governance --------------------------


def _fake_encrypt(plaintext: str, *, settings=None) -> bytes:
    """Deterministic fake: just encodes as UTF-8 with a recognisable prefix."""
    return b"ENC:" + plaintext.encode("utf-8")


def _fake_decrypt(ciphertext: bytes, *, settings=None) -> str:
    prefix = b"ENC:"
    if ciphertext.startswith(prefix):
        return ciphertext[len(prefix):].decode("utf-8")
    return ciphertext.decode("utf-8", errors="replace")


def _fake_mask(plaintext: str, *, keep: int = 4) -> str:
    return f"…{plaintext[-keep:]}"  # e.g. "…/xyz"


@pytest.fixture
def _crypto(monkeypatch):
    """Patch crypto helpers so tests don't need a real Fernet key in env."""
    monkeypatch.setattr("security_scanner.tokens.crypto.encrypt", _fake_encrypt)
    monkeypatch.setattr("security_scanner.tokens.crypto.decrypt", _fake_decrypt)
    monkeypatch.setattr("security_scanner.tokens.crypto.mask_for_display", _fake_mask)


def test_org_settings_get_no_row_shows_no_slack_test_button(client, session_factory, _crypto):
    """With no saved org settings, the Slack test button must not appear."""
    r = client.get("/admin/org-settings", headers=_admin_headers())
    assert r.status_code == 200
    assert "Send test message" not in r.text


async def test_org_settings_post_encrypts_slack_webhook(client, session_factory, _crypto):
    """Posting a webhook URL saves it encrypted; the response shows the masked value."""
    from security_scanner.tokens.models import OrgSettings as _OrgSettings

    r = client.post(
        "/admin/org-settings",
        headers=_admin_headers(),
        data={
            "default_provider": "anthropic",
            "slack_webhook": "https://hooks.slack.com/services/T123/B456/xyz123",
        },
    )
    assert r.status_code == 200
    assert "Org settings saved" in r.text

    # DB row has encrypted bytes
    async with session_factory() as session:
        row = (
            await session.execute(
                select(_OrgSettings).order_by(_OrgSettings.id.desc()).limit(1)
            )
        ).scalar_one()
    assert row.encrypted_slack_webhook is not None
    # Fake encrypt stores plaintext with prefix — round-trip recovers original
    assert _fake_decrypt(row.encrypted_slack_webhook) == (
        "https://hooks.slack.com/services/T123/B456/xyz123"
    )

    # Page shows masked tail (keep=8 → last 8 chars of URL = "xyz123" + maybe more)
    tail = "xyz123"[-8:]  # "xyz123" is 6 chars; whole suffix fits
    assert tail in r.text


async def test_org_settings_post_preserves_webhook_when_blank(client, session_factory, _crypto):
    """Re-saving with a blank webhook field must keep the previously stored value."""
    from security_scanner.tokens.models import OrgSettings as _OrgSettings

    # First save: set a webhook
    client.post(
        "/admin/org-settings",
        headers=_admin_headers(),
        data={
            "default_provider": "anthropic",
            "slack_webhook": "https://hooks.slack.com/services/T111/B222/original",
        },
    )

    # Second save: blank webhook field
    r2 = client.post(
        "/admin/org-settings",
        headers=_admin_headers(),
        data={
            "default_provider": "google",
            "slack_webhook": "",
        },
    )
    assert r2.status_code == 200

    # Latest DB row should still have the original webhook
    async with session_factory() as session:
        row = (
            await session.execute(
                select(_OrgSettings).order_by(_OrgSettings.id.desc()).limit(1)
            )
        ).scalar_one()
    assert row.encrypted_slack_webhook is not None
    assert _fake_decrypt(row.encrypted_slack_webhook) == (
        "https://hooks.slack.com/services/T111/B222/original"
    )


async def test_org_settings_post_shows_slack_test_button_after_save(client, session_factory, _crypto):
    """Once a webhook is saved the test-slack button appears in the response."""
    r = client.post(
        "/admin/org-settings",
        headers=_admin_headers(),
        data={
            "default_provider": "anthropic",
            "slack_webhook": "https://hooks.slack.com/services/T999/B999/token",
        },
    )
    assert r.status_code == 200
    assert "Send test message" in r.text


async def test_org_settings_test_slack_no_webhook_returns_error(client, session_factory, _crypto, monkeypatch):
    """Test-slack with no webhook in DB and no env var renders an error flash."""
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)

    # Patch _post_to_slack to ensure it's never called
    called: list[str] = []

    async def _fake_post(text, *, kind, http_client, webhook_url=None, **kw):
        called.append(webhook_url or "")

    monkeypatch.setattr("security_scanner.agent.slack_alert._post_to_slack", _fake_post)

    r = client.post("/admin/org-settings/test-slack", headers=_admin_headers())
    assert r.status_code == 200
    assert "error:" in r.text or "No Slack webhook" in r.text
    assert called == []  # _post_to_slack was never invoked


async def test_org_settings_test_slack_success_with_db_webhook(client, session_factory, _crypto, monkeypatch):
    """Test-slack uses the DB-stored webhook and renders a success flash."""
    # Save a webhook first
    client.post(
        "/admin/org-settings",
        headers=_admin_headers(),
        data={
            "default_provider": "anthropic",
            "slack_webhook": "https://hooks.slack.com/services/T000/B000/webhookabc",
        },
    )

    posted_to: list[str] = []

    async def _fake_post(text, *, kind, http_client, webhook_url=None, **kw):
        posted_to.append(webhook_url or "")

    monkeypatch.setattr("security_scanner.agent.slack_alert._post_to_slack", _fake_post)

    r = client.post("/admin/org-settings/test-slack", headers=_admin_headers())
    assert r.status_code == 200
    assert "ok:" in r.text or "Test message sent" in r.text
    # Webhook must have been resolved from DB and passed through
    assert posted_to == ["https://hooks.slack.com/services/T000/B000/webhookabc"]


def test_org_settings_template_contains_dg_warning(client, session_factory, _crypto):
    """The data-governance warning <div> must be present in the org-settings page."""
    r = client.get("/admin/org-settings", headers=_admin_headers())
    assert r.status_code == 200
    assert "dg-warning" in r.text
    assert "Data governance" in r.text or "data governance" in r.text.lower()


# --- Usage analytics (/admin/usage) -----------------------------------------


def test_admin_usage_200_empty_tables(client, session_factory):
    """Usage page renders without error when both tables are empty."""
    r = client.get("/admin/usage", headers=_admin_headers())
    assert r.status_code == 200
    assert "Usage Analytics" in r.text
    # Empty tables → descriptive "no data" text present
    assert "No scans" in r.text or "No LLM usage" in r.text


def test_admin_usage_403_for_non_admin(client, session_factory):
    r = client.get("/admin/usage", headers=_user_headers())
    assert r.status_code == 403


def test_admin_usage_shows_all_nav_links(client, session_factory):
    """Usage page must include nav links to the other admin sections."""
    r = client.get("/admin/usage", headers=_admin_headers())
    assert r.status_code == 200
    assert "/admin/tokens" in r.text
    assert "/admin/users" in r.text
    assert "/admin/ci-token" in r.text
    assert "/admin/audit" in r.text
