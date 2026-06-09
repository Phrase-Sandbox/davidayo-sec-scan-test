"""Tests for the ``/admin/*`` admin panel routes."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from security_scanner.tokens import registry as token_registry
from security_scanner.tokens.admin_panel import router as admin_router
from security_scanner.tokens.db import Base
from security_scanner.tokens.models import (
    LocalScanToken,
    User,
    UserRole,
)

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
    monkeypatch.setattr("security_scanner.tokens.admin_panel.get_session_factory", lambda: factory)
    # require_admin (in auth.py) now checks DB role — patch its factory too so
    # tests don't try to connect to the fake DATABASE_URL.
    monkeypatch.setattr("security_scanner.tokens.auth.get_session_factory", lambda: factory)
    # Seed the default admin user used by _admin_headers() so require_admin
    # finds role=admin in the DB (Okta groups are no longer used for auth).
    async with factory() as session:
        session.add(
            User(
                email="admin@phrase.com",
                role=UserRole.admin,
                is_active=True,
                created_at=datetime.now(UTC),
            )
        )
        await session.commit()
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
    assert "Token Registry" in r.text


# --- List / filter ----------------------------------------------------------


async def test_admin_tokens_lists_issued_tokens(client, session_factory):
    async with session_factory() as session:
        await token_registry.issue_or_rotate_for_user(session, user_email="alice@phrase.com")
        await token_registry.issue_or_rotate_for_user(session, user_email="bob@phrase.com")
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

    r = client.post(f"/admin/tokens/{issued.token_id}/revoke", headers=_admin_headers())
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


# --- Force-rotate removed ---------------------------------------------------
# The admin force-rotate endpoint was removed.  Admins may only revoke tokens;
# users must self-issue replacement tokens via the portal (/portal/).
# No plaintext token is ever shown to an admin.


def test_admin_force_rotate_route_does_not_exist(client, session_factory):
    """The /admin/tokens/{id}/force-rotate endpoint must be gone (405/404)."""
    r = client.post("/admin/tokens/tok-deadbeef0000/force-rotate", headers=_admin_headers())
    # FastAPI returns 405 for unknown methods on known paths, 404 for fully unknown paths.
    assert r.status_code in (404, 405)


# --- Protected super-admin guards -------------------------------------------


async def test_demote_protected_admin_returns_400(client, session_factory):
    """Demoting a protected super-admin must return 400."""
    # Ensure the protected user exists in the DB.
    async with session_factory() as session:
        from datetime import UTC, datetime

        from security_scanner.tokens.models import User, UserRole

        session.add(
            User(
                email="david.shoyemi@phrase.com",
                role=UserRole.admin,
                is_active=True,
                created_at=datetime.now(UTC),
            )
        )
        await session.commit()

    r = client.post(
        "/admin/users/david.shoyemi%40phrase.com/demote",
        headers=_admin_headers(),
    )
    assert r.status_code == 400
    assert "protected" in r.text.lower() or "protected" in r.json().get("detail", "").lower()


async def test_deactivate_protected_admin_returns_400(client, session_factory):
    """Deactivating a protected super-admin must return 400."""
    async with session_factory() as session:
        from datetime import UTC, datetime

        from security_scanner.tokens.models import User, UserRole

        session.add(
            User(
                email="david.shoyemi@phrase.com",
                role=UserRole.admin,
                is_active=True,
                created_at=datetime.now(UTC),
            )
        )
        await session.commit()

    r = client.post(
        "/admin/users/david.shoyemi%40phrase.com/deactivate",
        headers=_admin_headers(),
    )
    assert r.status_code == 400
    assert "protected" in r.text.lower() or "protected" in r.json().get("detail", "").lower()


async def test_revoke_tokens_for_protected_admin_returns_400(client, session_factory):
    """Bulk token revocation for a protected super-admin must return 400."""
    async with session_factory() as session:
        from datetime import UTC, datetime

        from security_scanner.tokens.models import User, UserRole

        session.add(
            User(
                email="david.shoyemi@phrase.com",
                role=UserRole.admin,
                is_active=True,
                created_at=datetime.now(UTC),
            )
        )
        await session.commit()

    r = client.post(
        "/admin/users/david.shoyemi%40phrase.com/revoke-tokens",
        headers=_admin_headers(),
    )
    assert r.status_code == 400
    assert "protected" in r.text.lower() or "protected" in r.json().get("detail", "").lower()


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

    r = client.get("/admin/audit?event_type=token_rotated", headers=_admin_headers())
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
        return ciphertext[len(prefix) :].decode("utf-8")
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
            await session.execute(select(_OrgSettings).order_by(_OrgSettings.id.desc()).limit(1))
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
            await session.execute(select(_OrgSettings).order_by(_OrgSettings.id.desc()).limit(1))
        ).scalar_one()
    assert row.encrypted_slack_webhook is not None
    assert _fake_decrypt(row.encrypted_slack_webhook) == (
        "https://hooks.slack.com/services/T111/B222/original"
    )


async def test_org_settings_post_shows_slack_test_button_after_save(
    client, session_factory, _crypto
):  # noqa: E501
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


async def test_org_settings_test_slack_no_webhook_returns_error(
    client, session_factory, _crypto, monkeypatch
):  # noqa: E501
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


async def test_org_settings_test_slack_success_with_db_webhook(
    client, session_factory, _crypto, monkeypatch
):  # noqa: E501
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


# ---------------------------------------------------------------------------
# Advanced settings (/admin/advanced-settings)
# ---------------------------------------------------------------------------


def test_admin_advanced_settings_401_without_auth(client):
    r = client.get("/admin/advanced-settings")
    assert r.status_code == 401


def test_admin_advanced_settings_403_for_non_admin(client, session_factory):
    r = client.get("/admin/advanced-settings", headers=_user_headers())
    assert r.status_code == 403


def test_admin_advanced_settings_200_for_admin(client, session_factory):
    r = client.get("/admin/advanced-settings", headers=_admin_headers())
    assert r.status_code == 200
    assert "Advanced Settings" in r.text
    assert "blocking" in r.text.lower() or "confidence" in r.text.lower()


def test_admin_advanced_settings_shows_nav_link(client, session_factory):
    """Advanced settings page must link back to itself and to other sections."""
    r = client.get("/admin/advanced-settings", headers=_admin_headers())
    assert r.status_code == 200
    assert "/admin/advanced-settings" in r.text
    assert "/admin/org-settings" in r.text
    assert "/admin/audit" in r.text


async def test_admin_advanced_settings_post_inserts_row(client, session_factory):
    """POST with valid form inserts a ScannerSettings row."""
    from sqlalchemy import select

    from security_scanner.tokens.models import ScannerSettings

    form_data = {
        "keep_confidences": "high,medium",
        "advisory_confidences": "low",
        "vuln_verifier_parallelism": "2",
        "high_risk_paths": "auth/\npayments/",
        "enable_semgrep": "on",
        "enable_bandit": "on",
        "semgrep_owasp": "on",
        "semgrep_audit": "on",
    }
    r = client.post(
        "/admin/advanced-settings",
        headers=_admin_headers(),
        data=form_data,
    )
    assert r.status_code == 200
    assert "saved" in r.text.lower()

    async with session_factory() as session:
        row = (
            await session.execute(
                select(ScannerSettings).order_by(ScannerSettings.id.desc()).limit(1)
            )
        ).scalar_one_or_none()

    assert row is not None
    assert row.keep_confidences == "high,medium"
    assert row.enable_semgrep is True
    assert row.enable_bandit is True
    assert row.enable_gosec is False  # not submitted → unchecked → False
    assert row.vuln_verifier_parallelism == 2
    assert "auth/" in row.high_risk_paths
    assert row.updated_by_email == "admin@phrase.com"


async def test_admin_advanced_settings_post_invalid_confidence_422(client, session_factory):
    """POST with an unknown keep_confidences value returns 422."""
    form_data = {
        "keep_confidences": "invalid_value",
        "advisory_confidences": "low",
        "vuln_verifier_parallelism": "2",
    }
    r = client.post(
        "/admin/advanced-settings",
        headers=_admin_headers(),
        data=form_data,
    )
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# Report HTML endpoint (/admin/reports/{scan_id}/html)
# ---------------------------------------------------------------------------


async def test_admin_report_html_serves_ci_scan_report(client, session_factory):
    """GET /admin/reports/{id}/html returns HTML content for a CI scan."""
    import uuid

    from security_scanner.tokens.models import CiScanRecord, ScanStatus

    scan_id = uuid.uuid4()
    async with session_factory() as session:
        session.add(CiScanRecord(
            scan_id=scan_id,
            triggered_by="actor@phrase.com",
            repo_url="https://github.com/Phrase-Launchpad/test-repo",
            started_at=datetime.now(UTC),
            status=ScanStatus.ok,
            findings_count=1,
            critical=0,
            high=1,
            medium=0,
            low=0,
            html_report="<html><body>CI Report</body></html>",
        ))
        await session.commit()

    r = client.get(f"/admin/reports/{scan_id}/html", headers=_admin_headers())
    assert r.status_code == 200
    assert "CI Report" in r.text
    assert r.headers["content-type"].startswith("text/html")


async def test_admin_report_html_serves_portal_scan_report(client, session_factory):
    """GET /admin/reports/{id}/html returns HTML for a portal ScanRecord."""
    import uuid

    from security_scanner.tokens.models import ScanRecord, ScanStatus

    scan_id = uuid.uuid4()
    async with session_factory() as session:
        session.add(ScanRecord(
            scan_id=scan_id,
            user_email="alice@phrase.com",
            repo_url="https://github.com/Phrase-Launchpad/test-repo",
            started_at=datetime.now(UTC),
            status=ScanStatus.ok,
            findings_count=0,
            html_report="<html><body>Portal Report</body></html>",
        ))
        await session.commit()

    r = client.get(f"/admin/reports/{scan_id}/html", headers=_admin_headers())
    assert r.status_code == 200
    assert "Portal Report" in r.text


def test_admin_report_html_404_for_missing_scan(client, session_factory):
    """GET /admin/reports/{id}/html returns 404 when no record exists."""
    import uuid

    r = client.get(f"/admin/reports/{uuid.uuid4()}/html", headers=_admin_headers())
    assert r.status_code == 404


def test_admin_report_html_401_without_auth(client):
    """Unauthenticated request is rejected."""
    import uuid

    r = client.get(f"/admin/reports/{uuid.uuid4()}/html")
    assert r.status_code == 401


def test_admin_report_html_403_for_non_admin(client, session_factory):
    """Non-admin user cannot view reports via admin endpoint."""
    import uuid

    r = client.get(f"/admin/reports/{uuid.uuid4()}/html", headers=_user_headers())
    assert r.status_code == 403
