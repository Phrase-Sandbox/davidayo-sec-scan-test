"""``/admin/*`` — admin panel for the per-user token registry.

Capabilities:

1. ``GET /admin/tokens`` — list/filter all tokens (active + historical).
2. ``POST /admin/tokens/{token_id}/revoke`` — force-revoke any active token.
   Admins can only revoke; users must self-issue replacement tokens via the
   portal (/portal/). No plaintext token is ever shown to an admin.
3. ``GET /admin/audit`` — paginated audit log viewer over ``audit_events``.

Every route is guarded by :func:`require_admin`.  For local dev
``ADMIN_LOCAL_BYPASS=true`` injects a synthetic admin (the app refuses to
start if that flag is set against a non-local DB).

Protected super-admins (``PROTECTED_ADMIN_EMAILS``) cannot be demoted,
deactivated, or have their tokens bulk-revoked via this panel.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid as _uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import delete, desc, func, select

from security_scanner.shared.config import get_settings
from security_scanner.shared.logging_util import get_logger
from security_scanner.tokens import audit as token_audit
from security_scanner.tokens import registry as token_registry
from security_scanner.tokens.auth import PhraseUser, require_admin
from security_scanner.tokens.db import get_session_factory
from security_scanner.tokens.models import (
    AuditEvent,
    AuditEventType,
    CiScanRecord,
    CIToken,
    LLMProvider,
    LLMUsageMonthly,
    OrgSettings,
    ScannerSettings,
    ScanRecord,
    User,
    UserRole,
)

log = get_logger(__name__)

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/", include_in_schema=False)
@router.get("", include_in_schema=False)
async def admin_root() -> RedirectResponse:
    """Redirect bare /admin and /admin/ to the token registry."""
    return RedirectResponse(url="/admin/tokens", status_code=302)


# Admin-managed model options surfaced in the /admin/org-settings dropdowns.
# First entry per provider is the recommended default.
KNOWN_MODELS: dict[str, list[str]] = {
    "anthropic": [
        "claude-sonnet-4-6",
        "claude-opus-4-7",
        "claude-haiku-4-5-20251001",
    ],
    "google": [
        "gemini-2.5-flash",
        "gemini-2.5-pro",
    ],
}

_TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

# No-cache headers applied to sensitive admin responses.
_NO_STORE_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "Referrer-Policy": "no-referrer",
}

_AdminDep = Annotated[PhraseUser, Depends(require_admin)]


def _assert_not_protected(email: str) -> None:
    """Raise 400 if *email* belongs to a protected super-admin account.

    Protected accounts are configured via ``PROTECTED_ADMIN_EMAILS`` and
    cannot be demoted, deactivated, or have their tokens bulk-revoked through
    the admin UI — that requires an infrastructure-level config change.
    """
    settings = get_settings()
    protected = frozenset(
        e.strip() for e in settings.PROTECTED_ADMIN_EMAILS.split(",") if e.strip()
    )
    if email in protected:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This account is a protected super-admin and cannot be modified via the admin UI.",  # noqa: E501
        )


# --- Token management -------------------------------------------------------


@router.get("/tokens", response_class=HTMLResponse)
async def admin_tokens(
    request: Request,
    admin: _AdminDep,
    user: Annotated[str | None, Query(max_length=320)] = None,
    active_only: Annotated[bool, Query()] = False,
    status: Annotated[str | None, Query(max_length=10)] = None,
) -> HTMLResponse:
    """Token registry view.

    ``status`` query param: "active" | "revoked" | "" (all).
    Legacy ``active_only=true`` is treated as status=active for back-compat.
    """
    if status not in (None, "", "active", "revoked"):
        status = None  # reject unknown values silently

    revoked_only = status == "revoked"
    effective_active = active_only or status == "active"

    factory = get_session_factory()
    async with factory() as session:
        rows = await token_registry.list_all(
            session,
            active_only=effective_active,
            revoked_only=revoked_only,
            user_email_contains=user or None,
        )

    if revoked_only:
        filter_status = "revoked"
    elif effective_active:
        filter_status = "active"
    else:
        filter_status = ""

    return templates.TemplateResponse(
        request,
        "admin_tokens.html",
        {
            "user": admin,
            "rows": rows,
            "filter_user": user or "",
            "active_only": effective_active,
            "filter_status": filter_status,
            "issued_token": None,
        },
        headers=_NO_STORE_HEADERS,
    )


@router.post("/tokens/{token_id}/revoke", response_class=HTMLResponse)
async def admin_revoke(
    request: Request,
    admin: _AdminDep,
    token_id: str,
) -> HTMLResponse:
    factory = get_session_factory()
    async with factory() as session:
        ok = await token_registry.revoke_by_token_id(
            session, token_id=token_id, admin_email=admin.email
        )
        await session.commit()
        rows = await token_registry.list_all(session)

    log.info(
        "admin token revoke",
        actor_email=admin.email,
        token_id=token_id,
        revoked=ok,
    )
    flash = f"Token {token_id} revoked." if ok else f"No active token found for {token_id}."
    return templates.TemplateResponse(
        request,
        "admin_tokens.html",
        {
            "user": admin,
            "rows": rows,
            "filter_user": "",
            "active_only": False,
            "filter_status": "",
            "issued_token": None,
            "flash": flash,
        },
        headers=_NO_STORE_HEADERS,
    )


# --- Audit log viewer -------------------------------------------------------


_AUDIT_PAGE_SIZE = 100


@router.get("/audit", response_class=HTMLResponse)
async def admin_audit(
    request: Request,
    admin: _AdminDep,
    user: Annotated[str | None, Query(max_length=320)] = None,
    event_type: Annotated[str | None, Query(max_length=64)] = None,
    page: Annotated[int, Query(ge=1, le=10_000)] = 1,
) -> HTMLResponse:
    stmt = select(AuditEvent).order_by(AuditEvent.at.desc())
    if user:
        stmt = stmt.where(AuditEvent.user_email.ilike(f"%{user}%"))
    if event_type:
        # Reject unknown event_type strings up front so we don't 500 on the cast.
        try:
            stmt = stmt.where(AuditEvent.event_type == AuditEventType(event_type))
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unknown event_type {event_type!r}.",
            ) from exc
    stmt = stmt.offset((page - 1) * _AUDIT_PAGE_SIZE).limit(_AUDIT_PAGE_SIZE + 1)

    factory = get_session_factory()
    async with factory() as session:
        rows = list((await session.execute(stmt)).scalars().all())

    has_next = len(rows) > _AUDIT_PAGE_SIZE
    rows = rows[:_AUDIT_PAGE_SIZE]

    return templates.TemplateResponse(
        request,
        "admin_audit.html",
        {
            "user": admin,
            "rows": rows,
            "filter_user": user or "",
            "filter_event_type": event_type or "",
            "page": page,
            "has_next": has_next,
            "event_types": [e.value for e in AuditEventType],
        },
        headers=_NO_STORE_HEADERS,
    )


# ---------------------------------------------------------------------------
# Org settings (/admin/org-settings)
# ---------------------------------------------------------------------------

# CI token prefix — distinct from user tokens (phs_local_) so ops can tell
# them apart in logs without decoding.
_CI_TOKEN_PREFIX = "phs_ci_"  # noqa: S105


def _hash_ci_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@router.get("/org-settings", response_class=HTMLResponse)
async def admin_org_settings_get(request: Request, admin: _AdminDep) -> HTMLResponse:
    from security_scanner.tokens.crypto import decrypt, mask_for_display  # noqa: PLC0415

    factory = get_session_factory()
    async with factory() as session:
        stmt = select(OrgSettings).order_by(OrgSettings.id.desc()).limit(1)
        org_row = (await session.execute(stmt)).scalar_one_or_none()

    masked_anthropic: str | None = None
    masked_google: str | None = None
    masked_slack: str | None = None
    current_provider = "anthropic"
    current_anthropic_model: str | None = None
    current_google_model: str | None = None
    if org_row is not None:
        if org_row.encrypted_anthropic_key:
            try:
                masked_anthropic = mask_for_display(decrypt(org_row.encrypted_anthropic_key))
            except Exception:  # noqa: BLE001
                masked_anthropic = "…(decryption error)"
        if org_row.encrypted_google_key:
            try:
                masked_google = mask_for_display(decrypt(org_row.encrypted_google_key))
            except Exception:  # noqa: BLE001
                masked_google = "…(decryption error)"
        if org_row.encrypted_slack_webhook:
            try:
                masked_slack = mask_for_display(decrypt(org_row.encrypted_slack_webhook), keep=8)
            except Exception:  # noqa: BLE001
                masked_slack = "…(decryption error)"
        current_provider = org_row.default_provider.value
        current_anthropic_model = org_row.anthropic_model
        current_google_model = org_row.google_model

    current_bypass_slack_mode = (
        getattr(org_row, "bypass_slack_mode", "dev_only") if org_row else "dev_only"
    )

    return templates.TemplateResponse(
        request,
        "admin_org_settings.html",
        {
            "user": admin,
            "masked_anthropic": masked_anthropic,
            "masked_google": masked_google,
            "masked_slack": masked_slack,
            "current_provider": current_provider,
            "current_anthropic_model": current_anthropic_model,
            "current_google_model": current_google_model,
            "current_bypass_slack_mode": current_bypass_slack_mode,
            "known_models": KNOWN_MODELS,
            "flash": None,
        },
        headers=_NO_STORE_HEADERS,
    )


@router.post("/org-settings", response_class=HTMLResponse)
async def admin_org_settings_post(
    request: Request,
    admin: _AdminDep,
    default_provider: Annotated[str, Form()],
    anthropic_model: Annotated[str, Form()] = "",
    google_model: Annotated[str, Form()] = "",
    anthropic_key: Annotated[str, Form()] = "",
    google_key: Annotated[str, Form()] = "",
    slack_webhook: Annotated[str, Form()] = "",
    bypass_slack_mode: Annotated[str, Form()] = "dev_only",
) -> HTMLResponse:
    """Save a new org_settings row (version-bumped, immutable history).

    Per-provider models are now separate fields (anthropic_model, google_model).
    Slack webhook URL stored encrypted (blank = keep existing).
    Keys left blank → preserve the existing encrypted value (if any).
    """
    from security_scanner.tokens.crypto import decrypt, encrypt, mask_for_display  # noqa: PLC0415

    default_provider = default_provider.strip().lower()
    anthropic_model = anthropic_model.strip() or None
    google_model = google_model.strip() or None
    slack_webhook = slack_webhook.strip()
    bypass_slack_mode = bypass_slack_mode.strip()

    if default_provider not in ("anthropic", "google"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown provider {default_provider!r}",
        )
    if bypass_slack_mode not in ("dev_only", "all", "none"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown bypass_slack_mode {bypass_slack_mode!r}",
        )

    factory = get_session_factory()
    async with factory() as session:
        stmt = select(OrgSettings).order_by(OrgSettings.id.desc()).limit(1)
        current = (await session.execute(stmt)).scalar_one_or_none()

        enc_anthropic = current.encrypted_anthropic_key if current else None
        enc_google = current.encrypted_google_key if current else None
        enc_slack = current.encrypted_slack_webhook if current else None

        if anthropic_key.strip():
            enc_anthropic = encrypt(anthropic_key.strip())
        if google_key.strip():
            enc_google = encrypt(google_key.strip())
        if slack_webhook:
            slack_webhook = slack_webhook.strip()
            if not slack_webhook.startswith("https://"):
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="Slack webhook URL must start with https://",
                )
            enc_slack = encrypt(slack_webhook)

        now = datetime.now(UTC)
        provider_enum = (
            LLMProvider.anthropic if default_provider == "anthropic" else LLMProvider.google
        )
        new_row = OrgSettings(
            encrypted_anthropic_key=enc_anthropic,
            encrypted_google_key=enc_google,
            encrypted_slack_webhook=enc_slack,
            default_provider=provider_enum,
            anthropic_model=anthropic_model,
            google_model=google_model,
            bypass_slack_mode=bypass_slack_mode,
            updated_at=now,
            updated_by_email=admin.email,
        )
        session.add(new_row)

        changed_fields = []
        if anthropic_key.strip():
            changed_fields.append("anthropic_key")
        if google_key.strip():
            changed_fields.append("google_key")
        if slack_webhook:
            changed_fields.append("slack_webhook")
        changed_fields.extend(
            ["default_provider", "anthropic_model", "google_model", "bypass_slack_mode"]
        )

        await token_audit.record(
            session,
            event_type=AuditEventType.org_config_changed,
            actor_email=admin.email,
            changed_fields=",".join(changed_fields),
            default_provider=default_provider,
            anthropic_model=anthropic_model or "(none)",
            google_model=google_model or "(none)",
            slack_webhook_configured=bool(enc_slack),
            bypass_slack_mode=bypass_slack_mode,
        )
        await session.commit()

    masked_anthropic_out: str | None = None
    masked_google_out: str | None = None
    masked_slack_out: str | None = None
    if enc_anthropic:
        try:
            masked_anthropic_out = mask_for_display(decrypt(enc_anthropic))
        except Exception:  # noqa: BLE001
            masked_anthropic_out = "…(decryption error)"
    if enc_google:
        try:
            masked_google_out = mask_for_display(decrypt(enc_google))
        except Exception:  # noqa: BLE001
            masked_google_out = "…(decryption error)"
    if enc_slack:
        try:
            masked_slack_out = mask_for_display(decrypt(enc_slack), keep=8)
        except Exception:  # noqa: BLE001
            masked_slack_out = "…(decryption error)"

    log.info(
        "admin org settings saved",
        actor_email=admin.email,
        default_provider=default_provider,
        anthropic_model=anthropic_model,
        google_model=google_model,
        slack_webhook_set=bool(enc_slack),
        bypass_slack_mode=bypass_slack_mode,
    )
    return templates.TemplateResponse(
        request,
        "admin_org_settings.html",
        {
            "user": admin,
            "masked_anthropic": masked_anthropic_out,
            "masked_google": masked_google_out,
            "masked_slack": masked_slack_out,
            "current_provider": default_provider,
            "current_anthropic_model": anthropic_model,
            "current_google_model": google_model,
            "current_bypass_slack_mode": bypass_slack_mode,
            "known_models": KNOWN_MODELS,
            "flash": (
                "ok:Org settings saved. All CI scans will use the new configuration immediately."
            ),
        },
        headers=_NO_STORE_HEADERS,
    )


@router.post("/org-settings/test-slack", response_class=HTMLResponse)
async def admin_test_slack(request: Request, admin: _AdminDep) -> HTMLResponse:
    """Send a test message to the configured Slack webhook.

    Resolves the webhook from DB first (admin-saved), falls back to the
    ``SLACK_WEBHOOK_URL`` env var.  Renders org-settings inline with a flash
    showing success or the specific error (no redirect needed — PRG pattern is
    the same page with a flash banner, which is already the convention here).
    """
    from security_scanner.agent.slack_alert import _post_to_slack  # noqa: PLC0415
    from security_scanner.shared.config import get_settings  # noqa: PLC0415
    from security_scanner.tokens.crypto import decrypt, mask_for_display  # noqa: PLC0415

    factory = get_session_factory()
    async with factory() as session:
        stmt = select(OrgSettings).order_by(OrgSettings.id.desc()).limit(1)
        org_row = (await session.execute(stmt)).scalar_one_or_none()

    # Resolve webhook: DB wins over env var
    webhook_url: str | None = None
    masked_anthropic: str | None = None
    masked_google: str | None = None
    masked_slack: str | None = None
    current_provider = "anthropic"
    current_anthropic_model: str | None = None
    current_google_model: str | None = None

    if org_row:
        if org_row.encrypted_anthropic_key:
            try:
                masked_anthropic = mask_for_display(decrypt(org_row.encrypted_anthropic_key))
            except Exception:  # noqa: BLE001
                masked_anthropic = "…(decryption error)"
        if org_row.encrypted_google_key:
            try:
                masked_google = mask_for_display(decrypt(org_row.encrypted_google_key))
            except Exception:  # noqa: BLE001
                masked_google = "…(decryption error)"
        if org_row.encrypted_slack_webhook:
            try:
                webhook_url = decrypt(org_row.encrypted_slack_webhook)
                masked_slack = mask_for_display(webhook_url, keep=8)
            except Exception:  # noqa: BLE001
                masked_slack = "…(decryption error)"
        current_provider = org_row.default_provider.value
        current_anthropic_model = org_row.anthropic_model
        current_google_model = org_row.google_model

    current_bypass_slack_mode_ts = (
        getattr(org_row, "bypass_slack_mode", "dev_only") if org_row else "dev_only"
    )

    if not webhook_url:
        webhook_url = get_settings().SLACK_WEBHOOK_URL

    ctx = {
        "user": admin,
        "masked_anthropic": masked_anthropic,
        "masked_google": masked_google,
        "masked_slack": masked_slack,
        "current_provider": current_provider,
        "current_anthropic_model": current_anthropic_model,
        "current_google_model": current_google_model,
        "current_bypass_slack_mode": current_bypass_slack_mode_ts,
        "known_models": KNOWN_MODELS,
    }

    if not webhook_url:
        return templates.TemplateResponse(
            request,
            "admin_org_settings.html",
            {**ctx, "flash": "error:No Slack webhook configured. Save a webhook URL below first."},
            headers=_NO_STORE_HEADERS,
        )

    text = (
        f":white_check_mark: *Test message from Phrase Security Scanner*\n"
        f"• Sent by: {admin.email}\n"
        f"• If you see this, your Slack webhook is working correctly."
    )
    delivered = await _post_to_slack(
        text, kind="admin-test", http_client=None, webhook_url=webhook_url
    )

    if delivered:
        log.info("admin slack test message sent", actor_email=admin.email)
        flash = "ok:Test message sent to Slack successfully."
    else:
        log.warning("admin slack test message failed", actor_email=admin.email)
        flash = (
            "error:Slack did not deliver the message. "
            "The webhook URL may be invalid or the channel no longer exists. "
            "Go to api.slack.com/apps → Incoming Webhooks and generate a fresh URL, "
            "then save it here."
        )

    return templates.TemplateResponse(
        request,
        "admin_org_settings.html",
        {**ctx, "flash": flash},
        headers=_NO_STORE_HEADERS,
    )


# ---------------------------------------------------------------------------
# User management (/admin/users)
# ---------------------------------------------------------------------------

_USERS_PAGE_SIZE = 50


@router.get("/users", response_class=HTMLResponse)
async def admin_users(
    request: Request,
    admin: _AdminDep,
    page: Annotated[int, Query(ge=1)] = 1,
    q: Annotated[str | None, Query(max_length=320)] = None,
) -> HTMLResponse:
    factory = get_session_factory()
    async with factory() as session:
        stmt = (
            select(User)
            .order_by(User.email)
            .offset((page - 1) * _USERS_PAGE_SIZE)
            .limit(_USERS_PAGE_SIZE + 1)
        )
        if q:
            stmt = stmt.where(User.email.ilike(f"%{q}%"))
        users = list((await session.execute(stmt)).scalars().all())

    has_next = len(users) > _USERS_PAGE_SIZE
    users = users[:_USERS_PAGE_SIZE]

    settings = get_settings()
    protected_admin_emails = frozenset(
        e.strip() for e in settings.PROTECTED_ADMIN_EMAILS.split(",") if e.strip()
    )

    return templates.TemplateResponse(
        request,
        "admin_users.html",
        {
            "user": admin,
            "users": users,
            "page": page,
            "has_next": has_next,
            "q": q or "",
            "flash": None,
            "protected_admin_emails": protected_admin_emails,
        },
    )


@router.post("/users/{email}/deactivate", response_class=HTMLResponse)
async def admin_deactivate_user(
    request: Request,
    admin: _AdminDep,
    email: str,
) -> HTMLResponse:
    """Set is_active=False. Next scan by this user → 401 Account deactivated."""
    _assert_not_protected(email)
    factory = get_session_factory()
    async with factory() as session:
        stmt = select(User).where(User.email == email)
        user_row = (await session.execute(stmt)).scalar_one_or_none()
        if user_row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
        user_row.is_active = False
        await token_audit.record(
            session,
            event_type=AuditEventType.user_deactivated,
            user_email=email,
            actor_email=admin.email,
        )
        await session.commit()

    log.info("admin user deactivated", actor_email=admin.email, target_email=email)
    return await admin_users(request, admin, page=1, q=email)


@router.post("/users/{email}/reactivate", response_class=HTMLResponse)
async def admin_reactivate_user(
    request: Request,
    admin: _AdminDep,
    email: str,
) -> HTMLResponse:
    """Set is_active=True. Re-enables scanning for the user."""
    factory = get_session_factory()
    async with factory() as session:
        stmt = select(User).where(User.email == email)
        user_row = (await session.execute(stmt)).scalar_one_or_none()
        if user_row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
        user_row.is_active = True
        user_row.last_reactivation_at = datetime.now(UTC)
        await token_audit.record(
            session,
            event_type=AuditEventType.user_reactivated,
            user_email=email,
            actor_email=admin.email,
        )
        await session.commit()

    log.info("admin user reactivated", actor_email=admin.email, target_email=email)
    return await admin_users(request, admin, page=1, q=email)


@router.post("/users/{email}/revoke-tokens", response_class=HTMLResponse)
async def admin_revoke_user_tokens(
    request: Request,
    admin: _AdminDep,
    email: str,
) -> HTMLResponse:
    """Revoke all active tokens for this user without touching is_active."""
    _assert_not_protected(email)
    factory = get_session_factory()
    async with factory() as session:
        revoked = await token_registry.revoke_active_for_user(
            session, user_email=email, actor=admin.email
        )
        await session.commit()

    log.info(
        "admin revoked user tokens",
        actor_email=admin.email,
        target_email=email,
        revoked=revoked,
    )
    return await admin_users(request, admin, page=1, q=email)


@router.post("/users/{email}/force-password-reset", response_class=HTMLResponse)
async def admin_force_password_reset(
    request: Request,
    admin: _AdminDep,
    email: str,
) -> HTMLResponse:
    """Set must_change_password=True and clear any stored password hash.

    Only applies to local-auth users. Okta users reset credentials via Okta.
    The user will be redirected to /portal/change-password on their next login.
    """
    factory = get_session_factory()
    async with factory() as session:
        row = await session.get(User, email)
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
        if getattr(row, "auth_provider", "local") != "local":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "Password reset only applies to local-auth users. "
                    "Okta users reset credentials via Okta."
                ),
            )
        row.must_change_password = True
        row.password_hash = None  # clear stored hash → falls back to env var on next login
        await token_audit.record(
            session,
            event_type=AuditEventType.user_password_force_reset,
            user_email=email,
            actor_email=admin.email,
        )
        await session.commit()
    log.info("admin forced password reset", actor_email=admin.email, target_email=email)
    return await admin_users(request, admin, page=1, q=email)


@router.post("/users/{email}/promote", response_class=HTMLResponse)
async def admin_promote_user(
    request: Request,
    admin: _AdminDep,
    email: str,
) -> HTMLResponse:
    """Set ``role=admin``.

    The user will be redirected to ``/admin/tokens`` on their next login.
    Target email is validated against DB (404 if not found) — prevents IDOR.
    """
    factory = get_session_factory()
    async with factory() as session:
        stmt = select(User).where(User.email == email)
        user_row = (await session.execute(stmt)).scalar_one_or_none()
        if user_row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
        user_row.role = UserRole.admin
        await token_audit.record(
            session,
            event_type=AuditEventType.user_promoted,
            user_email=email,
            actor_email=admin.email,
        )
        await session.commit()

    log.info("admin promoted user to admin", actor_email=admin.email, target_email=email)
    return await admin_users(request, admin, page=1, q=email)


@router.post("/users/{email}/demote", response_class=HTMLResponse)
async def admin_demote_user(
    request: Request,
    admin: _AdminDep,
    email: str,
) -> HTMLResponse:
    """Set ``role=user``.

    Blocks self-demotion to prevent admin lockout. Target email is validated
    against DB (404 if not found) — prevents IDOR.
    """
    # Lockout guard: an admin cannot remove their own admin role.
    if email == admin.email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot remove your own admin role.",
        )
    # Super-admin guard: protected accounts cannot be demoted by anyone.
    _assert_not_protected(email)
    factory = get_session_factory()
    async with factory() as session:
        stmt = select(User).where(User.email == email)
        user_row = (await session.execute(stmt)).scalar_one_or_none()
        if user_row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
        user_row.role = UserRole.user
        await token_audit.record(
            session,
            event_type=AuditEventType.user_demoted,
            user_email=email,
            actor_email=admin.email,
        )
        await session.commit()

    log.info("admin demoted user from admin", actor_email=admin.email, target_email=email)
    return await admin_users(request, admin, page=1, q=email)


# ---------------------------------------------------------------------------
# Advanced settings (/admin/advanced-settings)
# ---------------------------------------------------------------------------

_KEEP_CONF_OPTIONS = {
    "high": "High confidence only",
    "high,medium": "High + Medium confidence (recommended)",
    "high,medium,low": "High + Medium + Low confidence",
}

_ADVISORY_CONF_OPTIONS = {
    "low": "Low confidence only (recommended)",
    "medium,low": "Medium + Low confidence",
    "": "None (no advisory findings)",
}


@router.get("/advanced-settings", response_class=HTMLResponse)
async def admin_advanced_settings_get(
    request: Request,
    admin: _AdminDep,
) -> HTMLResponse:
    """Render the Advanced Settings page with the current DB-stored values."""
    factory = get_session_factory()
    async with factory() as session:
        stmt = select(ScannerSettings).order_by(ScannerSettings.id.desc()).limit(1)
        sc = (await session.execute(stmt)).scalar_one_or_none()

    return templates.TemplateResponse(
        request,
        "admin_advanced_settings.html",
        {
            "user": admin,
            "sc": sc,
            "keep_conf_options": _KEEP_CONF_OPTIONS,
            "advisory_conf_options": _ADVISORY_CONF_OPTIONS,
            "flash": None,
        },
        headers=_NO_STORE_HEADERS,
    )


@router.post("/advanced-settings", response_class=HTMLResponse)
async def admin_advanced_settings_post(
    request: Request,
    admin: _AdminDep,
    keep_confidences: Annotated[str, Form()],
    advisory_confidences: Annotated[str, Form()],
    vuln_verifier_parallelism: Annotated[int, Form()],
    high_risk_paths: Annotated[str, Form()] = "",
    enable_consolidation_verifier: Annotated[str, Form()] = "",
    enable_partial_scan: Annotated[str, Form()] = "",
    enable_zero_findings_retry: Annotated[str, Form()] = "",
    enable_quality_gate: Annotated[str, Form()] = "",
    report_retention_days: Annotated[str, Form()] = "",
    enable_semgrep: Annotated[str, Form()] = "",
    enable_bandit: Annotated[str, Form()] = "",
    enable_gosec: Annotated[str, Form()] = "",
    enable_eslint: Annotated[str, Form()] = "",
    semgrep_owasp: Annotated[str, Form()] = "",
    semgrep_audit: Annotated[str, Form()] = "",
    semgrep_upload: Annotated[str, Form()] = "",
) -> HTMLResponse:
    """Save a new ScannerSettings row (append-only, MAX id is authoritative)."""
    # Validate keep_confidences is one of the known combos.
    if keep_confidences not in _KEEP_CONF_OPTIONS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid keep_confidences value: {keep_confidences!r}",
        )
    # Clamp parallelism to [1, 16].
    parallelism = max(1, min(16, vuln_verifier_parallelism))

    # HTML checkboxes omit the field entirely when unchecked.
    # FastAPI Form() defaults to "" — bool("") == False, bool("on") == True.
    now = datetime.now(UTC)
    sc = ScannerSettings(
        keep_confidences=keep_confidences,
        advisory_confidences=advisory_confidences,
        enable_semgrep=bool(enable_semgrep),
        enable_bandit=bool(enable_bandit),
        enable_gosec=bool(enable_gosec),
        enable_eslint=bool(enable_eslint),
        semgrep_owasp=bool(semgrep_owasp),
        semgrep_audit=bool(semgrep_audit),
        semgrep_upload=bool(semgrep_upload),
        vuln_verifier_parallelism=parallelism,
        enable_consolidation_verifier=bool(enable_consolidation_verifier),
        enable_partial_scan=bool(enable_partial_scan),
        enable_zero_findings_retry=bool(enable_zero_findings_retry),
        enable_quality_gate=bool(enable_quality_gate),
        report_retention_days=(
            int(report_retention_days) if report_retention_days.strip().isdigit() else None
        ),
        high_risk_paths=high_risk_paths.strip(),
        updated_at=now,
        updated_by_email=admin.email,
    )
    factory = get_session_factory()
    async with factory() as session:
        session.add(sc)
        await token_audit.record(
            session,
            event_type=AuditEventType.org_config_changed,
            actor_email=admin.email,
            section="advanced_settings",
            keep_confidences=keep_confidences,
            advisory_confidences=advisory_confidences,
            parallelism=parallelism,
            enable_semgrep=bool(enable_semgrep),
            enable_bandit=bool(enable_bandit),
            enable_gosec=bool(enable_gosec),
            enable_eslint=bool(enable_eslint),
            enable_consolidation_verifier=bool(enable_consolidation_verifier),
            enable_partial_scan=bool(enable_partial_scan),
            enable_zero_findings_retry=bool(enable_zero_findings_retry),
            enable_quality_gate=bool(enable_quality_gate),
        )
        await session.commit()

    log.info(
        "admin advanced settings saved",
        actor_email=admin.email,
        keep_confidences=keep_confidences,
        parallelism=parallelism,
        enable_consolidation_verifier=bool(enable_consolidation_verifier),
        enable_partial_scan=bool(enable_partial_scan),
        enable_zero_findings_retry=bool(enable_zero_findings_retry),
    )
    return templates.TemplateResponse(
        request,
        "admin_advanced_settings.html",
        {
            "user": admin,
            "sc": sc,
            "keep_conf_options": _KEEP_CONF_OPTIONS,
            "advisory_conf_options": _ADVISORY_CONF_OPTIONS,
            "flash": "ok:Advanced settings saved. The next scan will use the new configuration.",
        },
        headers=_NO_STORE_HEADERS,
    )


# ---------------------------------------------------------------------------
# CI token management (/admin/ci-token)
# ---------------------------------------------------------------------------


@router.get("/ci-token", response_class=HTMLResponse)
async def admin_ci_token_get(request: Request, admin: _AdminDep) -> HTMLResponse:
    """Show the active CI token (truncated) and a Rotate button."""
    factory = get_session_factory()
    async with factory() as session:
        stmt = (
            select(CIToken).where(CIToken.revoked_at.is_(None)).order_by(desc(CIToken.id)).limit(1)
        )
        active = (await session.execute(stmt)).scalar_one_or_none()

    return templates.TemplateResponse(
        request,
        "admin_ci_token.html",
        {
            "user": admin,
            "active": active,
            "new_token": None,
            "flash": None,
        },
        headers=_NO_STORE_HEADERS,
    )


@router.post("/ci-token/rotate", response_class=HTMLResponse)
async def admin_ci_token_rotate(request: Request, admin: _AdminDep) -> HTMLResponse:
    """Rotate the CI token: revoke current (if any), insert new one.

    The new plaintext is shown ONCE. The admin must update SCANNER_API_TOKEN
    in GitHub Actions secrets before the next CI scan.
    """
    from datetime import UTC, datetime  # noqa: PLC0415

    suffix = secrets.token_urlsafe(32)
    new_plaintext = f"{_CI_TOKEN_PREFIX}{suffix}"
    new_hash = _hash_ci_token(new_plaintext)
    now = datetime.now(UTC)

    factory = get_session_factory()
    async with factory() as session:
        stmt = (
            select(CIToken).where(CIToken.revoked_at.is_(None)).order_by(desc(CIToken.id)).limit(1)
        )
        current = (await session.execute(stmt)).scalar_one_or_none()
        if current is not None:
            current.revoked_at = now
            current.revoked_by_email = admin.email
            await session.flush()

        new_row = CIToken(
            token_hash=new_hash,
            created_at=now,
            created_by_email=admin.email,
        )
        session.add(new_row)

        await token_audit.record(
            session,
            event_type=AuditEventType.ci_token_rotated,
            actor_email=admin.email,
            previous_id=current.id if current else None,
        )
        await session.commit()

    log.info("admin ci token rotated", actor_email=admin.email)
    return templates.TemplateResponse(
        request,
        "admin_ci_token.html",
        {
            "user": admin,
            "active": new_row,
            "new_token": new_plaintext,
            "flash": (
                "ok:CI token rotated. Copy the new token below and "
                "update the GitHub Actions secret SCANNER_API_TOKEN immediately."
            ),
        },
        headers=_NO_STORE_HEADERS,
    )


# ---------------------------------------------------------------------------
# Usage analytics (/admin/usage)
# ---------------------------------------------------------------------------

_USAGE_LOOKBACK_DAYS = 90


@router.get("/usage", response_class=HTMLResponse)
async def admin_usage(
    request: Request,
    admin: _AdminDep,
) -> HTMLResponse:
    """Per-user scan activity and LLM token spend from the last 90 days.

    Queries ``scan_records`` for scan counts + severity totals and
    ``llm_usage_monthly`` for token spend across the last 3 calendar months.
    No new data is written — read-only view over existing tables.
    """
    cutoff = datetime.now(UTC) - timedelta(days=_USAGE_LOOKBACK_DAYS)

    # Compute the last 3 calendar months (e.g. "2026-05", "2026-04", "2026-03")
    now = datetime.now(UTC)
    months: list[str] = []
    for i in range(3):
        # Subtract i months by stepping back month by month
        y, m = now.year, now.month - i
        while m <= 0:
            m += 12
            y -= 1
        months.append(f"{y:04d}-{m:02d}")

    factory = get_session_factory()
    async with factory() as session:
        # --- Scan activity: per-user aggregates over last 90 days ---
        scan_stmt = (
            select(
                ScanRecord.user_email,
                func.count().label("total_scans"),
                func.sum(ScanRecord.critical).label("total_critical"),
                func.sum(ScanRecord.high).label("total_high"),
                func.sum(ScanRecord.findings_count).label("total_findings"),
                func.max(ScanRecord.started_at).label("last_scan_at"),
            )
            .where(ScanRecord.started_at >= cutoff)
            .group_by(ScanRecord.user_email)
            .order_by(desc("total_scans"))
        )
        scan_rows = list((await session.execute(scan_stmt)).all())

        # --- CI scan activity: per-actor aggregates over last 90 days ---
        ci_scan_stmt = (
            select(
                CiScanRecord.triggered_by,
                func.count().label("total_scans"),
                func.sum(CiScanRecord.critical).label("total_critical"),
                func.sum(CiScanRecord.high).label("total_high"),
                func.sum(CiScanRecord.findings_count).label("total_findings"),
                func.max(CiScanRecord.started_at).label("last_scan_at"),
            )
            .where(CiScanRecord.started_at >= cutoff)
            .group_by(CiScanRecord.triggered_by)
            .order_by(desc("total_scans"))
        )
        ci_scan_rows = list((await session.execute(ci_scan_stmt)).all())

        # --- Token spend: last 3 months, all rows ---
        usage_stmt = (
            select(LLMUsageMonthly)
            .where(LLMUsageMonthly.year_month.in_(months))
            .order_by(
                LLMUsageMonthly.year_month.desc(),
                LLMUsageMonthly.user_email,
                LLMUsageMonthly.provider,
            )
        )
        usage_rows = list((await session.execute(usage_stmt)).scalars().all())

    return templates.TemplateResponse(
        request,
        "admin_usage.html",
        {
            "user": admin,
            "scan_rows": scan_rows,
            "ci_scan_rows": ci_scan_rows,
            "usage_rows": usage_rows,
            "months": months,
            "lookback_days": _USAGE_LOOKBACK_DAYS,
            "flash": None,
        },
    )


# --- Reports (/admin/reports) -----------------------------------------------


_REPORTS_PAGE_SIZE = 25


@dataclass
class _ReportRow:
    source: str  # "portal" | "ci"
    scan_id: _uuid.UUID
    started_at: datetime
    actor: str
    repo_url: str
    provider: str | None
    status: str
    findings_count: int
    critical: int
    high: int
    medium: int
    low: int
    has_report: bool  # True if html_report is not None (portal only)


async def _fetch_report_rows(session) -> list[_ReportRow]:  # type: ignore[type-arg]
    """Fetch all portal + CI scan records and merge into a unified sorted list."""
    portal_stmt = select(ScanRecord).order_by(desc(ScanRecord.started_at))
    portal_rows = (await session.execute(portal_stmt)).scalars().all()

    ci_stmt = select(CiScanRecord).order_by(desc(CiScanRecord.started_at))
    ci_rows = (await session.execute(ci_stmt)).scalars().all()

    rows: list[_ReportRow] = []
    for r in portal_rows:
        rows.append(_ReportRow(
            source="portal",
            scan_id=r.scan_id,
            started_at=r.started_at,
            actor=r.user_email,
            repo_url=r.repo_url or "",
            provider=r.provider,
            status=r.status.value if hasattr(r.status, "value") else str(r.status),
            findings_count=r.findings_count,
            critical=r.critical,
            high=r.high,
            medium=r.medium,
            low=r.low,
            has_report=bool(r.html_report),
        ))
    for r in ci_rows:
        rows.append(_ReportRow(
            source="ci",
            scan_id=r.scan_id,
            started_at=r.started_at,
            actor=r.triggered_by,
            repo_url=r.repo_url or "",
            provider=r.provider,
            status=r.status.value if hasattr(r.status, "value") else str(r.status),
            findings_count=r.findings_count,
            critical=r.critical,
            high=r.high,
            medium=r.medium,
            low=r.low,
            has_report=bool(r.html_report),
        ))

    rows.sort(key=lambda x: x.started_at, reverse=True)
    return rows


def _render_reports(
    request: Request,
    admin: PhraseUser,
    rows: list[_ReportRow],
    page: int,
    flash: str | None = None,
) -> HTMLResponse:
    total = len(rows)
    offset = (page - 1) * _REPORTS_PAGE_SIZE
    page_rows = rows[offset: offset + _REPORTS_PAGE_SIZE]
    has_next = offset + _REPORTS_PAGE_SIZE < total
    portal_count = sum(1 for r in rows if r.source == "portal")
    ci_count = total - portal_count
    return templates.TemplateResponse(
        request,
        "admin_reports.html",
        {
            "user": admin,
            "rows": page_rows,
            "page": page,
            "has_next": has_next,
            "portal_count": portal_count,
            "ci_count": ci_count,
            "flash": flash,
        },
        headers=_NO_STORE_HEADERS,
    )


@router.get("/reports", response_class=HTMLResponse)
async def admin_reports(
    request: Request,
    admin: _AdminDep,
    page: Annotated[int, Query(ge=1)] = 1,
) -> HTMLResponse:
    """Combined portal + CI scan report list."""
    factory = get_session_factory()
    async with factory() as session:
        all_rows = await _fetch_report_rows(session)
    return _render_reports(request, admin, all_rows, page)


@router.post("/reports/purge-all", response_class=HTMLResponse)
async def admin_reports_purge_all(
    request: Request,
    admin: _AdminDep,
) -> HTMLResponse:
    """Delete ALL portal and CI scan records."""
    factory = get_session_factory()
    async with factory() as session:
        portal_result = await session.execute(delete(ScanRecord))
        ci_result = await session.execute(delete(CiScanRecord))
        await session.commit()
        portal_deleted = portal_result.rowcount or 0
        ci_deleted = ci_result.rowcount or 0
        all_rows = await _fetch_report_rows(session)

    log.info(
        "admin reports purge_all",
        actor_email=admin.email,
        portal_deleted=portal_deleted,
        ci_deleted=ci_deleted,
    )
    flash = f"ok:Purged {portal_deleted} portal and {ci_deleted} CI records."
    return _render_reports(request, admin, all_rows, page=1, flash=flash)


@router.post("/reports/bulk-delete", response_class=HTMLResponse)
async def admin_reports_bulk_delete(
    request: Request,
    admin: _AdminDep,
) -> HTMLResponse:
    """Delete selected scan records. Form posts scan_ids as 'source:uuid' strings."""
    form = await request.form()
    raw_ids: list[str] = form.getlist("scan_ids")

    portal_ids: list[_uuid.UUID] = []
    ci_ids: list[_uuid.UUID] = []
    for item in raw_ids:
        parts = item.split(":", 1)
        if len(parts) != 2:
            continue
        source, scan_id_str = parts
        try:
            uid = _uuid.UUID(scan_id_str)
        except ValueError:
            continue
        if source == "portal":
            portal_ids.append(uid)
        elif source == "ci":
            ci_ids.append(uid)

    deleted = 0
    factory = get_session_factory()
    async with factory() as session:
        if portal_ids:
            res = await session.execute(
                delete(ScanRecord).where(ScanRecord.scan_id.in_(portal_ids))
            )
            deleted += res.rowcount or 0
        if ci_ids:
            res = await session.execute(
                delete(CiScanRecord).where(CiScanRecord.scan_id.in_(ci_ids))
            )
            deleted += res.rowcount or 0
        await session.commit()
        all_rows = await _fetch_report_rows(session)

    log.info("admin reports bulk_delete", actor_email=admin.email, deleted=deleted)
    flash = f"ok:Deleted {deleted} record{'s' if deleted != 1 else ''}."
    return _render_reports(request, admin, all_rows, page=1, flash=flash)


@router.post("/reports/{scan_id}/delete", response_class=HTMLResponse)
async def admin_delete_report(
    request: Request,
    admin: _AdminDep,
    scan_id: str,
) -> HTMLResponse:
    """Delete a single scan record (portal or CI)."""
    try:
        scan_uuid = _uuid.UUID(scan_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Invalid scan ID."
        ) from exc

    factory = get_session_factory()
    async with factory() as session:
        portal_row = (
            await session.execute(select(ScanRecord).where(ScanRecord.scan_id == scan_uuid))
        ).scalar_one_or_none()

        if portal_row is not None:
            await session.delete(portal_row)
            deleted = True
        else:
            ci_row = (
                await session.execute(
                    select(CiScanRecord).where(CiScanRecord.scan_id == scan_uuid)
                )
            ).scalar_one_or_none()
            if ci_row is not None:
                await session.delete(ci_row)
                deleted = True
            else:
                deleted = False

        await session.commit()
        all_rows = await _fetch_report_rows(session)

    log.info("admin reports delete", actor_email=admin.email, scan_id=scan_id, deleted=deleted)
    flash = "ok:Record deleted." if deleted else f"error:Record {scan_id} not found."
    return _render_reports(request, admin, all_rows, page=1, flash=flash)


@router.get("/reports/{scan_id}/html", response_class=HTMLResponse)
async def admin_report_html(
    scan_id: str,
    admin: _AdminDep,
) -> HTMLResponse:
    """Serve raw HTML report for a CI or portal scan (admin view)."""
    try:
        scan_uuid = _uuid.UUID(scan_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Invalid scan ID.") from exc

    factory = get_session_factory()
    async with factory() as session:
        ci = (await session.execute(
            select(CiScanRecord).where(CiScanRecord.scan_id == scan_uuid)
        )).scalar_one_or_none()
        if ci is not None:
            html = ci.html_report
        else:
            portal = (await session.execute(
                select(ScanRecord).where(ScanRecord.scan_id == scan_uuid)
            )).scalar_one_or_none()
            html = portal.html_report if portal else None

    if not html:
        raise HTTPException(status_code=404, detail="Report not found.")
    return HTMLResponse(content=html)
