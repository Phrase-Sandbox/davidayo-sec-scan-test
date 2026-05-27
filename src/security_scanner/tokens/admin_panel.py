"""``/admin/*`` — admin panel for the per-user token registry.

Three capabilities live here:

1. ``GET /admin/tokens`` — list/filter all tokens (active + historical).
2. ``POST /admin/tokens/{token_id}/revoke`` — force-revoke any active token.
3. ``POST /admin/tokens/{token_id}/force-rotate`` — server generates a new
   suffix; the admin sees the new plaintext token exactly once and hands it
   to the user via a secure channel (1Password share, etc.). Used when a
   user can't SSO themselves (lost laptop, off-network).
4. ``GET /admin/audit`` — paginated audit log viewer over ``audit_events``.

Every route is guarded by :func:`require_admin`, which checks
``ADMIN_GROUP_NAME`` membership in the ``X-Userinfo.groups`` claim. For
local dev ``ADMIN_LOCAL_BYPASS=true`` injects a synthetic admin (and the
app refuses to start if that flag is set against a non-local DB).
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc, func, select

from security_scanner.shared.logging_util import get_logger
from security_scanner.tokens import audit as token_audit
from security_scanner.tokens import registry as token_registry
from security_scanner.tokens.auth import PhraseUser, require_admin
from security_scanner.tokens.db import get_session_factory
from security_scanner.tokens.models import (
    AuditEvent,
    AuditEventType,
    CIToken,
    LLMProvider,
    LLMUsageMonthly,
    OrgSettings,
    ScanRecord,
    User,
)

log = get_logger(__name__)

router = APIRouter(prefix="/admin", tags=["admin"])

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

# Force-rotated tokens render the new plaintext once — keep them out of any
# caching proxy or browser history.
_NO_STORE_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "Referrer-Policy": "no-referrer",
}

_AdminDep = Annotated[PhraseUser, Depends(require_admin)]


# --- Token management -------------------------------------------------------


@router.get("/tokens", response_class=HTMLResponse)
async def admin_tokens(
    request: Request,
    admin: _AdminDep,
    user: Annotated[str | None, Query(max_length=320)] = None,
    active_only: Annotated[bool, Query()] = False,
) -> HTMLResponse:
    factory = get_session_factory()
    async with factory() as session:
        rows = await token_registry.list_all(
            session,
            active_only=active_only,
            user_email_contains=user or None,
        )
    return templates.TemplateResponse(
        request,
        "admin_tokens.html",
        {
            "user": admin,
            "rows": rows,
            "filter_user": user or "",
            "active_only": active_only,
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
    flash = (
        f"Token {token_id} revoked."
        if ok
        else f"No active token found for {token_id}."
    )
    return templates.TemplateResponse(
        request,
        "admin_tokens.html",
        {
            "user": admin,
            "rows": rows,
            "filter_user": "",
            "active_only": False,
            "issued_token": None,
            "flash": flash,
        },
        headers=_NO_STORE_HEADERS,
    )


@router.post("/tokens/{token_id}/force-rotate", response_class=HTMLResponse)
async def admin_force_rotate(
    request: Request,
    admin: _AdminDep,
    token_id: str,
) -> HTMLResponse:
    """Rotate a user's token on their behalf; render the new plaintext once.

    The admin is responsible for delivering the new value to the user via a
    secure channel (1Password share / Signal). The plaintext is NEVER stored
    or echoed back on a subsequent page load.
    """
    factory = get_session_factory()
    async with factory() as session:
        issued = await token_registry.force_rotate_by_token_id(
            session, token_id=token_id, admin_email=admin.email
        )
        if issued is None:
            await session.rollback()
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No active token found for {token_id}.",
            )
        await session.commit()
        rows = await token_registry.list_all(session)

    log.info(
        "admin token force-rotate",
        actor_email=admin.email,
        token_id=issued.token_id,
        user_email=issued.user_email,
    )
    return templates.TemplateResponse(
        request,
        "admin_tokens.html",
        {
            "user": admin,
            "rows": rows,
            "filter_user": "",
            "active_only": False,
            "issued_token": issued,
            "flash": (
                f"Rotated token for {issued.user_email}. "
                "Copy the new plaintext below and hand it over via a secure channel."
            ),
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
                masked_slack = mask_for_display(
                    decrypt(org_row.encrypted_slack_webhook), keep=8
                )
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
            enc_slack = encrypt(slack_webhook)

        now = datetime.now(UTC)
        provider_enum = LLMProvider.anthropic if default_provider == "anthropic" else LLMProvider.google
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
        changed_fields.extend(["default_provider", "anthropic_model", "google_model", "bypass_slack_mode"])

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
            "flash": "ok:Org settings saved. All CI scans will use the new configuration immediately.",
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
            {**ctx, "flash": "error:No Slack webhook configured. Save a webhook URL in the form below first."},
            headers=_NO_STORE_HEADERS,
        )

    text = (
        f":white_check_mark: *Test message from Phrase Security Scanner*\n"
        f"• Sent by: {admin.email}\n"
        f"• If you see this, your Slack webhook is working correctly."
    )
    await _post_to_slack(text, kind="admin-test", http_client=None, webhook_url=webhook_url)
    log.info("admin slack test message sent", actor_email=admin.email)

    return templates.TemplateResponse(
        request,
        "admin_org_settings.html",
        {**ctx, "flash": "ok:Test message sent to Slack successfully."},
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
        },
    )


@router.post("/users/{email}/deactivate", response_class=HTMLResponse)
async def admin_deactivate_user(
    request: Request,
    admin: _AdminDep,
    email: str,
) -> HTMLResponse:
    """Set is_active=False. Next scan by this user → 401 Account deactivated."""
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


# ---------------------------------------------------------------------------
# CI token management (/admin/ci-token)
# ---------------------------------------------------------------------------


@router.get("/ci-token", response_class=HTMLResponse)
async def admin_ci_token_get(request: Request, admin: _AdminDep) -> HTMLResponse:
    """Show the active CI token (truncated) and a Rotate button."""
    factory = get_session_factory()
    async with factory() as session:
        stmt = (
            select(CIToken)
            .where(CIToken.revoked_at.is_(None))
            .order_by(desc(CIToken.id))
            .limit(1)
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
            select(CIToken)
            .where(CIToken.revoked_at.is_(None))
            .order_by(desc(CIToken.id))
            .limit(1)
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
            "flash": "ok:CI token rotated. Copy the new token below and update the GitHub Actions secret SCANNER_API_TOKEN immediately.",
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
            "usage_rows": usage_rows,
            "months": months,
            "lookback_days": _USAGE_LOOKBACK_DAYS,
            "flash": None,
        },
    )
