"""``/portal/*`` — user self-service portal.

Four sections:

1. **Token** (``GET /portal/``, ``POST /portal/tokens``,
   ``POST /portal/tokens/revoke``) — issue, rotate, or revoke the
   developer's personal scanner token. The plaintext is shown exactly once
   on ``portal_token_shown.html`` and is never re-displayed.

2. **Settings** (``GET/POST /portal/settings``) — save the user's LLM
   provider, model, and API key (encrypted at rest with Fernet).

3. **Scans** (``GET /portal/scans``, ``GET /portal/scans/<scan_id>``) —
   paginated scan history and per-scan HTML report viewer.

4. **Usage** (``GET /portal/usage``) — monthly token + call breakdown for
   the user's own LLM key, with response IDs for cross-referencing with the
   provider's billing console.

5. **CLI browser-callback login** (``GET /portal/cli/login``,
   ``POST /portal/cli/login/complete``) — the ``phrase-sec-scan`` CLI binds
   a localhost listener; on approval the server redirects to the loopback
   listener with the token in the query string.

Trust model: every request MUST come through the Phrase Platform ingress
(Okta ``X-Userinfo``). For local dev, set ``ADMIN_LOCAL_BYPASS=true``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc, select

from security_scanner.shared.config import get_settings
from security_scanner.shared.logging_util import get_logger
from security_scanner.tokens import audit as token_audit
from security_scanner.tokens import registry as token_registry
from security_scanner.tokens.auth import PhraseUser, require_phrase_user
from security_scanner.tokens.db import get_session_factory
from security_scanner.tokens.models import (
    AuditEventType,
    LLMProvider,
    LLMUsageMonthly,
    OrgSettings,
    ScanRecord,
    UserLLMSettings,
)

log = get_logger(__name__)

router = APIRouter(prefix="/portal", tags=["portal"])

_TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

# Issued tokens land in the response body / a loopback redirect. Keep them
# out of any caching proxy or browser history beyond strict need.
_NO_STORE_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "Referrer-Policy": "no-referrer",
}


_UserDep = Annotated[PhraseUser, Depends(require_phrase_user)]

_SCANS_PAGE_SIZE = 20


async def _load_active_org_settings_for_portal() -> OrgSettings | None:
    """Return the latest ``OrgSettings`` row for portal display, or ``None``."""
    factory = get_session_factory()
    async with factory() as session:
        stmt = select(OrgSettings).order_by(OrgSettings.id.desc()).limit(1)
        return (await session.execute(stmt)).scalar_one_or_none()


def _valid_callback_port(port: int) -> bool:
    """Ports < 1024 require root on macOS/Linux — never a legitimate CLI listener."""
    return 1024 <= port <= 65535


def _valid_hostname(hostname: str) -> bool:
    """Hostname is display-only on the consent screen — sanity-check it's not absurd."""
    if not hostname or len(hostname) > 253:
        return False
    # Allow letters, digits, dot, dash, underscore. Anything richer is likely an injection.
    return all(c.isalnum() or c in "-._" for c in hostname)


# --- Login / logout (Okta-wired) ---------------------------------------------


@router.get("/login", response_class=HTMLResponse, include_in_schema=False)
async def portal_login_page(
    request: Request,
    next: str = "/portal/",
) -> HTMLResponse:
    """Login landing page shown to unauthenticated browser requests.

    If ``PORTAL_LOGIN_URL`` is configured (e.g. Okta auth endpoint), the page
    shows a "Sign in with Okta" button pointing there.  If not set, it shows
    contact-administrator instructions.  Authentication itself is handled by
    the Okta ingress — this page is purely informational / a redirect helper.
    """
    settings = get_settings()
    return templates.TemplateResponse(
        request,
        "portal_login.html",
        {"login_url": settings.PORTAL_LOGIN_URL, "next": next},
    )


@router.post("/logout", response_class=HTMLResponse, include_in_schema=False)
async def portal_logout(request: Request) -> RedirectResponse:
    """Sign-out: redirect to login page.

    Okta sessions are terminated by the ingress; this route handles the
    in-app link and ensures the browser lands on the login page.
    """
    return RedirectResponse(url="/portal/login", status_code=302)


# --- Browser self-service ----------------------------------------------------


@router.get("/", response_class=HTMLResponse)
async def portal_index(request: Request, user: _UserDep) -> HTMLResponse:
    """Show the caller's current token status.

    Admins are redirected to the admin panel — they have a separate UI.
    Regular portal users see their token management page.
    """
    # Role-based landing: admins belong in the admin panel.
    if get_settings().ADMIN_GROUP_NAME in user.groups:
        return RedirectResponse(url="/admin/tokens", status_code=302)

    factory = get_session_factory()
    async with factory() as session:
        active = await token_registry.get_active_for_user(
            session, user_email=user.email
        )
    return templates.TemplateResponse(
        request,
        "portal_index.html",
        {
            "user": user,
            "active": active,
        },
        headers=_NO_STORE_HEADERS,
    )


@router.post("/tokens", response_class=HTMLResponse)
async def portal_issue_or_rotate(
    request: Request, user: _UserDep
) -> HTMLResponse:
    """Issue a first token, or rotate the existing one.

    On rotation, the same 12-hex ``token_id`` prefix is preserved so audit
    history stays continuous; only the secret suffix changes.
    """
    factory = get_session_factory()
    async with factory() as session:
        # Ensure a users row exists — required FK parent for user_llm_settings
        # and scan_records. Called here so the row is always present before
        # any FK-constrained child insert in this session or later ones.
        await token_registry.upsert_user(session, email=user.email)
        issued = await token_registry.issue_or_rotate_for_user(
            session, user_email=user.email
        )
        await session.commit()

    log.info(
        "token issued via portal",
        user_email=user.email,
        token_id=issued.token_id,
        was_rotation=issued.was_rotation,
    )
    return templates.TemplateResponse(
        request,
        "portal_token_shown.html",
        {
            "user": user,
            "issued": issued,
            "cli_callback": None,
        },
        headers=_NO_STORE_HEADERS,
    )


@router.post("/tokens/revoke", response_class=HTMLResponse)
async def portal_revoke(request: Request, user: _UserDep) -> HTMLResponse:
    """Revoke the caller's current active token, if any."""
    factory = get_session_factory()
    async with factory() as session:
        revoked = await token_registry.revoke_active_for_user(
            session, user_email=user.email, actor="self"
        )
        await session.commit()

    log.info("token revoked via portal", user_email=user.email, revoked=revoked)
    return templates.TemplateResponse(
        request,
        "portal_index.html",
        {
            "user": user,
            "active": None,
            "flash": "Token revoked." if revoked else "No active token to revoke.",
        },
        headers=_NO_STORE_HEADERS,
    )


# --- CLI browser-callback ---------------------------------------------------


@router.get("/cli/login", response_class=HTMLResponse)
async def cli_login_consent(
    request: Request,
    user: _UserDep,
    callback_port: Annotated[int, Query(ge=1024, le=65535)],
    hostname: Annotated[str, Query(min_length=1, max_length=253)],
) -> HTMLResponse:
    """Render the consent screen: ``phrase-sec-scan`` on ``<hostname>`` wants a token.

    Validates the callback target up front. The localhost address is fixed
    at submit time — we never accept an arbitrary redirect URL.
    """
    if not _valid_callback_port(callback_port):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="callback_port must be in [1024, 65535].",
        )
    if not _valid_hostname(hostname):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="hostname must be a plausible host string.",
        )
    return templates.TemplateResponse(
        request,
        "portal_cli_consent.html",
        {
            "user": user,
            "callback_port": callback_port,
            "hostname": hostname,
        },
        headers=_NO_STORE_HEADERS,
    )


@router.post("/cli/login/complete")
async def cli_login_complete(
    user: _UserDep,
    callback_port: Annotated[int, Form()],
    hostname: Annotated[str, Form()],
) -> RedirectResponse:
    """Issue (or rotate) and redirect to ``http://127.0.0.1:<port>/?token=...``.

    The token leaves the server in a query string, but only on the loopback
    hop to the CLI's local listener — it never traverses the network. If it
    leaks (e.g. screenshare), the user can revoke it from ``/portal/``.
    """
    if not _valid_callback_port(callback_port):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="callback_port must be in [1024, 65535].",
        )
    if not _valid_hostname(hostname):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="hostname must be a plausible host string.",
        )

    factory = get_session_factory()
    async with factory() as session:
        issued = await token_registry.issue_or_rotate_for_user(
            session, user_email=user.email
        )
        await session.commit()

    log.info(
        "token issued via cli callback",
        user_email=user.email,
        token_id=issued.token_id,
        was_rotation=issued.was_rotation,
        cli_hostname=hostname,
    )

    # 127.0.0.1 over ``localhost`` — avoids any chance of an IPv6 resolution
    # mismatch with the CLI listener which binds the IPv4 loopback.
    redirect = (
        f"http://127.0.0.1:{callback_port}/"
        f"?token={issued.full_token}"
    )
    return RedirectResponse(
        url=redirect,
        status_code=status.HTTP_303_SEE_OTHER,
        headers=_NO_STORE_HEADERS,
    )


# ---------------------------------------------------------------------------
# LLM Settings (/portal/settings)
# ---------------------------------------------------------------------------


@router.get("/settings", response_class=HTMLResponse)
async def portal_settings_get(request: Request, user: _UserDep) -> HTMLResponse:
    """Show the LLM provider/key settings form.

    Model selection is controlled by the admin; we show the currently configured
    admin model for each provider as read-only informational text.
    """
    factory = get_session_factory()
    async with factory() as session:
        stmt = select(UserLLMSettings).where(UserLLMSettings.user_email == user.email)
        settings_row = (await session.execute(stmt)).scalar_one_or_none()

    masked_key: str | None = None
    current_provider: str = "anthropic"
    if settings_row is not None:
        from security_scanner.tokens.crypto import decrypt, mask_for_display  # noqa: PLC0415
        try:
            plaintext = decrypt(settings_row.encrypted_api_key)
            masked_key = mask_for_display(plaintext)
        except Exception:  # noqa: BLE001
            masked_key = "…(decryption error)"
        current_provider = settings_row.provider.value

    # Admin-set model for informational display
    org_row = await _load_active_org_settings_for_portal()
    anthropic_model = org_row.anthropic_model if org_row else None
    google_model = org_row.google_model if org_row else None

    return templates.TemplateResponse(
        request,
        "portal_settings.html",
        {
            "user": user,
            "current_provider": current_provider,
            "masked_key": masked_key,
            "anthropic_model": anthropic_model or "(admin not yet configured)",
            "google_model": google_model or "(admin not yet configured)",
            "flash": None,
        },
        headers=_NO_STORE_HEADERS,
    )


@router.post("/settings", response_class=HTMLResponse)
async def portal_settings_post(
    request: Request,
    user: _UserDep,
    provider: Annotated[str, Form()],
    api_key: Annotated[str, Form()] = "",
) -> HTMLResponse:
    """Save or update the user's LLM provider and API key.

    Model is now admin-controlled and not accepted from the form.
    If ``api_key`` is blank the existing key is preserved (the form shows a
    masked hint so the user knows one is already saved).  The key is encrypted
    with Fernet before storage and never logged.
    """
    from security_scanner.tokens.crypto import encrypt, mask_for_display  # noqa: PLC0415

    provider = provider.strip().lower()
    api_key = api_key.strip()

    if provider not in ("anthropic", "google"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown provider {provider!r}",
        )

    # Load org model info for the response template
    org_row = await _load_active_org_settings_for_portal()
    anthropic_model = org_row.anthropic_model if org_row else None
    google_model = org_row.google_model if org_row else None

    factory = get_session_factory()
    async with factory() as session:
        # Ensure users row exists before any FK-constrained child insert.
        await token_registry.upsert_user(session, email=user.email)

        stmt = select(UserLLMSettings).where(UserLLMSettings.user_email == user.email)
        row = (await session.execute(stmt)).scalar_one_or_none()

        if api_key:
            encrypted = encrypt(api_key)
        elif row is not None:
            encrypted = row.encrypted_api_key  # preserve existing
        else:
            # No existing key, none supplied — ask the user to provide one.
            return templates.TemplateResponse(
                request,
                "portal_settings.html",
                {
                    "user": user,
                    "current_provider": provider,
                    "masked_key": None,
                    "anthropic_model": anthropic_model or "(admin not yet configured)",
                    "google_model": google_model or "(admin not yet configured)",
                    "flash": "error:Please enter your API key.",
                },
                headers=_NO_STORE_HEADERS,
            )

        provider_enum = LLMProvider.anthropic if provider == "anthropic" else LLMProvider.google

        from datetime import UTC, datetime  # noqa: PLC0415
        now = datetime.now(UTC)
        if row is None:
            from security_scanner.tokens.models import UserLLMSettings as _ULS  # noqa: PLC0415
            row = _ULS(
                user_email=user.email,
                provider=provider_enum,
                model=None,  # model is admin-controlled; not user-settable
                encrypted_api_key=encrypted,
                updated_at=now,
            )
            session.add(row)
        else:
            row.provider = provider_enum
            # Do NOT update row.model — it is admin-controlled
            row.encrypted_api_key = encrypted
            row.updated_at = now

        await token_audit.record(
            session,
            event_type=AuditEventType.user_llm_settings_updated,
            user_email=user.email,
            provider=provider,
        )
        await session.commit()

    masked_key = mask_for_display(api_key) if api_key else "…(unchanged)"
    log.info("portal llm settings saved", user_email=user.email, provider=provider)

    return templates.TemplateResponse(
        request,
        "portal_settings.html",
        {
            "user": user,
            "current_provider": provider,
            "masked_key": masked_key,
            "anthropic_model": anthropic_model or "(admin not yet configured)",
            "google_model": google_model or "(admin not yet configured)",
            "flash": "ok:Settings saved.",
        },
        headers=_NO_STORE_HEADERS,
    )


# ---------------------------------------------------------------------------
# Scan history (/portal/scans, /portal/scans/<scan_id>)
# ---------------------------------------------------------------------------


@router.get("/scans", response_class=HTMLResponse)
async def portal_scans(
    request: Request,
    user: _UserDep,
    page: Annotated[int, Query(ge=1)] = 1,
) -> HTMLResponse:
    """Paginated list of the caller's scan records."""
    factory = get_session_factory()
    offset = (page - 1) * _SCANS_PAGE_SIZE
    async with factory() as session:
        stmt = (
            select(ScanRecord)
            .where(ScanRecord.user_email == user.email)
            .order_by(desc(ScanRecord.started_at))
            .offset(offset)
            .limit(_SCANS_PAGE_SIZE + 1)  # fetch one extra to detect next page
        )
        rows = (await session.execute(stmt)).scalars().all()

    has_next = len(rows) > _SCANS_PAGE_SIZE
    scans = list(rows[:_SCANS_PAGE_SIZE])

    return templates.TemplateResponse(
        request,
        "portal_scans.html",
        {
            "user": user,
            "scans": scans,
            "page": page,
            "has_next": has_next,
        },
    )


@router.get("/scans/{scan_id}", response_class=HTMLResponse)
async def portal_scan_detail(
    request: Request,
    user: _UserDep,
    scan_id: str,
) -> HTMLResponse:
    """Render the saved HTML report for a single scan."""
    import uuid  # noqa: PLC0415
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Invalid scan ID."
        ) from exc

    factory = get_session_factory()
    async with factory() as session:
        from security_scanner.tokens.models import ScanUsage  # noqa: PLC0415
        stmt = select(ScanRecord).where(
            ScanRecord.scan_id == scan_uuid,
            ScanRecord.user_email == user.email,
        )
        scan = (await session.execute(stmt)).scalar_one_or_none()
        usage_row: ScanUsage | None = None
        if scan is not None:
            usage_stmt = select(ScanUsage).where(ScanUsage.scan_id == scan_uuid)
            usage_row = (await session.execute(usage_stmt)).scalar_one_or_none()

    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    response_ids: list[str] = []
    if usage_row and usage_row.response_ids:
        response_ids = [r.strip() for r in usage_row.response_ids.split(",") if r.strip()]

    # Anthropic console deep-link format (message inspector)
    console_base = (
        "https://console.anthropic.com/workbench"
        if scan.provider == "anthropic"
        else "https://console.cloud.google.com/vertex-ai/generative/multimodal"
    )

    return templates.TemplateResponse(
        request,
        "portal_scan_detail.html",
        {
            "user": user,
            "scan": scan,
            "usage": usage_row,
            "response_ids": response_ids,
            "console_base": console_base,
        },
    )


# ---------------------------------------------------------------------------
# Usage transparency (/portal/usage)
# ---------------------------------------------------------------------------

# Published list prices (USD) per 1M tokens — best-effort, for estimation only.
# Real cost = provider invoice; these numbers help users spot surprises.
_PRICE_PER_MTok: dict[tuple[str, str], tuple[float, float]] = {
    ("anthropic", "claude-sonnet-4-6"):  (3.00, 15.00),
    ("anthropic", "claude-opus-4-7"):    (15.00, 75.00),
    ("anthropic", "claude-haiku-4-5-20251001"): (0.80, 4.00),
    ("google",    "gemini-2.5-flash"):   (0.075, 0.30),
    ("google",    "gemini-2.5-pro"):     (1.25, 10.00),
}


def _est_cost_usd(row: LLMUsageMonthly) -> float:
    """Best-effort cost estimate in USD."""
    key = (row.provider, row.model or "")
    prices = _PRICE_PER_MTok.get(key)
    if prices is None:
        return 0.0
    in_price, out_price = prices
    return (
        row.input_tokens / 1_000_000 * in_price
        + row.output_tokens / 1_000_000 * out_price
    )


@router.get("/usage", response_class=HTMLResponse)
async def portal_usage(request: Request, user: _UserDep) -> HTMLResponse:
    """Monthly LLM usage breakdown for the caller's BYO key."""
    from datetime import UTC, datetime  # noqa: PLC0415

    now = datetime.now(UTC)
    this_month = now.strftime("%Y-%m")
    # Last month
    if now.month == 1:
        last_month = f"{now.year - 1}-12"
    else:
        last_month = f"{now.year}-{now.month - 1:02d}"

    factory = get_session_factory()
    async with factory() as session:
        stmt = (
            select(LLMUsageMonthly)
            .where(LLMUsageMonthly.user_email == user.email)
            .where(LLMUsageMonthly.year_month.in_([this_month, last_month]))
            .order_by(LLMUsageMonthly.year_month.desc())
        )
        rows = (await session.execute(stmt)).scalars().all()

    usage_with_cost = [
        {"row": r, "est_cost": _est_cost_usd(r)}
        for r in rows
    ]

    return templates.TemplateResponse(
        request,
        "portal_usage.html",
        {
            "user": user,
            "this_month": this_month,
            "last_month": last_month,
            "usage": usage_with_cost,
        },
    )


