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

from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select

from security_scanner.shared.logging_util import get_logger
from security_scanner.tokens import registry as token_registry
from security_scanner.tokens.auth import PhraseUser, require_admin
from security_scanner.tokens.db import get_session_factory
from security_scanner.tokens.models import AuditEvent, AuditEventType

log = get_logger(__name__)

router = APIRouter(prefix="/admin", tags=["admin"])

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
