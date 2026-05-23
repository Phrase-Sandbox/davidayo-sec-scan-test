"""``/portal/*`` — user self-service for per-developer ``/scan/local`` tokens.

Three flows live here:

1. **Browser self-service** (``GET /portal/``, ``POST /portal/tokens``,
   ``POST /portal/tokens/revoke``) — the developer sees their current token
   status, issues or rotates, or revokes. The full token plaintext is shown
   on ``portal_token_shown.html`` **exactly once**; it's never persisted on
   the server outside the SHA-256 hash and never echoed back on subsequent
   page loads.

2. **CLI browser-callback login** (``GET /portal/cli/login``,
   ``POST /portal/cli/login/complete``) — the ``phrase-sec-scan`` CLI binds
   a localhost listener and points the user's browser at the consent page.
   On approval, the server issues / rotates a token and 302-redirects to
   ``http://localhost:<port>/?token=...`` so the CLI listener picks it up
   and writes it to ``~/.phrase-sec-scan/config.yaml``. The redirect target
   is hard-coded to loopback; we never accept an arbitrary URL.

Trust model: every request here MUST come through the Phrase Platform
ingress, which terminates Okta and injects ``X-Userinfo``. The
:func:`require_phrase_user` dep gates every route. For local dev we set
``ADMIN_LOCAL_BYPASS=true`` and the dep returns a fake user — guarded by
the startup check in :mod:`security_scanner.main` so this can't enable
against a non-local DB.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from security_scanner.shared.logging_util import get_logger
from security_scanner.tokens import registry as token_registry
from security_scanner.tokens.auth import PhraseUser, require_phrase_user
from security_scanner.tokens.db import get_session_factory

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


def _valid_callback_port(port: int) -> bool:
    """Ports < 1024 require root on macOS/Linux — never a legitimate CLI listener."""
    return 1024 <= port <= 65535


def _valid_hostname(hostname: str) -> bool:
    """Hostname is display-only on the consent screen — sanity-check it's not absurd."""
    if not hostname or len(hostname) > 253:
        return False
    # Allow letters, digits, dot, dash, underscore. Anything richer is likely an injection.
    return all(c.isalnum() or c in "-._" for c in hostname)


# --- Browser self-service ----------------------------------------------------


@router.get("/", response_class=HTMLResponse)
async def portal_index(request: Request, user: _UserDep) -> HTMLResponse:
    """Show the caller's current token status."""
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


