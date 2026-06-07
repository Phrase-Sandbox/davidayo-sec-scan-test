"""``X-Userinfo`` decoder + FastAPI dependencies for the portal & admin UIs.

Per CLAUDE.md §Authentication, the Phrase Platform ingress gateway terminates
Okta and injects a trusted ``X-Userinfo`` header — base64-encoded JSON with
claims ``sub``, ``email``, ``name``, ``given_name``, ``family_name``,
``groups``. The header is added *after* the gateway has validated the OIDC
session, so we trust it implicitly inside the cluster.

Two deps:

- :func:`require_phrase_user` — any authenticated Phrase user. Used by
  ``/portal/*``.
- :func:`require_admin` — must additionally be in ``ADMIN_GROUP_NAME``.
  Used by ``/admin/*``.

Local-dev bypass: when ``ADMIN_LOCAL_BYPASS=true`` (guarded by a startup
check in :mod:`security_scanner.main` so it can't enable against a non-local
DB), both deps return a fake admin user so the portal and admin panel are
usable on ``http://localhost:8000`` without an Okta proxy in front.
"""

from __future__ import annotations

import base64
import binascii
import json
import time
from dataclasses import dataclass
from urllib.parse import quote

from cryptography.fernet import Fernet, InvalidToken
from fastapi import HTTPException, Request, status

from security_scanner.shared.config import get_settings
from security_scanner.shared.logging_util import get_logger
from security_scanner.tokens.db import get_session_factory
from security_scanner.tokens.models import User, UserRole

# ---------------------------------------------------------------------------
# Portal session cookie (local-auth path, complements Okta X-Userinfo).
# ---------------------------------------------------------------------------
_SESSION_COOKIE = "portal_session"
_SESSION_TTL = 8 * 3600  # 8 hours


def _get_fernet() -> Fernet:
    """Return a Fernet cipher using SCANNER_ENCRYPTION_KEY."""
    key = get_settings().SCANNER_ENCRYPTION_KEY
    if not key:
        raise RuntimeError("SCANNER_ENCRYPTION_KEY is required for portal session cookies")
    return Fernet(key.encode() if isinstance(key, str) else key)


def sign_portal_session(email: str, name: str) -> str:
    """Return a Fernet-encrypted, TTL-bearing session cookie value."""
    payload = json.dumps({
        "e": email,
        "n": name,
        "x": int(time.time()) + _SESSION_TTL,
    }).encode()
    return _get_fernet().encrypt(payload).decode()


def verify_portal_session(token: str) -> PhraseUser | None:
    """Decrypt and validate a ``portal_session`` cookie.

    Returns ``None`` when the token is missing, tampered, malformed, or expired.
    Never raises — callers treat ``None`` as "no session".
    """
    try:
        raw = _get_fernet().decrypt(token.encode())
        data = json.loads(raw)
    except RuntimeError:
        # SCANNER_ENCRYPTION_KEY not configured — fall through to next auth method.
        return None
    except (InvalidToken, json.JSONDecodeError, Exception):  # noqa: BLE001
        return None
    if data.get("x", 0) < int(time.time()):
        return None  # expired
    email = data.get("e")
    name = data.get("n") or email
    if not isinstance(email, str) or not email:
        return None
    return PhraseUser(email=email, name=str(name), groups=())

log = get_logger(__name__)

_LOCAL_BYPASS_EMAIL = "local-admin@phrase.dev"
_LOCAL_BYPASS_NAME = "Local Admin"


@dataclass(frozen=True)
class PhraseUser:
    """Resolved identity from ``X-Userinfo``."""

    email: str
    name: str
    groups: tuple[str, ...]


def _decode_userinfo(raw: str) -> dict | None:
    """Decode the base64-JSON ``X-Userinfo`` payload, or return ``None`` on garbage.

    The gateway pads correctly, but be defensive: accept missing padding
    rather than 401-ing on a recoverable mistake from a proxy in between.
    """
    s = raw.strip()
    # Tolerate missing base64 padding.
    if len(s) % 4:
        s += "=" * (4 - len(s) % 4)
    try:
        payload = base64.b64decode(s)
    except (binascii.Error, ValueError):
        return None
    try:
        claims = json.loads(payload)
    except json.JSONDecodeError:
        return None
    if not isinstance(claims, dict):
        return None
    return claims


def _user_from_claims(claims: dict) -> PhraseUser | None:
    email = claims.get("email")
    name = claims.get("name") or email
    groups = claims.get("groups") or []
    if not isinstance(email, str) or not email:
        return None
    if not isinstance(groups, list):
        groups = []
    return PhraseUser(
        email=email,
        name=str(name),
        groups=tuple(g for g in groups if isinstance(g, str)),
    )


def _bypass_user() -> PhraseUser:
    return PhraseUser(
        email=_LOCAL_BYPASS_EMAIL,
        name=_LOCAL_BYPASS_NAME,
        groups=(get_settings().ADMIN_GROUP_NAME,),
    )


def _browser_login_redirect(request: Request) -> HTTPException:
    """Return a 302 HTTPException that sends browsers to the login page.

    Preserves the original path as ``?next=`` so the ingress (or the login
    page) can redirect back after successful Okta authentication.
    FastAPI's default HTTPException handler forwards the ``Location`` header,
    so browsers follow the redirect even though the body is JSON.
    """
    next_path = quote(str(request.url.path), safe="")
    return HTTPException(
        status_code=status.HTTP_302_FOUND,
        headers={"Location": f"/portal/login?next={next_path}"},
    )


async def _check_account_active(user: PhraseUser, request: Request) -> None:
    """Raise if the user exists in the DB but has been deactivated.

    Skips the check for users not yet in the DB (Okta new-user / lazy
    provisioning flow — the DB row is created on first token issue).
    Never raises for the ``ADMIN_LOCAL_BYPASS`` synthetic user.
    """
    factory = get_session_factory()
    async with factory() as _sess:
        _db_user = await _sess.get(User, user.email)
    if _db_user is not None and not _db_user.is_active:
        log.info("portal access denied — account deactivated", user_email=user.email)
        if "text/html" in request.headers.get("accept", ""):
            raise _browser_login_redirect(request)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account deactivated. Contact your administrator.",
        )


async def require_phrase_user(request: Request) -> PhraseUser:
    """Resolve the calling Phrase user from ``X-Userinfo``.

    Priority:
    1. ``ADMIN_LOCAL_BYPASS`` — injects a fake admin (local dev only).
    2. ``portal_session`` cookie — Fernet-signed, issued by ``POST /portal/login``
       when ``LOCAL_PORTAL_PASSWORD`` is set.  Works without Okta for local dev.
    3. ``X-Userinfo`` header — injected by the Okta ingress gateway (production).
    4. Missing header + browser request → 302 redirect to ``/portal/login``.
    5. Missing header + API request → 401 JSON (CLI / CI callers).

    After identity is confirmed, verifies the user is not deactivated in the DB.
    New users not yet provisioned (Okta path, lazy flow) are always allowed through.
    """
    settings = get_settings()
    if settings.ADMIN_LOCAL_BYPASS:
        return _bypass_user()

    # Portal session cookie (local password auth path).
    cookie_val = request.cookies.get(_SESSION_COOKIE)
    if cookie_val:
        session_user = verify_portal_session(cookie_val)
        if session_user is not None:
            await _check_account_active(session_user, request)
            return session_user

    raw = request.headers.get("X-Userinfo") or request.headers.get("x-userinfo")
    if not raw:
        # Redirect browsers to the login page; return 401 to API/CLI clients.
        if "text/html" in request.headers.get("accept", ""):
            raise _browser_login_redirect(request)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-Userinfo header.",
        )

    claims = _decode_userinfo(raw)
    if claims is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed X-Userinfo header.",
        )

    user = _user_from_claims(claims)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="X-Userinfo missing required claims.",
        )
    await _check_account_active(user, request)
    return user


async def require_admin(request: Request) -> PhraseUser:
    """Same as :func:`require_phrase_user` plus a DB role check.

    Priority:
    1. ``ADMIN_LOCAL_BYPASS`` — bypass user is always admin (local dev only).
    2. ``User.role == UserRole.admin`` in the DB — source of truth in production.

    Okta groups are NOT used for admin determination. Roles are assigned
    in-app via the ``/admin/users`` promote/demote UI.
    """
    settings = get_settings()
    user = await require_phrase_user(request)

    # Bypass user is always admin — no DB hit needed.
    if settings.ADMIN_LOCAL_BYPASS:
        return user

    # DB role check — single SELECT by primary key.
    factory = get_session_factory()
    async with factory() as session:
        row = await session.get(User, user.email)

    if row is None or row.role != UserRole.admin:
        # Log at info — this is a legitimate 403, not a system fault.
        log.info(
            "admin route forbidden",
            user_email=user.email,
            reason="role not admin in DB",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required.",
        )
    return user
