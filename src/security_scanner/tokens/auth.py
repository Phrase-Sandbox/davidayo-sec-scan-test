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
from datetime import UTC, datetime, timezone
from urllib.parse import quote

from cryptography.fernet import Fernet, InvalidToken
from fastapi import HTTPException, Request, status
from sqlalchemy.exc import IntegrityError

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


def sign_portal_session(email: str, name: str, auth_provider: str = "local") -> str:
    """Return a Fernet-encrypted, TTL-bearing session cookie value."""
    now = int(time.time())
    payload = json.dumps({
        "e": email,
        "n": name,
        "x": now + _SESSION_TTL,
        "t": now,            # session_issued_at — used for reactivation reauth
        "a": auth_provider,  # "okta" or "local"
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
    return PhraseUser(
        email=email,
        name=str(name),
        groups=(),
        auth_provider=data.get("a", "local"),
        session_issued_at=data.get("t"),  # None for old cookies → reauth check skipped
    )

log = get_logger(__name__)

_LOCAL_BYPASS_EMAIL = "local-admin@phrase.dev"
_LOCAL_BYPASS_NAME = "Local Admin"


@dataclass(frozen=True)
class PhraseUser:
    """Resolved identity from ``X-Userinfo`` or portal session cookie."""

    email: str
    name: str
    groups: tuple[str, ...]
    auth_provider: str = "unknown"          # "okta", "local", or "unknown"
    session_issued_at: float | None = None  # unix timestamp when cookie was minted


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


def _raise_login_required(request: Request) -> None:
    """Raise a login-redirect (browsers) or 401 (API/CLI callers)."""
    if "text/html" in request.headers.get("accept", ""):
        raise _browser_login_redirect(request)
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Session expired. Please re-authenticate.",
    )


def _check_email_domain(email: str, settings) -> None:
    """Raise 403 if OKTA_EMAIL_DOMAIN is set and the email domain doesn't match.

    Applied to all auth paths when the setting is configured.
    Set OKTA_EMAIL_DOMAIN='' to disable (for local dev with test emails).
    """
    allowed = getattr(settings, "OKTA_EMAIL_DOMAIN", "").strip().lower()
    if not allowed:
        return
    domain = email.split("@")[-1].lower() if "@" in email else ""
    if domain != allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Login restricted to @{allowed} accounts.",
        )


async def _jit_provision_user(user: PhraseUser) -> None:
    """Create a User row on first gateway login (JIT provisioning).

    Called by :func:`_check_account_active` when no DB row exists for the
    authenticated user.  This is the primary onboarding path on Launchpad
    (gateway-managed Okta, no local login page) and a safe fallback for any
    auth path where the user has not yet been provisioned.

    Role assignment:
    1. ``PROTECTED_ADMIN_EMAILS`` → admin (super-admin bootstrap)
    2. ``ADMIN_GROUP_NAME`` in ``user.groups`` → admin (Okta group access)
    3. Otherwise → user

    Uses ``add`` + ``commit`` wrapped in ``IntegrityError`` catch to handle
    the rare concurrent double-provision without raising to the caller.
    """
    settings = get_settings()
    protected = frozenset(
        e.strip() for e in settings.PROTECTED_ADMIN_EMAILS.split(",") if e.strip()
    )
    admin_group = settings.ADMIN_GROUP_NAME
    is_protected = user.email in protected
    is_group_admin = bool(admin_group and admin_group in user.groups)
    role = UserRole.admin if (is_protected or is_group_admin) else UserRole.user
    # "unknown" is the PhraseUser default — set by _user_from_claims (X-Userinfo
    # path).  Cookie-auth users already have a concrete provider ("local"/"okta").
    auth_provider = "okta" if user.auth_provider == "unknown" else user.auth_provider
    now = datetime.now(UTC)
    new_user = User(
        email=user.email,
        auth_provider=auth_provider,
        role=role,
        is_active=True,
        created_at=now,
        last_login_at=now,
        display_name=user.name,
    )
    factory = get_session_factory()
    async with factory() as sess:
        try:
            sess.add(new_user)
            await sess.commit()
            log.info(
                "jit user provisioned on gateway login",
                user_email=user.email,
                role=role.value,
                auth_provider=auth_provider,
                is_protected_admin=is_protected,
                is_group_admin=is_group_admin,
            )
        except IntegrityError:
            # Race: a concurrent request provisioned the same user first.
            # Roll back and carry on — the row exists, which is all we need.
            await sess.rollback()
            log.debug(
                "jit provision skipped — already provisioned by concurrent request",
                user_email=user.email,
            )


async def _check_account_active(user: PhraseUser, request: Request) -> None:
    """JIT-provision new users, then enforce active/deactivated status.

    On first gateway login (no DB row found): calls :func:`_jit_provision_user`
    to create a User row so admins can reach ``/admin/`` immediately without
    having to issue a scanner token first.  Role is set by
    ``PROTECTED_ADMIN_EMAILS`` and ``ADMIN_GROUP_NAME``.

    For existing users: raises if ``is_active`` is ``False`` or if the
    session predates a reactivation event (forced reauth after admin reactivate).

    Never raises for the ``ADMIN_LOCAL_BYPASS`` synthetic user.
    """
    factory = get_session_factory()
    async with factory() as _sess:
        _db_user = await _sess.get(User, user.email)
    if _db_user is None:
        await _jit_provision_user(user)
        return
    if not _db_user.is_active:
        log.info("portal access denied — account deactivated", user_email=user.email)
        _raise_login_required(request)
    # Forced reauth: if the user was reactivated after this session was issued,
    # the old session is no longer valid — the user must log in again.
    # SQLite returns naive datetimes even for timezone=True columns; treat them
    # as UTC so the timestamp() comparison is correct in all environments.
    _reactivated_at = _db_user.last_reactivation_at
    if _reactivated_at is not None and _reactivated_at.tzinfo is None:
        _reactivated_at = _reactivated_at.replace(tzinfo=UTC)
    if (
        _reactivated_at is not None
        and user.session_issued_at is not None
        and user.session_issued_at < _reactivated_at.timestamp()
    ):
        log.info(
            "portal session expired — reactivation requires fresh login",
            user_email=user.email,
        )
        _raise_login_required(request)


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
    New users (no DB row) are JIT-provisioned on first login: protected admin
    emails and ``ADMIN_GROUP_NAME`` Okta group members get role=admin; everyone
    else gets role=user.
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
    _check_email_domain(user.email, get_settings())
    await _check_account_active(user, request)
    return user


async def require_admin(request: Request) -> PhraseUser:
    """Same as :func:`require_phrase_user` plus a DB role check.

    Priority:
    1. ``ADMIN_LOCAL_BYPASS`` — bypass user is always admin (local dev only).
    2. ``User.role == UserRole.admin`` in the DB — source of truth in production.

    Initial role is set at JIT provisioning time (first login):
    ``PROTECTED_ADMIN_EMAILS`` and ``ADMIN_GROUP_NAME`` Okta group members
    get admin.  After provisioning, roles can be changed via the
    ``/admin/users`` promote/demote UI.
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
