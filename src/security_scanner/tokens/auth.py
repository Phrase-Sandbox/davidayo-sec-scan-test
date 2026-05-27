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
from dataclasses import dataclass
from urllib.parse import quote

from fastapi import HTTPException, Request, status

from security_scanner.shared.config import get_settings
from security_scanner.shared.logging_util import get_logger

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


async def require_phrase_user(request: Request) -> PhraseUser:
    """Resolve the calling Phrase user from ``X-Userinfo``.

    Priority:
    1. ``ADMIN_LOCAL_BYPASS`` — injects a fake admin (local dev only).
    2. ``X-Userinfo`` header — injected by the Okta ingress gateway (production).
    3. Missing header + browser request → 302 redirect to ``/portal/login``.
    4. Missing header + API request → 401 JSON (CLI / CI callers).
    """
    settings = get_settings()
    if settings.ADMIN_LOCAL_BYPASS:
        return _bypass_user()

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
    return user


async def require_admin(request: Request) -> PhraseUser:
    """Same as :func:`require_phrase_user` plus a group membership check."""
    user = await require_phrase_user(request)
    admin_group = get_settings().ADMIN_GROUP_NAME
    if admin_group not in user.groups:
        # Log at info — not error — because this is a legitimate 403 from a
        # non-admin user, not a system fault.
        log.info(
            "admin route forbidden",
            user_email=user.email,
            required_group=admin_group,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin group membership required.",
        )
    return user
