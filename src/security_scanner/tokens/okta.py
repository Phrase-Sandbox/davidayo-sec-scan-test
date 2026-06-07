"""Direct Okta OIDC SSO routes — an *additional* auth path alongside the
X-Userinfo gateway.

When ``OKTA_DOMAIN``, ``OKTA_CLIENT_ID``, and ``OKTA_CLIENT_SECRET`` are set,
the portal login page shows an "Sign in with Okta SSO" button that drives the
Authorization Code Flow directly (no ingress gateway required).

The existing X-Userinfo gateway path (trusted ``X-Userinfo`` header from the
Phrase Platform ingress) is preserved unchanged — both paths coexist.

Security notes:
- CSRF: state + nonce are Fernet-encrypted in a short-lived (15-min)
  ``okta_oauth_state`` cookie. On callback, state is compared with
  ``secrets.compare_digest``; nonce is compared with the JWT claim.
- JWT: validated with ``PyJWKClient`` (pyjwt[crypto] ≥ 2.8) — signature,
  issuer, audience, expiry, and nonce are all verified.
- Domain: ``_check_email_domain`` rejects non-``OKTA_EMAIL_DOMAIN`` emails.
- JIT provisioning: new Okta users are lazily created with ``role=user``
  (or ``role=admin`` if their email is in ``PROTECTED_ADMIN_EMAILS``).
- Lookup by ``okta_user_id`` (sub claim) before falling back to email,
  so Okta account data stays consistent even after email changes in Okta.
"""

from __future__ import annotations

import json
import secrets
import time
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from jwt import PyJWKClient
from jwt import decode as jwt_decode
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from security_scanner.shared.config import get_settings, okta_is_configured
from security_scanner.shared.logging_util import get_logger
from security_scanner.tokens.auth import (
    _SESSION_COOKIE,
    _SESSION_TTL,
    _check_email_domain,
    _get_fernet,
    sign_portal_session,
)
from security_scanner.tokens.db import get_session_factory
from security_scanner.tokens.models import User, UserRole

log = get_logger(__name__)

router = APIRouter(prefix="/portal", tags=["portal-okta"])

_TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

# ---------------------------------------------------------------------------
# State cookie — stateless CSRF protection for the OAuth round-trip
# ---------------------------------------------------------------------------
_OKTA_STATE_COOKIE = "okta_oauth_state"  # noqa: S105 — cookie name, not a credential
_OKTA_STATE_TTL = 900  # 15 minutes


def _pack_state(state: str, nonce: str) -> str:
    """Fernet-encrypt a (state, nonce, created_at) bundle into a cookie value."""
    payload = json.dumps({"s": state, "n": nonce, "t": int(time.time())}).encode()
    return _get_fernet().encrypt(payload).decode()


def _unpack_state(cookie: str) -> tuple[str, str]:
    """Decrypt and validate the state cookie. Returns ``(state, nonce)``.

    Raises ``ValueError`` if the cookie is invalid, tampered, or expired.
    """
    try:
        raw = _get_fernet().decrypt(cookie.encode())
        data = json.loads(raw)
    except Exception as exc:
        raise ValueError("invalid state cookie") from exc
    if int(time.time()) - data.get("t", 0) > _OKTA_STATE_TTL:
        raise ValueError("state cookie expired")
    return data["s"], data["n"]


# ---------------------------------------------------------------------------
# JWKS client — one instance per Okta domain, cached in-process
# ---------------------------------------------------------------------------

@lru_cache(maxsize=4)
def _jwks_client(okta_domain: str) -> PyJWKClient:
    """Return a cached JWKS client for the given Okta domain.

    ``PyJWKClient`` fetches and caches the public keys from Okta's JWKS
    endpoint automatically; it refreshes when a key ID is not found.
    """
    return PyJWKClient(f"https://{okta_domain}/oauth2/default/v1/keys")


# ---------------------------------------------------------------------------
# JWT validation
# ---------------------------------------------------------------------------

def _validate_id_token(id_token: str, nonce: str, settings) -> dict:
    """Validate the Okta ID token and return the verified claims.

    Verifies: RS256 signature (via JWKS), issuer, audience, expiry,
    and nonce. Raises on any failure — caller treats all exceptions as
    'please try again'.
    """
    client = _jwks_client(settings.OKTA_DOMAIN)
    signing_key = client.get_signing_key_from_jwt(id_token)
    claims = jwt_decode(
        id_token,
        signing_key.key,
        algorithms=["RS256"],
        audience=settings.OKTA_CLIENT_ID,
        issuer=f"https://{settings.OKTA_DOMAIN}/oauth2/default",
    )
    # Nonce must be validated manually — it is an OIDC concept, not core JWT.
    # Use constant-time comparison to prevent timing attacks.
    if not secrets.compare_digest(claims.get("nonce", ""), nonce):
        raise ValueError("nonce mismatch — possible replay or CSRF attack")
    if not claims.get("email_verified", False):
        raise ValueError("Okta email_verified is false — cannot trust this email address")
    return claims


# ---------------------------------------------------------------------------
# Okta token exchange
# ---------------------------------------------------------------------------

async def _exchange_code(code: str, settings) -> str:
    """Exchange an authorization code for an ID token.

    Sends ``client_secret`` server-side (never exposed to the browser).
    Raises ``HTTPException(400)`` on any Okta error.
    """
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.post(
            f"https://{settings.OKTA_DOMAIN}/oauth2/default/v1/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": settings.OKTA_REDIRECT_URI,
                "client_id": settings.OKTA_CLIENT_ID,
                "client_secret": settings.OKTA_CLIENT_SECRET,
            },
            headers={"Accept": "application/json"},
        )
    if r.status_code >= 400:
        log.warning(
            "okta token exchange failed",
            http_status=r.status_code,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Okta token exchange failed.",
        )
    data = r.json()
    if "id_token" not in data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Okta token response missing id_token.",
        )
    return data["id_token"]


# ---------------------------------------------------------------------------
# JIT user provisioning
# ---------------------------------------------------------------------------

async def _provision_okta_user(claims: dict, sess: AsyncSession, settings) -> User:
    """Lazily create or update a portal User from Okta JWT claims.

    Lookup priority:
    1. ``okta_user_id`` (sub claim) — stable across email changes.
    2. ``email`` — fallback for first-time Okta logins.

    Raises:
    - ``HTTPException(403)`` if email domain doesn't match ``OKTA_EMAIL_DOMAIN``.
    - ``HTTPException(409)`` if a local account exists with the same email.
    """
    email: str = claims["email"]
    sub: str = claims["sub"]
    name: str = claims.get("name") or email.split("@")[0]
    now = datetime.now(UTC)

    # Domain restriction — enforced for all Okta users.
    _check_email_domain(email, settings)

    # Look up by okta_user_id first (handles email changes gracefully).
    stmt = select(User).where(User.okta_user_id == sub)
    user: User | None = (await sess.execute(stmt)).scalar_one_or_none()

    if user is None:
        # Try by email (may be a legacy local user or first Okta login).
        user = await sess.get(User, email)
        if user is not None and getattr(user, "auth_provider", "local") == "local":
            # A local account already exists with this email.
            # Policy (spec Option A): reject and require admin to migrate.
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "A local account with this email already exists. "
                    "Ask your administrator to migrate it to Okta authentication."
                ),
            )

    protected = frozenset(
        e.strip() for e in settings.PROTECTED_ADMIN_EMAILS.split(",") if e.strip()
    )

    if user is None:
        # New user — lazy provisioning.
        user = User(
            email=email,
            okta_user_id=sub,
            auth_provider="okta",
            role=UserRole.admin if email in protected else UserRole.user,
            is_active=True,
            created_at=now,
            last_login_at=now,
            display_name=name,
        )
        sess.add(user)
        log.info("okta user provisioned", user_email=email)
    else:
        # Existing Okta user — update mutable fields.
        user.okta_user_id = sub
        user.auth_provider = "okta"
        user.display_name = name
        user.last_login_at = now
        # Note: email PK is NOT updated even if Okta email changed (requires
        # surrogate-PK migration — deferred). The user record is still found by
        # okta_user_id, so no duplicate is created.

    await sess.commit()
    return user


# ---------------------------------------------------------------------------
# Error response helper
# ---------------------------------------------------------------------------

def _okta_error(request: Request, message: str) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "portal_okta_error.html",
        {"error": message},
        status_code=status.HTTP_400_BAD_REQUEST,
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/oauth/init", include_in_schema=False)
async def okta_oauth_init(request: Request) -> RedirectResponse:
    """Start the Okta OIDC flow.

    Generates a random state + nonce, stores them in a Fernet-encrypted
    short-lived cookie, then redirects the browser to Okta's authorize endpoint.
    """
    settings = get_settings()
    if not okta_is_configured(settings):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Okta SSO is not configured on this server.",
        )

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)

    params = urlencode({
        "response_type": "code",
        "client_id": settings.OKTA_CLIENT_ID,
        "redirect_uri": settings.OKTA_REDIRECT_URI,
        "scope": settings.OKTA_SCOPES,
        "state": state,
        "nonce": nonce,
    })
    auth_url = f"https://{settings.OKTA_DOMAIN}/oauth2/default/v1/authorize?{params}"

    redirect = RedirectResponse(url=auth_url, status_code=status.HTTP_302_FOUND)
    redirect.set_cookie(
        key=_OKTA_STATE_COOKIE,
        value=_pack_state(state, nonce),
        httponly=True,
        samesite="lax",
        max_age=_OKTA_STATE_TTL,
        secure=request.url.scheme == "https",
    )
    log.info("okta oauth init", state_prefix=state[:8])
    return redirect


@router.get("/oauth/callback", include_in_schema=False)
async def okta_oauth_callback(
    request: Request,
    code: str,
    state: str,
) -> Response:
    """Handle the Okta authorization callback.

    1. Validates CSRF state against the encrypted cookie.
    2. Exchanges the authorization code for an ID token.
    3. Validates the ID token (signature, claims, nonce).
    4. Lazily provisions the user in the DB.
    5. Issues a portal_session cookie and redirects to /portal/.
    """
    settings = get_settings()
    if not okta_is_configured(settings):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Okta SSO is not configured on this server.",
        )

    # --- CSRF state validation ---
    raw_state_cookie = request.cookies.get(_OKTA_STATE_COOKIE)
    if not raw_state_cookie:
        log.warning("okta callback: missing state cookie")
        return _okta_error(request, "Missing OAuth state. Please try again.")
    try:
        expected_state, nonce = _unpack_state(raw_state_cookie)
    except ValueError as exc:
        log.warning("okta callback: invalid state cookie", error=str(exc))
        return _okta_error(request, "Invalid or expired OAuth state. Please try again.")
    if not secrets.compare_digest(state, expected_state):
        log.warning("okta callback: state mismatch — possible CSRF")
        return _okta_error(request, "OAuth state mismatch. Please try again.")

    # --- Token exchange + JWT validation ---
    try:
        id_token = await _exchange_code(code, settings)
        claims = _validate_id_token(id_token, nonce, settings)
    except HTTPException:
        raise
    except Exception as exc:
        log.warning("okta token validation failed", error=str(exc))
        return _okta_error(request, "Token validation failed. Please try again.")

    # --- JIT provisioning ---
    factory = get_session_factory()
    async with factory() as sess:
        db_user = await _provision_okta_user(claims, sess, settings)

    log.info("okta login successful", user_email=db_user.email)

    # --- Issue portal session cookie ---
    cookie_val = sign_portal_session(
        email=db_user.email,
        name=db_user.display_name or db_user.email,
        auth_provider="okta",
    )
    resp = RedirectResponse(url="/portal/", status_code=status.HTTP_302_FOUND)
    resp.set_cookie(
        key=_SESSION_COOKIE,
        value=cookie_val,
        httponly=True,
        samesite="lax",
        max_age=_SESSION_TTL,
        secure=request.url.scheme == "https",
    )
    resp.delete_cookie(_OKTA_STATE_COOKIE)
    return resp
