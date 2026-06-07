"""Skill OAuth flow — session-scoped, in-memory (spec §7.1, §2.2 skill steps 1–2, §3.3).

GitHub App OAuth web-flow for the on-demand skill path. Per §3.3 OAuth
tokens are **never** persisted to disk or database. They live in an
in-memory ``SessionStore`` keyed by an HttpOnly cookie, expire on TTL, and
vanish when the process restarts — exactly what the spec requires for a
stateless service.

Two endpoints:

- ``GET /skill/oauth/init`` — generates a CSRF state token, sets the session
  cookie, and redirects the browser to GitHub's authorize endpoint.
- ``GET /skill/oauth/callback`` — receives ``code`` + ``state`` from GitHub,
  validates the state against the session (CSRF guard, constant-time
  comparison), exchanges the code for an access token via GitHub's token
  endpoint, stores the access token in the session, and redirects to
  ``/skill/ready``.

Session expiry is enforced lazily on every access — there is no background
sweeper. Sessions cannot be reused once an access token is attached
(prevents replay of the callback URL).
"""

from __future__ import annotations

import secrets
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Annotated
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse

from security_scanner.shared.config import Settings, get_settings
from security_scanner.shared.logging_util import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/skill/oauth", tags=["skill-oauth"])

_GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
_GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"  # noqa: S105 — endpoint URL

SESSION_TTL_SECONDS = 3600.0
SESSION_COOKIE_NAME = "session_token"  # noqa: S105 — cookie name, not a credential


@dataclass
class _Session:
    state: str
    created_at: float
    access_token: str | None = None


class SessionStore:
    """In-memory OAuth session store with TTL eviction. NOT persisted (§3.3)."""

    def __init__(self, ttl_seconds: float = SESSION_TTL_SECONDS) -> None:
        self._sessions: dict[str, _Session] = {}
        self._ttl = ttl_seconds

    def create_pending(self) -> tuple[str, str]:
        """Mint a new pending session. Returns ``(session_token, state)``."""
        session_token = secrets.token_urlsafe(32)
        state = secrets.token_urlsafe(32)
        self._sessions[session_token] = _Session(
            state=state, created_at=time.monotonic()
        )
        return session_token, state

    def complete(
        self, session_token: str, state: str, access_token: str
    ) -> bool:
        """Attach an access token to a session after validating state. CSRF guard."""
        session = self._sessions.get(session_token)
        if session is None:
            return False
        # Replay defence — a completed session cannot be re-completed.
        if session.access_token is not None:
            return False
        if self._is_expired(session):
            del self._sessions[session_token]
            return False
        if not secrets.compare_digest(session.state, state):
            return False
        session.access_token = access_token
        return True

    def get_access_token(self, session_token: str) -> str | None:
        """Return the access token for *session_token*, or ``None`` if absent/expired."""
        session = self._sessions.get(session_token)
        if session is None or session.access_token is None:
            return None
        if self._is_expired(session):
            del self._sessions[session_token]
            return None
        return session.access_token

    def _is_expired(self, session: _Session) -> bool:
        return (time.monotonic() - session.created_at) > self._ttl


_default_store = SessionStore()


def get_session_store() -> SessionStore:
    """Module-singleton store. Tests override via ``app.dependency_overrides``."""
    return _default_store


# Token-exchange function signature. Lifted into a dependency so tests can
# inject a fake exchanger without patching httpx internals.
TokenExchanger = Callable[[str, Settings], Awaitable[str]]


async def _exchange_oauth_code(code: str, settings: Settings) -> str:
    """Exchange a GitHub OAuth ``code`` for a user access token.

    Raises ``HTTPException(400)`` on any failure: GitHub HTTP error, missing
    token in the response body, or an ``error`` field returned by GitHub.
    Never raises a 500 — OAuth failures are user-actionable.
    """
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(
            _GITHUB_TOKEN_URL,
            data={
                "client_id": settings.GITHUB_OAUTH_CLIENT_ID,
                "client_secret": settings.GITHUB_OAUTH_CLIENT_SECRET,
                "code": code,
            },
            headers={"Accept": "application/json"},
        )
    if response.status_code >= 400:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"GitHub OAuth token exchange failed (HTTP {response.status_code})."
            ),
        )
    data = response.json()
    if "error" in data or not data.get("access_token"):
        error_desc = data.get("error_description", "no token returned")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"GitHub OAuth token exchange failed: {error_desc}",
        )
    return data["access_token"]


def get_token_exchanger() -> TokenExchanger:
    """Dependency provider so tests can swap in a fake exchanger."""
    return _exchange_oauth_code


_SettingsDep = Annotated[Settings, Depends(get_settings)]
_StoreDep = Annotated[SessionStore, Depends(get_session_store)]
_ExchangerDep = Annotated[TokenExchanger, Depends(get_token_exchanger)]


@router.get("/init")
async def oauth_init(
    request: Request,
    store: _StoreDep,
    settings: _SettingsDep,
) -> RedirectResponse:
    """Start the OAuth flow: mint session, set cookie, redirect to GitHub."""
    session_token, state = store.create_pending()
    log.info("oauth init", session_token_prefix=session_token[:8])

    query = urlencode(
        {
            "client_id": settings.GITHUB_OAUTH_CLIENT_ID,
            "scope": "repo:read",
            "state": state,
        }
    )
    redirect = RedirectResponse(
        url=f"{_GITHUB_AUTHORIZE_URL}?{query}",
        status_code=status.HTTP_302_FOUND,
    )
    redirect.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_token,
        httponly=True,
        samesite="lax",
        max_age=int(SESSION_TTL_SECONDS),
        secure=request.url.scheme == "https",
    )
    return redirect


@router.get("/callback")
async def oauth_callback(
    code: str,
    state: str,
    store: _StoreDep,
    settings: _SettingsDep,
    exchanger: _ExchangerDep,
    session_token: Annotated[str | None, Cookie()] = None,
) -> RedirectResponse:
    """GitHub returns here after the user authorises. Validate state, exchange, store."""
    if session_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                "Missing session cookie — start the OAuth flow at "
                "/skill/oauth/init."
            ),
        )

    access_token = await exchanger(code, settings)
    if not store.complete(session_token, state, access_token):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Invalid OAuth state — possible CSRF attempt, expired "
                "session, or replayed callback."
            ),
        )

    log.info("oauth callback complete", session_token_prefix=session_token[:8])
    return RedirectResponse(url="/skill/ready", status_code=status.HTTP_302_FOUND)
