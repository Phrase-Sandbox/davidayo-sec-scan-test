"""OAuth session verifier for the skill path (spec §7.1, EC-005).

Looks up the session cookie minted by ``/skill/oauth/init`` in the
in-memory session store and returns the GitHub access token attached at
``/skill/oauth/callback``. Any failure mode produces the canonical EC-005
message — the skill UI renders it verbatim, prompting the developer to
re-authorise.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Request, status

from security_scanner.skill.oauth import (
    SESSION_COOKIE_NAME,
    SessionStore,
    get_session_store,
)

_EC_005_MESSAGE = (
    "GitHub authorisation failed. Please re-authorise and try again."
)


def verify_oauth_token(
    request: Request,
    store: Annotated[SessionStore, Depends(get_session_store)],
) -> str:
    """Return the GitHub access token for this session, or raise 401 (EC-005)."""
    session_token = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_EC_005_MESSAGE,
        )

    access_token = store.get_access_token(session_token)
    if access_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_EC_005_MESSAGE,
        )

    return access_token
