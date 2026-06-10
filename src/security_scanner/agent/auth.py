"""Auth for the deployment-gate endpoint (§7.1, §7.3, EC-006).

Two paths, tried in order:

1. **GitHub OIDC** (when ``GITHUB_OIDC_ENABLED=true`` and the bearer looks
   like a JWT) — validates a workflow-issued OIDC token from the
   master-scanner-pipeline. See ``security_scanner.agent.oidc``.
2. **Static ``PHRASE_SCAN_TOKEN``** bearer (constant-time ``hmac.compare_digest``).

Either path success returns the token string; any failure surfaces the
canonical EC-006 message — the CI/CD step renders it verbatim.
"""

from __future__ import annotations

import hmac
import logging

from fastapi import HTTPException, Request, status

from security_scanner.agent.oidc import (
    OidcVerificationError,
    looks_like_jwt,
    verify_github_oidc,
)
from security_scanner.shared.config import get_settings

logger = logging.getLogger(__name__)

_AUTH_FAILURE_MESSAGE = "Security scan authentication failed. Contact TechOps."


def verify_scan_token(request: Request) -> str:
    """Validate ``Authorization: Bearer <token>`` — OIDC first, then static.

    Returns the bearer string on success. Raises ``HTTPException(401)`` on any
    failure mode — missing header, wrong scheme, OIDC rejection, token
    mismatch, or ``PHRASE_SCAN_TOKEN`` not configured.
    """
    token = _extract_bearer_token(request)
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_AUTH_FAILURE_MESSAGE,
        )

    settings = get_settings()

    if settings.GITHUB_OIDC_ENABLED and looks_like_jwt(token):
        allowed = [
            ref.strip()
            for ref in settings.GITHUB_OIDC_ALLOWED_WORKFLOW_REFS.split(",")
            if ref.strip()
        ]
        try:
            identity = verify_github_oidc(
                token,
                audience=settings.GITHUB_OIDC_AUDIENCE,
                allowed_workflow_refs=allowed,
            )
        except OidcVerificationError as exc:
            logger.info("oidc verification failed: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=_AUTH_FAILURE_MESSAGE,
            ) from exc
        request.state.github_identity = identity
        return token

    expected = settings.PHRASE_SCAN_TOKEN.get_secret_value() if settings.PHRASE_SCAN_TOKEN else None
    if expected is None or not hmac.compare_digest(token, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_AUTH_FAILURE_MESSAGE,
        )

    return token


def _extract_bearer_token(request: Request) -> str | None:
    header = request.headers.get("Authorization") or request.headers.get("authorization")
    if not header:
        return None
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()
