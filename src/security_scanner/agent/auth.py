"""``PHRASE_SCAN_TOKEN`` verification for the deployment-gate endpoint (§7.1, §7.3, EC-006).

Bearer token comparison is constant-time (``hmac.compare_digest``) so token
length is not leaked via timing. Any mismatch surfaces the canonical
EC-006 message — the CI/CD step renders it verbatim.
"""

from __future__ import annotations

import hmac

from fastapi import HTTPException, Request, status

from security_scanner.shared.config import get_settings

_AUTH_FAILURE_MESSAGE = "Security scan authentication failed. Contact TechOps."


def verify_scan_token(request: Request) -> str:
    """Validate the ``Authorization: Bearer <token>`` header against ``PHRASE_SCAN_TOKEN``.

    Returns the token on success. Raises ``HTTPException(401)`` on any failure
    mode — missing header, wrong scheme, token mismatch, or
    ``PHRASE_SCAN_TOKEN`` not configured.
    """
    token = _extract_bearer_token(request)
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_AUTH_FAILURE_MESSAGE,
        )

    expected = get_settings().PHRASE_SCAN_TOKEN
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
