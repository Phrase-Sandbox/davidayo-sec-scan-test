"""GitHub Actions OIDC token verification for the master-scanner-pipeline path.

When `GITHUB_OIDC_ENABLED=true`, /scan accepts an `Authorization: Bearer <JWT>`
where the JWT is issued by `https://token.actions.githubusercontent.com`. The
verifier:

  1. Fetches GitHub's JWKS (public signing keys), cached for `_JWKS_TTL_SECONDS`.
  2. Verifies the JWT signature with the matching `kid`.
  3. Validates `iss`, `aud`, `exp`, `nbf` standard claims.
  4. Enforces that `job_workflow_ref` starts with one of the configured
     allowlist prefixes — this is what stops a rogue dev workflow from
     authenticating directly; only workflows that ran through our master
     pipeline pass.

Returns a `GitHubIdentity` (repository + workflow_ref + run_id) suitable for
audit logging. All failures raise `OidcVerificationError` with a sanitised
message — the caller maps that to HTTP 401.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any
from urllib.request import urlopen

import jwt
from jwt.algorithms import RSAAlgorithm

GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
GITHUB_OIDC_JWKS_URL = f"{GITHUB_OIDC_ISSUER}/.well-known/jwks"

_JWKS_TTL_SECONDS = 3600  # GitHub rotates keys ~weekly; 1-hour cache is safe


class OidcVerificationError(Exception):
    """Raised when an OIDC token fails any validation step."""


@dataclass(frozen=True)
class GitHubIdentity:
    repository: str
    workflow_ref: str
    run_id: str
    actor: str


class _JwksCache:
    """Thread-safe TTL cache of GitHub's JWKS, indexed by `kid`.

    A single instance is shared across requests. On cache miss or expiry we
    refetch once; if the refetch fails we fall back to the prior cache (if
    any) so a transient GitHub outage doesn't black out auth.
    """

    def __init__(self, fetcher=None) -> None:
        self._fetcher = fetcher or _default_jwks_fetcher
        self._keys: dict[str, Any] = {}
        self._fetched_at: float = 0.0
        self._lock = threading.Lock()

    def get(self, kid: str) -> Any:
        with self._lock:
            now = time.time()
            stale = (now - self._fetched_at) > _JWKS_TTL_SECONDS
            missing = kid not in self._keys
            if stale or missing:
                try:
                    self._keys = self._fetcher()
                    self._fetched_at = now
                except Exception as exc:
                    if not self._keys:
                        raise OidcVerificationError(f"unable to fetch JWKS: {exc}") from exc
                    # else: fall back to last-known keys
            key = self._keys.get(kid)
            if key is None:
                raise OidcVerificationError(f"unknown signing key kid={kid}")
            return key

    def _reset_for_test(self) -> None:
        self._keys = {}
        self._fetched_at = 0.0


def _default_jwks_fetcher() -> dict[str, Any]:
    """Fetch GitHub's JWKS and return a `{kid: public_key}` map."""
    with urlopen(GITHUB_OIDC_JWKS_URL, timeout=5) as resp:  # noqa: S310 — hardcoded https URL
        import json

        doc = json.loads(resp.read())
    return {jwk["kid"]: RSAAlgorithm.from_jwk(jwk) for jwk in doc.get("keys", [])}


_default_cache = _JwksCache()


def verify_github_oidc(
    token: str,
    *,
    audience: str,
    allowed_workflow_refs: list[str],
    cache: _JwksCache | None = None,
    now: float | None = None,
) -> GitHubIdentity:
    """Validate `token` and return the GitHub identity that issued it.

    Args:
        token: The raw JWT string from the Authorization header.
        audience: Expected `aud` claim.
        allowed_workflow_refs: Prefixes that the `job_workflow_ref` claim must
            start with. Empty list disables the allowlist check (NOT
            recommended — required in production).
        cache: JWKS cache; defaults to the module-level singleton. Tests inject.
        now: Override clock for tests; defaults to `time.time()`.

    Raises:
        OidcVerificationError on any validation failure.
    """
    cache = cache or _default_cache
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise OidcVerificationError(f"malformed token: {exc}") from exc

    kid = unverified_header.get("kid")
    if not kid:
        raise OidcVerificationError("token header missing `kid`")

    public_key = cache.get(kid)

    leeway = 30  # tolerate small clock skew between GitHub and us
    try:
        claims = jwt.decode(
            token,
            key=public_key,
            algorithms=["RS256"],
            audience=audience,
            issuer=GITHUB_OIDC_ISSUER,
            leeway=leeway,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except jwt.PyJWTError as exc:
        raise OidcVerificationError(f"signature/claim check failed: {exc}") from exc

    # Override clock for tests (PyJWT doesn't accept `now=`).
    if now is not None:
        if claims.get("exp", 0) < now:
            raise OidcVerificationError("token expired")
        if claims.get("nbf", 0) > now + leeway:
            raise OidcVerificationError("token not yet valid")

    workflow_ref = claims.get("job_workflow_ref") or claims.get("workflow_ref") or ""
    if allowed_workflow_refs and not any(
        workflow_ref.startswith(prefix) for prefix in allowed_workflow_refs
    ):
        raise OidcVerificationError(f"workflow_ref {workflow_ref!r} not in allowlist")

    repository = claims.get("repository")
    run_id = claims.get("run_id") or claims.get("runner_id") or ""
    actor = claims.get("actor") or ""

    if not repository:
        raise OidcVerificationError("token missing `repository` claim")

    return GitHubIdentity(
        repository=str(repository),
        workflow_ref=str(workflow_ref),
        run_id=str(run_id),
        actor=str(actor),
    )


def looks_like_jwt(token: str) -> bool:
    """Cheap heuristic — JWTs have two dots separating three base64url segments.

    Used by the auth dispatch path to decide whether to try OIDC verification
    or fall through to the bearer-token check. Not a security boundary; the
    real validation happens in `verify_github_oidc`.
    """
    parts = token.split(".")
    return len(parts) == 3 and all(p for p in parts)
