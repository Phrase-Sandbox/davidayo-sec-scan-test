"""GitHub API client (spec §7.1).

Authenticates via GitHub App installation tokens:
1. Sign a JWT (RS256) with the App's private key (max 10-min TTL).
2. Exchange JWT for an installation access token (1-hour TTL).
3. Use the installation token to call ``/contents`` and ``/compare`` endpoints.

Non-negotiable rules from §7.1 (mirrored in the implementation):

- **Sequential fetching only.** Never issue parallel HTTP calls.
- **200 ms delay** between consecutive file fetches inside a directory listing.
- **3 attempts** with exponential backoff 1 s, 2 s, 4 s.
- **Auto-refresh on 401.** The refresh is a one-shot retry within the same
  attempt — it does *not* consume the 3-attempt retry budget. A second 401/403
  after refresh is a hard auth failure (``GitHubAuthError``).
- **Circuit breaker** — open after 5 consecutive failures, half-open after
  60 s, close after 3 consecutive successes.
- **Never log file contents.** Only paths, counts, and owner/repo metadata.
"""

from __future__ import annotations

import base64
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import httpx
import jwt

from security_scanner.shared.logging_util import get_logger

log = get_logger(__name__)

GITHUB_API_BASE = "https://api.github.com"
MAX_ATTEMPTS = 3
BACKOFF_SECONDS: tuple[float, ...] = (1.0, 2.0, 4.0)
INTER_REQUEST_DELAY_SECONDS = 0.2
JWT_TTL_SECONDS = 540  # 9 min; GitHub allows up to 10
INSTALLATION_TOKEN_TTL_SECONDS = 3500.0  # 58 min; GitHub expires at 60 min
HTTP_TIMEOUT_SECONDS = 30.0

CB_FAILURE_THRESHOLD = 5
CB_RECOVERY_TIMEOUT_SECONDS = 60.0
CB_SUCCESS_THRESHOLD = 3


class GitHubError(Exception):
    """Base class for GitHub client errors."""


class GitHubAuthError(GitHubError):
    """401/403 from GitHub — credentials invalid or insufficient. Not retried."""


class GitHubCircuitOpenError(GitHubError):
    """Too many recent failures; calls are refused until the recovery timeout elapses."""


@dataclass
class _CachedToken:
    token: str
    expires_at: float  # monotonic clock


class _CircuitBreaker:
    """Three-state breaker (closed / open / half-open) per spec §7.1."""

    STATE_CLOSED = "closed"
    STATE_OPEN = "open"
    STATE_HALF_OPEN = "half_open"

    def __init__(self, clock_fn: Callable[[], float]) -> None:
        self._clock = clock_fn
        self._state = self.STATE_CLOSED
        self._consecutive_failures = 0
        self._consecutive_successes_half_open = 0
        self._opened_at: float | None = None

    @property
    def state(self) -> str:
        return self._state

    def check(self) -> None:
        """Raise if open and still within the recovery window; transition to half-open otherwise."""
        if self._state != self.STATE_OPEN:
            return
        elapsed = self._clock() - (self._opened_at or 0.0)
        if elapsed < CB_RECOVERY_TIMEOUT_SECONDS:
            remaining = CB_RECOVERY_TIMEOUT_SECONDS - elapsed
            raise GitHubCircuitOpenError(f"GitHub circuit breaker open; retry in {remaining:.0f}s")
        self._state = self.STATE_HALF_OPEN
        self._consecutive_successes_half_open = 0

    def record_success(self) -> None:
        if self._state == self.STATE_HALF_OPEN:
            self._consecutive_successes_half_open += 1
            if self._consecutive_successes_half_open >= CB_SUCCESS_THRESHOLD:
                self._state = self.STATE_CLOSED
                self._consecutive_failures = 0
                self._consecutive_successes_half_open = 0
                self._opened_at = None
        else:
            self._consecutive_failures = 0

    def record_failure(self) -> None:
        if self._state == self.STATE_HALF_OPEN:
            self._state = self.STATE_OPEN
            self._opened_at = self._clock()
            self._consecutive_failures = 0
            self._consecutive_successes_half_open = 0
            return
        self._consecutive_failures += 1
        if self._consecutive_failures >= CB_FAILURE_THRESHOLD:
            self._state = self.STATE_OPEN
            self._opened_at = self._clock()


class GitHubClient:
    """GitHub App-authenticated client for fetching source files and diffs."""

    def __init__(
        self,
        app_id: str | None = None,
        private_key: str | None = None,
        *,
        oauth_token: str | None = None,
        http_client: httpx.Client | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
        clock_fn: Callable[[], float] = time.monotonic,
    ) -> None:
        """Construct in one of two auth modes.

        - **App mode** (gate path): pass ``app_id`` + ``private_key``. The
          client mints installation tokens by signing JWTs.
        - **OAuth mode** (skill path): pass ``oauth_token``. The token IS the
          bearer used for every request — no JWT signing, no installation
          lookup. The token expires when the OAuth session does.
        """
        if oauth_token is None and (not app_id or not private_key):
            raise ValueError(
                "GitHubClient requires either oauth_token (skill path) "
                "or both app_id and private_key (gate path)"
            )
        self._app_id = app_id or ""
        self._private_key = private_key or ""
        self._oauth_token = oauth_token
        self._http = http_client or httpx.Client(
            base_url=GITHUB_API_BASE,
            timeout=HTTP_TIMEOUT_SECONDS,
            headers={"Accept": "application/vnd.github+json"},
        )
        self._sleep = sleep_fn
        self._clock = clock_fn
        self._installation_ids: dict[str, int] = {}
        self._installation_tokens: dict[str, _CachedToken] = {}
        self._circuit_breaker = _CircuitBreaker(clock_fn)

    # --- Public API ----------------------------------------------------------

    def get_repo_files(
        self,
        owner: str,
        repo: str,
        ref: str = "HEAD",
        path: str = "",
    ) -> dict[str, str]:
        """Fetch all files under *path* in *owner/repo* at *ref* recursively.

        Returns ``{filepath: utf8_decoded_content}``. Binary content is decoded
        with ``errors="replace"`` so callers can rely on getting a ``str``.
        """
        files: dict[str, str] = {}
        self._fetch_path_recursive(owner, repo, ref, path, files)
        log.info("github fetch complete", owner=owner, repo=repo, file_count=len(files))
        return files

    def get_diff_files(
        self,
        owner: str,
        repo: str,
        base: str,
        head: str,
    ) -> dict[str, str]:
        """Fetch the diff between *base* and *head* for *owner/repo*.

        Returns ``{filename: unified_diff_patch}`` per the §7.1 endpoint table
        (``files[].filename, files[].patch``). Files without a patch (e.g. pure
        binary changes) are omitted.
        """
        url = f"/repos/{owner}/{repo}/compare/{base}...{head}"
        response = self._authed_request("GET", url, owner=owner)
        data = response.json()
        files: dict[str, str] = {}
        for entry in data.get("files", []):
            filename = entry.get("filename")
            patch = entry.get("patch")
            if filename and patch is not None:
                files[filename] = patch
        log.info(
            "github diff complete",
            owner=owner,
            repo=repo,
            base=base,
            head=head,
            file_count=len(files),
        )
        return files

    # --- Internals -----------------------------------------------------------

    def _fetch_path_recursive(
        self,
        owner: str,
        repo: str,
        ref: str,
        path: str,
        accumulator: dict[str, str],
    ) -> None:
        url = f"/repos/{owner}/{repo}/contents/{path}"
        response = self._authed_request("GET", url, owner=owner, params={"ref": ref})
        payload = response.json()

        if isinstance(payload, dict):
            # Single-file path — content already in payload.
            if payload.get("type") == "file":
                accumulator[payload["path"]] = self._decode_blob(payload)
            return

        # Directory listing — fetch each file individually with a 200 ms delay
        # between consecutive requests.
        for index, item in enumerate(payload):
            if item.get("type") == "file":
                file_url = f"/repos/{owner}/{repo}/contents/{item['path']}"
                file_response = self._authed_request(
                    "GET", file_url, owner=owner, params={"ref": ref}
                )
                accumulator[item["path"]] = self._decode_blob(file_response.json())
            elif item.get("type") == "dir":
                self._fetch_path_recursive(owner, repo, ref, item["path"], accumulator)
            if index < len(payload) - 1:
                self._sleep(INTER_REQUEST_DELAY_SECONDS)

    @staticmethod
    def _decode_blob(blob: dict[str, Any]) -> str:
        if blob.get("encoding") == "base64":
            raw = base64.b64decode(blob.get("content", ""))
            return raw.decode("utf-8", errors="replace")
        return blob.get("content", "") or ""

    def _authed_request(
        self,
        method: str,
        url: str,
        owner: str,
        **kwargs: Any,
    ) -> httpx.Response:
        """Issue an authenticated request to GitHub with retry, refresh, and circuit-breaker."""
        self._circuit_breaker.check()

        base_headers = dict(kwargs.pop("headers", {}))
        last_error: str = "unknown error"

        for attempt in range(MAX_ATTEMPTS):
            headers = {
                **base_headers,
                "Authorization": f"Bearer {self._get_installation_token(owner)}",
            }
            try:
                response = self._http.request(method, url, headers=headers, **kwargs)
            except httpx.RequestError as exc:
                last_error = f"network error: {exc!r}"
                self._sleep(BACKOFF_SECONDS[attempt])
                continue

            status = response.status_code

            # 401 → one-shot refresh, then either succeed or fail-fast.
            if status == 401:
                self._invalidate_installation_token(owner)
                headers["Authorization"] = f"Bearer {self._get_installation_token(owner)}"
                response = self._http.request(method, url, headers=headers, **kwargs)
                status = response.status_code
                if status in (401, 403):
                    self._circuit_breaker.record_failure()
                    raise GitHubAuthError(
                        f"GitHub returned {status} after installation-token refresh"
                    )

            if status == 403:
                self._circuit_breaker.record_failure()
                raise GitHubAuthError("GitHub returned 403 (forbidden)")

            if status == 429:
                retry_after = _parse_retry_after(response.headers.get("Retry-After"))
                self._sleep(retry_after)
                last_error = f"rate limited (429), waited {retry_after}s"
                continue

            if 500 <= status < 600:
                last_error = f"server error {status}"
                self._sleep(BACKOFF_SECONDS[attempt])
                continue

            if status >= 400:
                self._circuit_breaker.record_failure()
                response.raise_for_status()

            self._circuit_breaker.record_success()
            return response

        self._circuit_breaker.record_failure()
        raise GitHubError(f"GitHub request failed after {MAX_ATTEMPTS} attempts: {last_error}")

    # --- Auth ---------------------------------------------------------------

    def _get_installation_token(self, owner: str) -> str:
        # OAuth mode: use the user's access token directly — no JWT, no
        # installation lookup. The token is opaque to us; refresh is the
        # OAuth session's job.
        if self._oauth_token is not None:
            return self._oauth_token

        cached = self._installation_tokens.get(owner)
        if cached and cached.expires_at > self._clock():
            return cached.token

        installation_id = self._get_installation_id(owner)
        jwt_token = self._generate_jwt()
        response = self._http.post(
            f"/app/installations/{installation_id}/access_tokens",
            headers=_jwt_headers(jwt_token),
        )
        response.raise_for_status()
        data = response.json()
        token = data["token"]
        expires_at = self._clock() + INSTALLATION_TOKEN_TTL_SECONDS
        self._installation_tokens[owner] = _CachedToken(token=token, expires_at=expires_at)
        log.info("github installation token minted", owner=owner)
        return token

    def _invalidate_installation_token(self, owner: str) -> None:
        # OAuth mode has nothing to invalidate — the user's token is the only
        # one we have, and we can't refresh it. A 401 in OAuth mode means
        # the OAuth session has died; the caller should re-auth.
        if self._oauth_token is not None:
            return
        self._installation_tokens.pop(owner, None)

    def _get_installation_id(self, owner: str) -> int:
        if owner in self._installation_ids:
            return self._installation_ids[owner]

        jwt_token = self._generate_jwt()
        headers = _jwt_headers(jwt_token)

        # Try user first, then org. The two endpoints are mutually exclusive.
        response = self._http.get(f"/users/{owner}/installation", headers=headers)
        if response.status_code == 404:
            response = self._http.get(f"/orgs/{owner}/installation", headers=headers)
        response.raise_for_status()
        installation_id = int(response.json()["id"])
        self._installation_ids[owner] = installation_id
        return installation_id

    def _generate_jwt(self) -> str:
        now = int(time.time())
        payload = {
            "iat": now - 60,
            "exp": now + JWT_TTL_SECONDS,
            "iss": self._app_id,
        }
        return jwt.encode(payload, self._private_key, algorithm="RS256")


def _jwt_headers(jwt_token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {jwt_token}",
        "Accept": "application/vnd.github+json",
    }


def _parse_retry_after(raw: str | None) -> float:
    if raw is None:
        return 1.0
    try:
        return float(raw)
    except ValueError:
        return 1.0
