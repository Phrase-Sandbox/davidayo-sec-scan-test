"""Tests for the GitHub App-authenticated client (spec §7.1).

Uses ``httpx.MockTransport`` (built into httpx, no extra deps) to intercept
requests. A fresh RSA keypair is generated per session and passed as the
private key for JWT signing.
"""

import base64
from collections.abc import Callable

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from security_scanner.shared.github.client import (
    BACKOFF_SECONDS,
    CB_FAILURE_THRESHOLD,
    CB_RECOVERY_TIMEOUT_SECONDS,
    INTER_REQUEST_DELAY_SECONDS,
    GitHubAuthError,
    GitHubCircuitOpenError,
    GitHubClient,
    GitHubError,
)

# --- Fixtures ----------------------------------------------------------------


@pytest.fixture(scope="session")
def rsa_private_key_pem() -> str:
    """Generate a throwaway RSA keypair to sign test JWTs."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


def _build_client(rsa_private_key_pem: str, handler: Callable):
    """Build a client backed by ``MockTransport`` with a fake clock and recorded sleeps."""
    transport = httpx.MockTransport(handler)
    http_client = httpx.Client(transport=transport, base_url="https://api.github.com")

    clock = [0.0]
    sleeps: list[float] = []

    def sleep_fn(duration: float) -> None:
        sleeps.append(duration)
        clock[0] += duration

    def clock_fn() -> float:
        return clock[0]

    client = GitHubClient(
        app_id="123",
        private_key=rsa_private_key_pem,
        http_client=http_client,
        sleep_fn=sleep_fn,
        clock_fn=clock_fn,
    )
    return client, sleeps, clock


def _auth_response(request: httpx.Request) -> httpx.Response | None:
    """Common handler for installation-lookup and token-mint requests."""
    path = request.url.path
    if path == "/users/owner/installation" or path == "/orgs/owner/installation":
        return httpx.Response(200, json={"id": 42})
    if "/access_tokens" in path:
        return httpx.Response(200, json={"token": "ghs_test_token"})
    return None


def _b64(content: bytes) -> str:
    return base64.b64encode(content).decode()


# --- Happy paths -------------------------------------------------------------


def test_get_repo_files_single_file(rsa_private_key_pem):
    def handler(request: httpx.Request) -> httpx.Response:
        if (r := _auth_response(request)) is not None:
            return r
        if request.url.path == "/repos/owner/repo/contents/":
            return httpx.Response(200, json=[{"type": "file", "path": "README.md"}])
        if request.url.path == "/repos/owner/repo/contents/README.md":
            return httpx.Response(
                200,
                json={
                    "type": "file",
                    "path": "README.md",
                    "encoding": "base64",
                    "content": _b64(b"hello\n"),
                },
            )
        return httpx.Response(404)

    client, _, _ = _build_client(rsa_private_key_pem, handler)
    assert client.get_repo_files("owner", "repo") == {"README.md": "hello\n"}


def test_get_repo_files_recurses_into_subdirectories(rsa_private_key_pem):
    listings = {
        "/repos/owner/repo/contents/": [
            {"type": "dir", "path": "src"},
            {"type": "file", "path": "README.md"},
        ],
        "/repos/owner/repo/contents/src": [
            {"type": "file", "path": "src/app.py"},
        ],
    }
    blobs = {
        "/repos/owner/repo/contents/README.md": b"# Hello\n",
        "/repos/owner/repo/contents/src/app.py": b"x = 1\n",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if (r := _auth_response(request)) is not None:
            return r
        path = request.url.path
        if path in listings:
            return httpx.Response(200, json=listings[path])
        if path in blobs:
            return httpx.Response(
                200,
                json={
                    "type": "file",
                    "path": path.split("/contents/")[1],
                    "encoding": "base64",
                    "content": _b64(blobs[path]),
                },
            )
        return httpx.Response(404, json={"message": f"unhandled {path}"})

    client, sleeps, _ = _build_client(rsa_private_key_pem, handler)
    files = client.get_repo_files("owner", "repo")
    assert files == {"README.md": "# Hello\n", "src/app.py": "x = 1\n"}
    # 200 ms delay between the README fetch and recursing into src.
    assert INTER_REQUEST_DELAY_SECONDS in sleeps


def test_get_diff_files_returns_patches_only(rsa_private_key_pem):
    def handler(request: httpx.Request) -> httpx.Response:
        if (r := _auth_response(request)) is not None:
            return r
        if "/compare/" in request.url.path:
            return httpx.Response(
                200,
                json={
                    "files": [
                        {"filename": "src/app.py", "patch": "@@ -1 +1 @@\n-old\n+new"},
                        {"filename": "image.png", "patch": None},  # binary — no patch
                    ]
                },
            )
        return httpx.Response(404)

    client, _, _ = _build_client(rsa_private_key_pem, handler)
    files = client.get_diff_files("owner", "repo", "abc", "def")
    assert files == {"src/app.py": "@@ -1 +1 @@\n-old\n+new"}


# --- Auth refresh on 401 -----------------------------------------------------


def test_401_triggers_one_shot_token_refresh(rsa_private_key_pem):
    counts = {"contents": 0, "token_mint": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/users/owner/installation":
            return httpx.Response(200, json={"id": 42})
        if "/access_tokens" in path:
            counts["token_mint"] += 1
            return httpx.Response(200, json={"token": f"tok_{counts['token_mint']}"})
        if path == "/repos/owner/repo/contents/":
            counts["contents"] += 1
            if counts["contents"] == 1:
                return httpx.Response(401, json={"message": "Bad credentials"})
            return httpx.Response(200, json=[])
        return httpx.Response(404)

    client, _, _ = _build_client(rsa_private_key_pem, handler)
    assert client.get_repo_files("owner", "repo") == {}
    assert counts["token_mint"] == 2  # initial + refresh
    assert counts["contents"] == 2  # original 401 + retry with fresh token


def test_repeated_401_after_refresh_raises_auth_error(rsa_private_key_pem):
    def handler(request: httpx.Request) -> httpx.Response:
        if (r := _auth_response(request)) is not None:
            return r
        return httpx.Response(401, json={"message": "Bad credentials"})

    client, _, _ = _build_client(rsa_private_key_pem, handler)
    with pytest.raises(GitHubAuthError):
        client.get_repo_files("owner", "repo")


def test_403_raises_github_auth_error(rsa_private_key_pem):
    def handler(request: httpx.Request) -> httpx.Response:
        if (r := _auth_response(request)) is not None:
            return r
        return httpx.Response(403, json={"message": "Forbidden"})

    client, _, _ = _build_client(rsa_private_key_pem, handler)
    with pytest.raises(GitHubAuthError):
        client.get_repo_files("owner", "repo")


# --- 429 honours Retry-After ------------------------------------------------


def test_429_waits_for_retry_after_header_then_retries(rsa_private_key_pem):
    counts = {"contents": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if (r := _auth_response(request)) is not None:
            return r
        if request.url.path == "/repos/owner/repo/contents/":
            counts["contents"] += 1
            if counts["contents"] == 1:
                return httpx.Response(429, headers={"Retry-After": "7"})
            return httpx.Response(200, json=[])
        return httpx.Response(404)

    client, sleeps, _ = _build_client(rsa_private_key_pem, handler)
    assert client.get_repo_files("owner", "repo") == {}
    assert 7.0 in sleeps
    assert counts["contents"] == 2


# --- Retry budget exhaustion ------------------------------------------------


def test_three_retries_exhausted_raises_github_error(rsa_private_key_pem):
    def handler(request: httpx.Request) -> httpx.Response:
        if (r := _auth_response(request)) is not None:
            return r
        return httpx.Response(500, text="server error")

    client, sleeps, _ = _build_client(rsa_private_key_pem, handler)
    with pytest.raises(GitHubError) as exc_info:
        client.get_repo_files("owner", "repo")
    # The error must NOT be the auth subclass — auth/non-auth distinction matters
    # to callers (EC-001 vs EC-005).
    assert not isinstance(exc_info.value, GitHubAuthError)
    # All three backoff durations must have been honoured.
    for backoff in BACKOFF_SECONDS:
        assert backoff in sleeps


def test_network_error_is_retried(rsa_private_key_pem):
    counts = {"contents": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if (r := _auth_response(request)) is not None:
            return r
        if request.url.path == "/repos/owner/repo/contents/":
            counts["contents"] += 1
            if counts["contents"] == 1:
                raise httpx.ConnectError("simulated network blip")
            return httpx.Response(200, json=[])
        return httpx.Response(404)

    client, sleeps, _ = _build_client(rsa_private_key_pem, handler)
    assert client.get_repo_files("owner", "repo") == {}
    assert counts["contents"] == 2
    assert BACKOFF_SECONDS[0] in sleeps


# --- Circuit breaker --------------------------------------------------------


def test_circuit_breaker_opens_after_5_consecutive_failures(rsa_private_key_pem):
    def handler(request: httpx.Request) -> httpx.Response:
        if (r := _auth_response(request)) is not None:
            return r
        return httpx.Response(500)

    client, _, _ = _build_client(rsa_private_key_pem, handler)
    # Five failed calls — each exhausts its 3-attempt retry budget.
    for _ in range(CB_FAILURE_THRESHOLD):
        with pytest.raises(GitHubError):
            client.get_repo_files("owner", "repo")
    # Sixth call should short-circuit without hitting the network.
    with pytest.raises(GitHubCircuitOpenError):
        client.get_repo_files("owner", "repo")


def test_circuit_breaker_transitions_to_half_open_after_recovery_timeout(rsa_private_key_pem):
    state = {"fail": True}

    def handler(request: httpx.Request) -> httpx.Response:
        if (r := _auth_response(request)) is not None:
            return r
        if state["fail"]:
            return httpx.Response(500)
        return httpx.Response(200, json=[])

    client, _, clock = _build_client(rsa_private_key_pem, handler)
    for _ in range(CB_FAILURE_THRESHOLD):
        with pytest.raises(GitHubError):
            client.get_repo_files("owner", "repo")

    # Circuit is open.
    with pytest.raises(GitHubCircuitOpenError):
        client.get_repo_files("owner", "repo")

    # Advance the clock past the recovery timeout and flip the upstream to success.
    clock[0] += CB_RECOVERY_TIMEOUT_SECONDS + 1.0
    state["fail"] = False
    assert client.get_repo_files("owner", "repo") == {}
