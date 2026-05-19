"""Tests for the skill OAuth flow (spec §7.1, §2.2 skill steps 1–2, §3.3, EC-005)."""

from typing import Annotated
from unittest.mock import MagicMock
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from security_scanner.skill.auth import verify_oauth_token
from security_scanner.skill.oauth import (
    SESSION_COOKIE_NAME,
    SessionStore,
    get_session_store,
    get_token_exchanger,
    router,
)

# --- Fixtures --------------------------------------------------------------


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    """Settings need every required var to instantiate."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("PHRASE_SCAN_TOKEN", "scan-token")
    monkeypatch.setenv("GITHUB_APP_ID", "123")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", "-----BEGIN PRIVATE KEY-----")
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_ID", "Iv1.test_client_id")
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_SECRET", "oauth_test_secret")


@pytest.fixture
def store() -> SessionStore:
    return SessionStore()


@pytest.fixture
def exchanger_calls() -> list[str]:
    return []


@pytest.fixture
def app(store, exchanger_calls):
    """Build a test app with the OAuth router + an isolated session store +
    a fake token exchanger that returns deterministic tokens."""

    async def fake_exchanger(code: str, settings) -> str:
        exchanger_calls.append(code)
        return f"gho_fake_{code}"

    fastapi_app = FastAPI()
    fastapi_app.include_router(router)

    # Mount a probe endpoint that exercises verify_oauth_token so we can
    # assert its behaviour through HTTP.
    @fastapi_app.get("/probe/me")
    def probe(token: Annotated[str, Depends(verify_oauth_token)]) -> dict:
        return {"access_token": token}

    fastapi_app.dependency_overrides[get_session_store] = lambda: store
    fastapi_app.dependency_overrides[get_token_exchanger] = lambda: fake_exchanger
    return fastapi_app


@pytest.fixture
def client(app):
    return TestClient(app)


def _init_session(client: TestClient) -> tuple[str, str]:
    """Hit /skill/oauth/init and return ``(session_token, state)``."""
    response = client.get("/skill/oauth/init", follow_redirects=False)
    assert response.status_code == 302
    location = response.headers["location"]
    state = parse_qs(urlparse(location).query)["state"][0]
    session_token = response.cookies[SESSION_COOKIE_NAME]
    return session_token, state


# --- /skill/oauth/init ----------------------------------------------------


def test_init_redirects_to_github_authorize_with_client_id_and_scope(client):
    response = client.get("/skill/oauth/init", follow_redirects=False)
    assert response.status_code == 302
    location = response.headers["location"]
    parsed = urlparse(location)
    assert parsed.netloc == "github.com"
    assert parsed.path == "/login/oauth/authorize"
    query = parse_qs(parsed.query)
    assert query["client_id"] == ["Iv1.test_client_id"]
    assert query["scope"] == ["repo:read"]
    assert "state" in query
    # state is a urlsafe-base64-ish blob; should be long enough to be unguessable.
    assert len(query["state"][0]) >= 32


def test_init_sets_httponly_session_cookie_with_samesite_lax(client):
    response = client.get("/skill/oauth/init", follow_redirects=False)
    # Inspect the raw Set-Cookie header — TestClient's cookies dict drops attrs.
    set_cookie = response.headers["set-cookie"]
    assert SESSION_COOKIE_NAME in set_cookie
    assert "HttpOnly" in set_cookie
    # SameSite is normalised to "lax" by Starlette.
    assert "samesite=lax" in set_cookie.lower()


def test_each_init_creates_a_fresh_session_with_unique_state(client):
    a_token, a_state = _init_session(client)
    b_token, b_state = _init_session(client)
    assert a_token != b_token
    assert a_state != b_state


# --- /skill/oauth/callback ------------------------------------------------


def test_valid_callback_stores_token_and_redirects_to_skill_ready(
    client, store, exchanger_calls
):
    session_token, state = _init_session(client)
    response = client.get(
        f"/skill/oauth/callback?code=good_code&state={state}",
        cookies={SESSION_COOKIE_NAME: session_token},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert response.headers["location"] == "/skill/ready"
    # The fake exchanger was invoked with the supplied code.
    assert exchanger_calls == ["good_code"]
    # The store now has the access token attached.
    assert store.get_access_token(session_token) == "gho_fake_good_code"


def test_callback_with_mismatched_state_is_rejected(client, store):
    session_token, _real_state = _init_session(client)
    response = client.get(
        "/skill/oauth/callback?code=good_code&state=attacker_chosen_state",
        cookies={SESSION_COOKIE_NAME: session_token},
        follow_redirects=False,
    )
    assert response.status_code == 400
    assert "Invalid OAuth state" in response.json()["detail"]
    # No access token was attached.
    assert store.get_access_token(session_token) is None


def test_callback_without_session_cookie_is_unauthorised(client):
    # Init creates a session; we deliberately drop the cookie before calling
    # the callback. TestClient persists cookies between requests, so we have
    # to clear the cookie jar to simulate a request that lacks the cookie.
    _session_token, state = _init_session(client)
    client.cookies.clear()
    response = client.get(
        f"/skill/oauth/callback?code=good_code&state={state}",
        follow_redirects=False,
    )
    assert response.status_code == 401
    assert "Missing session cookie" in response.json()["detail"]


def test_callback_replayed_after_success_is_rejected(client, store):
    """A completed session must not accept a second callback (replay defence)."""
    session_token, state = _init_session(client)
    first = client.get(
        f"/skill/oauth/callback?code=good_code&state={state}",
        cookies={SESSION_COOKIE_NAME: session_token},
        follow_redirects=False,
    )
    assert first.status_code == 302
    # Replay the same callback URL.
    second = client.get(
        f"/skill/oauth/callback?code=good_code&state={state}",
        cookies={SESSION_COOKIE_NAME: session_token},
        follow_redirects=False,
    )
    assert second.status_code == 400


def test_callback_with_unknown_session_token_is_rejected(client):
    """A session_token that was never minted by /init must fail state validation."""
    _real_token, state = _init_session(client)
    response = client.get(
        f"/skill/oauth/callback?code=good_code&state={state}",
        cookies={SESSION_COOKIE_NAME: "forged_session_token_xyz"},
        follow_redirects=False,
    )
    assert response.status_code == 400


def test_callback_requires_code_and_state_query_params(client):
    response = client.get("/skill/oauth/callback", follow_redirects=False)
    # FastAPI validates required query params before the handler runs.
    assert response.status_code == 422


# --- verify_oauth_token via probe endpoint --------------------------------


def test_probe_with_valid_session_returns_access_token(client):
    session_token, state = _init_session(client)
    client.get(
        f"/skill/oauth/callback?code=good_code&state={state}",
        cookies={SESSION_COOKIE_NAME: session_token},
        follow_redirects=False,
    )
    response = client.get(
        "/probe/me",
        cookies={SESSION_COOKIE_NAME: session_token},
    )
    assert response.status_code == 200
    assert response.json() == {"access_token": "gho_fake_good_code"}


def test_probe_without_session_cookie_returns_401_with_ec_005_message(client):
    response = client.get("/probe/me")
    assert response.status_code == 401
    assert response.json()["detail"] == (
        "GitHub authorisation failed. Please re-authorise and try again."
    )


def test_probe_with_session_cookie_but_pending_session_returns_401(client):
    """A session that exists but hasn't completed OAuth has no access token."""
    session_token, _state = _init_session(client)
    # Use the cookie without completing the callback.
    response = client.get(
        "/probe/me",
        cookies={SESSION_COOKIE_NAME: session_token},
    )
    assert response.status_code == 401


def test_probe_with_forged_session_cookie_returns_401(client):
    response = client.get(
        "/probe/me",
        cookies={SESSION_COOKIE_NAME: "forged_token_not_in_store"},
    )
    assert response.status_code == 401


# --- Direct SessionStore tests --------------------------------------------


def test_session_store_complete_rejects_mismatched_state():
    store = SessionStore()
    token, real_state = store.create_pending()
    assert store.complete(token, "attacker_state", "gho_test") is False


def test_session_store_complete_rejects_replay():
    store = SessionStore()
    token, state = store.create_pending()
    assert store.complete(token, state, "gho_first") is True
    # Second complete on the same session must fail.
    assert store.complete(token, state, "gho_second") is False
    # The first token is preserved.
    assert store.get_access_token(token) == "gho_first"


def test_session_store_get_access_token_returns_none_for_unknown_token():
    store = SessionStore()
    assert store.get_access_token("nope") is None


def test_session_store_expired_pending_session_cannot_complete():
    store = SessionStore(ttl_seconds=0.001)
    token, state = store.create_pending()
    # Sleep past the TTL.
    import time
    time.sleep(0.01)
    assert store.complete(token, state, "gho_test") is False


def test_session_store_expired_completed_session_returns_none():
    store = SessionStore(ttl_seconds=0.001)
    token, state = store.create_pending()
    assert store.complete(token, state, "gho_test") is True
    import time
    time.sleep(0.01)
    assert store.get_access_token(token) is None


def test_verify_oauth_token_directly_with_injected_store():
    """The dependency is a regular callable; tests can call it directly."""
    store = SessionStore()
    token, state = store.create_pending()
    store.complete(token, state, "gho_direct_test")

    request = MagicMock(spec=Request)
    request.cookies = {SESSION_COOKIE_NAME: token}

    assert verify_oauth_token(request, store) == "gho_direct_test"
