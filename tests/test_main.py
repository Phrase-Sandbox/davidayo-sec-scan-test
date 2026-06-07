"""Service-shell tests — health probes, metrics endpoint, router mounting."""

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    """Settings need every required var to instantiate."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("PHRASE_SCAN_TOKEN", "scan-token")
    monkeypatch.setenv("GITHUB_APP_ID", "123")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", "-----BEGIN PRIVATE KEY-----")
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_ID", "Iv1.test")
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_SECRET", "secret")


@pytest.fixture
def client(_env):
    # Importing the app re-runs lifespan setup; reimport to pick up the
    # current env vars.
    from security_scanner.main import app
    with TestClient(app) as c:
        yield c


# --- Liveness / readiness --------------------------------------------------


def test_healthz_returns_200_with_ok_status(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readyz_returns_200_when_required_config_present(client):
    response = client.get("/readyz")
    assert response.status_code == 200
    assert response.json() == {"status": "ready"}


def test_readyz_returns_503_when_anthropic_key_missing(monkeypatch):
    """A missing required env var leaves get_settings() raising ValidationError.

    The readyz probe must catch that and return 503 — not crash. We run this
    test with a freshly imported app so the env-var deletion is in effect at
    request time.
    """
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    # Reload the app module so fixture state is consistent for this test.
    import importlib

    import security_scanner.main as main_mod
    importlib.reload(main_mod)

    # Lifespan startup will fail and SystemExit (sys.exit(1)).
    # We bypass lifespan by NOT using `with TestClient(...)`.
    raw_client = TestClient(main_mod.app, raise_server_exceptions=False)
    response = raw_client.get("/readyz")
    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "not ready"
    assert "ANTHROPIC_API_KEY" in body["reason"] or "config error" in body["reason"]


# --- Metrics ---------------------------------------------------------------


def test_metrics_endpoint_returns_prometheus_text_format(client):
    response = client.get("/metrics")
    assert response.status_code == 200
    body = response.text
    # Prometheus exposition format always lists declared metric metadata,
    # even when no observations have been made yet.
    assert "# HELP scan_requests_total" in body
    assert "# HELP claude_api_calls_total" in body
    assert "# HELP github_api_calls_total" in body
    assert "# HELP secrets_found_total" in body
    assert "# HELP findings_total" in body
    assert "# HELP scan_duration_seconds" in body


# --- Router mounting -------------------------------------------------------


def test_agent_router_is_mounted(client):
    # No auth header → 401 from the agent's verify_scan_token dependency,
    # which proves the route exists and the dependency ran.
    response = client.post("/agent/scan", json={})
    assert response.status_code in (401, 422)


# --- OpenAPI / schema sanity ----------------------------------------------


def test_openapi_schema_lists_all_routers(client):
    schema = client.get("/openapi.json").json()
    paths = set(schema["paths"])
    assert "/healthz" in paths
    assert "/readyz" in paths
    assert "/metrics" in paths
    assert "/agent/scan" in paths
    assert "/skill/scan" not in paths
    assert "/skill/oauth/callback" not in paths
    assert "/skill/oauth/init" not in paths
    assert "/agent/pr-event" not in paths
