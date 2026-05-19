"""Tests for the LOCAL_TEST_MODE-only ``/agent/test-scan`` endpoint."""

import importlib
from datetime import UTC, datetime
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from security_scanner.agent.test_endpoint import (
    _MockGitHubClient,
    get_test_pipeline_factory,
    router,
)
from security_scanner.pipeline import ScanPipeline, TokenLimitError
from security_scanner.shared.models.enums import (
    Confidence,
    GateDecision,
    ScanTarget,
    ScanType,
    Severity,
    VerificationStatus,
)
from security_scanner.shared.models.finding import VulnerabilityFinding
from security_scanner.shared.models.scan_result import ScanResult

_VALID_TOKEN = "test-mode-scan-token"  # noqa: S105 — test fixture


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("PHRASE_SCAN_TOKEN", _VALID_TOKEN)
    monkeypatch.setenv("GITHUB_APP_ID", "1")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", "-----BEGIN PRIVATE KEY-----")
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_ID", "Iv1.test")
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_SECRET", "secret")


@pytest.fixture
def mock_pipeline() -> AsyncMock:
    return AsyncMock(spec=ScanPipeline)


@pytest.fixture
def factory_calls() -> list[dict[str, str]]:
    return []


@pytest.fixture
def app(mock_pipeline, factory_calls):
    fastapi_app = FastAPI()
    fastapi_app.include_router(router)

    def factory_provider():
        def factory(mock_files: dict[str, str]):
            factory_calls.append(mock_files)
            return mock_pipeline
        return factory

    fastapi_app.dependency_overrides[get_test_pipeline_factory] = factory_provider
    return fastapi_app


@pytest.fixture
def client(app):
    return TestClient(app)


def _result(**overrides) -> ScanResult:
    base = {
        "scan_id": uuid4(),
        "repo_url": "https://github.com/Phrase-Launchpad/local-test",
        "scan_target": ScanTarget.full_repo,
        "scan_type": ScanType.deployment_gate,
        "triggered_by": "local-smoke-test",
        "timestamp": datetime(2026, 5, 18, tzinfo=UTC),
        "findings_count": 0,
        "gate_decision": GateDecision.advisory,
        "partial_scan": False,
        "unscanned_files": [],
        "findings": [],
        "warnings": [],
        "patches": {},
    }
    base.update(overrides)
    return ScanResult(**base)


def _finding(severity: Severity, vid: str) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        vulnerability_id=vid,
        severity=severity,
        confidence=Confidence.High,
        cvss_band={
            Severity.Critical: "9.0-10.0",
            Severity.High: "7.0-8.9",
            Severity.Medium: "4.0-6.9",
            Severity.Low: "0.1-3.9",
        }[severity],
        affected_file="src/handlers/query.py",
        affected_lines="6",
        description="x",
        suggested_fix="y",
        owasp_reference="https://owasp.org/Top10/A03_2021-Injection/",
        patch_file_path="patches/x.patch",
        exploit_scenario=(
            "Attacker sends a crafted payload via the username parameter "
            "to src/handlers/query.py bypassing the WHERE clause."
        ),
        verification_status=VerificationStatus.verified,
    )


def _valid_body() -> dict:
    return {
        "repo_url": "https://github.com/Phrase-Launchpad/local-test",
        "scan_target": "full_repo",
        "triggered_by": "local-smoke-test",
        "mock_files": {
            "src/handlers/query.py": "x = 1\n",
            "config/settings.py": "y = 2\n",
        },
    }


def _auth_header(token: str = _VALID_TOKEN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# --- Auth -----------------------------------------------------------------


def test_test_scan_requires_phrase_scan_token(client, mock_pipeline):
    response = client.post("/agent/test-scan", json=_valid_body())
    assert response.status_code == 401
    mock_pipeline.run.assert_not_called()


def test_test_scan_rejects_wrong_token(client, mock_pipeline):
    response = client.post(
        "/agent/test-scan",
        json=_valid_body(),
        headers=_auth_header("wrong"),
    )
    assert response.status_code == 401
    mock_pipeline.run.assert_not_called()


# --- mock_files passed through to pipeline (no GitHub fetch) --------------


def test_mock_files_passed_directly_to_pipeline_factory(
    client, mock_pipeline, factory_calls,
):
    mock_pipeline.run.return_value = _result()
    body = _valid_body()
    response = client.post("/agent/test-scan", json=body, headers=_auth_header())

    assert response.status_code == 200
    # The factory received the exact mock_files dict; no GitHub fetch logic
    # was reached.
    assert factory_calls == [body["mock_files"]]


def test_mock_github_client_returns_supplied_files():
    """``_MockGitHubClient`` is the duck-typed stand-in that bypasses HTTP.
    Both ``get_repo_files`` and ``get_diff_files`` return the supplied dict."""
    files = {"a.py": "x = 1\n", "b.py": "y = 2\n"}
    stub = _MockGitHubClient(files)
    assert stub.get_repo_files("owner", "repo") == files
    assert stub.get_repo_files("owner", "repo", ref="main", path="src") == files
    assert stub.get_diff_files("owner", "repo", "abc", "def") == files


# --- Body validation -----------------------------------------------------


def test_invalid_repo_url_returns_422(client, mock_pipeline):
    body = {**_valid_body(), "repo_url": "not-a-github-url"}
    response = client.post("/agent/test-scan", json=body, headers=_auth_header())
    assert response.status_code == 422
    mock_pipeline.run.assert_not_called()


def test_missing_mock_files_field_returns_422(client):
    body = _valid_body()
    del body["mock_files"]
    response = client.post("/agent/test-scan", json=body, headers=_auth_header())
    assert response.status_code == 422


# --- Response forwarding -------------------------------------------------


def test_test_scan_returns_scan_result_json_with_findings(client, mock_pipeline):
    mock_pipeline.run.return_value = _result(
        findings=[_finding(Severity.Critical, "SECRET-001")],
        findings_count=1,
        gate_decision=GateDecision.blocked,
    )
    response = client.post("/agent/test-scan", json=_valid_body(), headers=_auth_header())
    assert response.status_code == 200
    body = response.json()
    assert body["gate_decision"] == "blocked"
    assert body["findings_count"] == 1
    assert body["findings"][0]["vulnerability_id"] == "SECRET-001"


def test_token_limit_error_returns_advisory_with_warning(client, mock_pipeline):
    mock_pipeline.run.side_effect = TokenLimitError(
        estimated_tokens=200_000, threshold=150_000,
    )
    response = client.post(
        "/agent/test-scan", json=_valid_body(), headers=_auth_header(),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["gate_decision"] == "advisory"
    assert any("BR-005" in w for w in body["warnings"])


# --- main.py conditional mount ------------------------------------------


def test_test_endpoint_is_not_mounted_when_local_test_mode_is_false(monkeypatch):
    """If LOCAL_TEST_MODE is unset (or anything other than 'true'), the test
    endpoint must NOT appear in the application's route table."""
    monkeypatch.delenv("LOCAL_TEST_MODE", raising=False)
    import security_scanner.main as main_mod  # noqa: PLC0415
    importlib.reload(main_mod)
    paths = {route.path for route in main_mod.app.router.routes}
    assert "/agent/test-scan" not in paths
    assert "/agent/scan" in paths  # the real scan endpoint is still there


def test_test_endpoint_is_mounted_when_local_test_mode_is_true(monkeypatch):
    monkeypatch.setenv("LOCAL_TEST_MODE", "true")
    import security_scanner.main as main_mod  # noqa: PLC0415
    importlib.reload(main_mod)
    paths = {route.path for route in main_mod.app.router.routes}
    assert "/agent/test-scan" in paths
    # Clean up so other tests get the default app.
    monkeypatch.delenv("LOCAL_TEST_MODE", raising=False)
    importlib.reload(main_mod)
