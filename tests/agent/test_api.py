"""Tests for the deployment-gate API (spec §7.1, §7.3, EC-006, §2.2 gate path)."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from security_scanner.agent.api import get_pipeline, router
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

# --- Fixtures --------------------------------------------------------------


_VALID_TOKEN = "phrase-scan-token-secret"  # noqa: S105 — test fixture, not a real credential


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    """Set every env var Settings requires so get_settings() doesn't error out."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("PHRASE_SCAN_TOKEN", _VALID_TOKEN)
    monkeypatch.setenv("GITHUB_APP_ID", "123")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", "-----BEGIN PRIVATE KEY-----")
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_ID", "Iv1.test")
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_SECRET", "secret")


@pytest.fixture
def app():
    app = FastAPI()
    app.include_router(router)
    return app


def _make_pipeline(*, run_result=None, run_side_effect=None) -> AsyncMock:
    mock = AsyncMock(spec=ScanPipeline)
    if run_side_effect is not None:
        mock.run.side_effect = run_side_effect
    else:
        mock.run.return_value = run_result
    return mock


def _result(
    *,
    gate_decision: GateDecision = GateDecision.pass_,
    findings: list[VulnerabilityFinding] | None = None,
    warnings: list[str] | None = None,
) -> ScanResult:
    fs = findings or []
    return ScanResult(
        scan_id=uuid4(),
        repo_url="https://github.com/Phrase-Launchpad/example",
        scan_target=ScanTarget.full_repo,
        scan_type=ScanType.deployment_gate,
        triggered_by="alice@phrase.com",
        timestamp=datetime(2026, 5, 18, tzinfo=UTC),
        findings_count=len(fs),
        gate_decision=gate_decision,
        partial_scan=False,
        unscanned_files=[],
        findings=fs,
        warnings=warnings or [],
    )


def _blocking_finding() -> VulnerabilityFinding:
    return VulnerabilityFinding(
        vulnerability_id="A03:2021",
        severity=Severity.High,
        confidence=Confidence.High,
        cvss_band="7.0-8.9",
        affected_file="src/handlers/login.py",
        affected_lines="42-55",
        description="SQL injection.",
        suggested_fix="Use a parameterised query.",
        owasp_reference="https://owasp.org/Top10/A03_2021-Injection/",
        patch_file_path="patches/A03-2021.patch",
        exploit_scenario=(
            "Attacker sends username=admin' OR '1'='1 as a login payload to "
            "src/handlers/login.py bypassing the WHERE clause."
        ),
        verification_status=VerificationStatus.verified,
    )


def _valid_body() -> dict:
    return {
        "repo_url": "https://github.com/Phrase-Launchpad/example",
        "scan_target": "full_repo",
        "triggered_by": "alice@phrase.com",
    }


def _auth_header(token: str = _VALID_TOKEN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _override_pipeline(app: FastAPI, pipeline) -> None:
    app.dependency_overrides[get_pipeline] = lambda: pipeline


# --- Authentication --------------------------------------------------------


def test_valid_token_returns_200(app):
    _override_pipeline(app, _make_pipeline(run_result=_result()))
    client = TestClient(app)

    response = client.post("/agent/scan", json=_valid_body(), headers=_auth_header())
    assert response.status_code == 200


def test_invalid_token_returns_401_with_techops_message(app):
    _override_pipeline(app, _make_pipeline(run_result=_result()))
    client = TestClient(app)

    response = client.post("/agent/scan", json=_valid_body(), headers=_auth_header("wrong"))
    assert response.status_code == 401
    assert response.json()["detail"] == (
        "Security scan authentication failed. Contact TechOps."
    )


def test_missing_authorization_header_returns_401(app):
    _override_pipeline(app, _make_pipeline(run_result=_result()))
    client = TestClient(app)

    response = client.post("/agent/scan", json=_valid_body())
    assert response.status_code == 401


def test_wrong_scheme_returns_401(app):
    _override_pipeline(app, _make_pipeline(run_result=_result()))
    client = TestClient(app)

    response = client.post(
        "/agent/scan",
        json=_valid_body(),
        headers={"Authorization": f"Basic {_VALID_TOKEN}"},
    )
    assert response.status_code == 401


# --- Repo URL validation ---------------------------------------------------


@pytest.mark.parametrize(
    "bad_url",
    [
        "not-a-url",
        "http://github.com/owner/repo",  # http not https
        "https://gitlab.com/owner/repo",
        "https://github.com/onlyowner",
        "https://example.com/owner/repo",
    ],
)
def test_invalid_repo_url_returns_422(app, bad_url):
    _override_pipeline(app, _make_pipeline(run_result=_result()))
    client = TestClient(app)

    body = {**_valid_body(), "repo_url": bad_url}
    response = client.post("/agent/scan", json=body, headers=_auth_header())
    assert response.status_code == 422


def test_missing_required_field_returns_422(app):
    _override_pipeline(app, _make_pipeline(run_result=_result()))
    client = TestClient(app)

    body = {"repo_url": "https://github.com/owner/repo", "scan_target": "full_repo"}
    # No triggered_by.
    response = client.post("/agent/scan", json=body, headers=_auth_header())
    assert response.status_code == 422


# --- Body / pipeline interaction -------------------------------------------


def test_scan_returns_blocked_decision_in_200_body(app):
    pipeline = _make_pipeline(
        run_result=_result(
            gate_decision=GateDecision.blocked,
            findings=[_blocking_finding()],
        ),
    )
    _override_pipeline(app, pipeline)
    client = TestClient(app)

    response = client.post("/agent/scan", json=_valid_body(), headers=_auth_header())
    # Gate decisions are communicated in the BODY, not the HTTP status —
    # §7.3 / build-plan resolved-question on sync calls.
    assert response.status_code == 200
    body = response.json()
    assert body["gate_decision"] == "blocked"
    assert body["findings_count"] == 1


def test_claude_unavailable_produces_advisory_200(app):
    """Pipeline catches ClaudeUnavailableError on gate path (BR-006) and returns
    a ``GateDecision.advisory`` ScanResult. The API just propagates it."""
    pipeline = _make_pipeline(run_result=_result(gate_decision=GateDecision.advisory))
    _override_pipeline(app, pipeline)
    client = TestClient(app)

    response = client.post("/agent/scan", json=_valid_body(), headers=_auth_header())
    assert response.status_code == 200
    body = response.json()
    assert body["gate_decision"] == "advisory"


def test_token_limit_error_translates_to_200_advisory_with_warning(app):
    pipeline = _make_pipeline(
        run_side_effect=TokenLimitError(estimated_tokens=200_000, threshold=150_000),
    )
    _override_pipeline(app, pipeline)
    client = TestClient(app)

    response = client.post("/agent/scan", json=_valid_body(), headers=_auth_header())
    assert response.status_code == 200
    body = response.json()
    assert body["gate_decision"] == "advisory"
    assert body["findings"] == []
    assert any("BR-005" in w or "scan size limit" in w for w in body["warnings"])


# --- Endpoint passes through to the pipeline correctly ---------------------


def test_pipeline_called_with_request_body_values(app):
    pipeline = _make_pipeline(run_result=_result())
    _override_pipeline(app, pipeline)
    client = TestClient(app)

    body = {
        **_valid_body(),
        "scan_target": "diff",
        "base": "abc",
        "head": "def",
    }
    client.post("/agent/scan", json=body, headers=_auth_header())

    call = pipeline.run.call_args
    assert call.kwargs["repo_url"] == body["repo_url"]
    assert call.kwargs["scan_target"] == ScanTarget.diff
    assert call.kwargs["base"] == "abc"
    assert call.kwargs["head"] == "def"
    assert call.kwargs["triggered_by"] == body["triggered_by"]


# --- GET /agent/config/slack-webhook ---------------------------------------


def test_slack_webhook_config_returns_env_fallback(app, monkeypatch):
    """When no org settings exist, the endpoint returns the env-var webhook."""
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/test/env")
    client = TestClient(app)
    response = client.get("/agent/config/slack-webhook", headers=_auth_header())
    assert response.status_code == 200
    assert response.json()["webhook_url"] == "https://hooks.slack.com/services/test/env"


def test_slack_webhook_config_returns_null_when_not_configured(app, monkeypatch):
    """When neither DB nor env var is set, webhook_url is null."""
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    client = TestClient(app)
    response = client.get("/agent/config/slack-webhook", headers=_auth_header())
    assert response.status_code == 200
    assert response.json()["webhook_url"] is None


def test_slack_webhook_config_requires_auth(app):
    """Unauthenticated requests are rejected with 401."""
    client = TestClient(app)
    response = client.get("/agent/config/slack-webhook")
    assert response.status_code == 401
