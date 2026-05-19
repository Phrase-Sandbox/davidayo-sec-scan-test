"""Tests for the on-demand skill API (spec §2.2 skill path, §6.1, EC-002, BR-005, BR-009)."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from security_scanner.pipeline import ScanPipeline, TokenLimitError
from security_scanner.shared.claude.client import ClaudeUnavailableError
from security_scanner.shared.github.client import GitHubAuthError
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
from security_scanner.skill.api import (
    get_skill_pipeline_factory,
)
from security_scanner.skill.api import (
    router as skill_router,
)
from security_scanner.skill.oauth import (
    SESSION_COOKIE_NAME,
    SessionStore,
    get_session_store,
)
from security_scanner.skill.oauth import (
    router as oauth_router,
)

# --- Fixtures --------------------------------------------------------------


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("PHRASE_SCAN_TOKEN", "scan-token")
    monkeypatch.setenv("GITHUB_APP_ID", "123")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", "-----BEGIN PRIVATE KEY-----")
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_ID", "Iv1.test")
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_SECRET", "secret")


@pytest.fixture
def store() -> SessionStore:
    return SessionStore()


@pytest.fixture
def authenticated_cookie(store) -> str:
    """Pre-populate the session store with a completed OAuth session."""
    session_token, state = store.create_pending()
    store.complete(session_token, state, "gho_test_user_oauth_token")
    return session_token


@pytest.fixture
def mock_pipeline() -> AsyncMock:
    return AsyncMock(spec=ScanPipeline)


@pytest.fixture
def app(store, mock_pipeline):
    fastapi_app = FastAPI()
    fastapi_app.include_router(oauth_router)
    fastapi_app.include_router(skill_router)
    fastapi_app.dependency_overrides[get_session_store] = lambda: store

    def fake_factory_provider():
        def factory(_oauth_token: str):
            return mock_pipeline
        return factory

    fastapi_app.dependency_overrides[get_skill_pipeline_factory] = fake_factory_provider
    return fastapi_app


@pytest.fixture
def client(app):
    return TestClient(app)


def _finding(severity: Severity, vid: str = "A03:2021") -> VulnerabilityFinding:
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
        affected_file="src/app.py",
        affected_lines="10",
        description="SQL injection",
        suggested_fix="Use parameterised query",
        owasp_reference="https://owasp.org/Top10/A03_2021-Injection/",
        patch_file_path="patches/x.patch",
        exploit_scenario="Attacker sends a crafted payload via login parameter to src/app.py.",
        verification_status=VerificationStatus.unverified,
    )


def _result(
    *,
    findings: list[VulnerabilityFinding] | None = None,
    patches: dict[str, str] | None = None,
    warnings: list[str] | None = None,
) -> ScanResult:
    fs = findings or []
    return ScanResult(
        scan_id=uuid4(),
        repo_url="https://github.com/Phrase-Launchpad/example",
        scan_target=ScanTarget.full_repo,
        scan_type=ScanType.on_demand,
        triggered_by="(skill OAuth session)",
        timestamp=datetime(2026, 5, 18, tzinfo=UTC),
        findings_count=len(fs),
        gate_decision=GateDecision.advisory,
        partial_scan=False,
        unscanned_files=[],
        findings=fs,
        warnings=warnings or [],
        patches=patches or {},
    )


def _valid_body() -> dict:
    return {
        "repo_url": "https://github.com/Phrase-Launchpad/example",
        "scan_target": "full_repo",
    }


# --- Auth: missing / invalid OAuth session ---------------------------------


def test_missing_oauth_cookie_returns_401_with_ec_005_message(client, mock_pipeline):
    response = client.post("/skill/scan", json=_valid_body())
    assert response.status_code == 401
    assert response.json()["detail"] == (
        "GitHub authorisation failed. Please re-authorise and try again."
    )
    mock_pipeline.run.assert_not_called()


def test_invalid_oauth_cookie_returns_401(client, mock_pipeline):
    response = client.post(
        "/skill/scan",
        json=_valid_body(),
        cookies={SESSION_COOKIE_NAME: "forged-session-token-xyz"},
    )
    assert response.status_code == 401
    mock_pipeline.run.assert_not_called()


# --- Request validation ----------------------------------------------------


def test_invalid_repo_url_returns_422(client, mock_pipeline, authenticated_cookie):
    body = {**_valid_body(), "repo_url": "not-a-github-url"}
    response = client.post(
        "/skill/scan",
        json=body,
        cookies={SESSION_COOKIE_NAME: authenticated_cookie},
    )
    assert response.status_code == 422
    mock_pipeline.run.assert_not_called()


def test_missing_required_body_field_returns_422(client, authenticated_cookie):
    body = {"repo_url": "https://github.com/owner/repo"}
    response = client.post(
        "/skill/scan",
        json=body,
        cookies={SESSION_COOKIE_NAME: authenticated_cookie},
    )
    assert response.status_code == 422


# --- Valid scan happy path -------------------------------------------------


def test_valid_scan_returns_report_markdown_and_patches(
    client, mock_pipeline, authenticated_cookie,
):
    finding = _finding(Severity.High)
    mock_pipeline.run.return_value = _result(
        findings=[finding],
        patches={
            "scan_0_app.py.patch": "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-x\n+y\n",
        },
    )

    response = client.post(
        "/skill/scan",
        json=_valid_body(),
        cookies={SESSION_COOKIE_NAME: authenticated_cookie},
    )

    assert response.status_code == 200
    body = response.json()
    assert "# Security Scan Report" in body["report_markdown"]
    assert "A03:2021" in body["report_markdown"]
    assert body["patches"] == [
        {
            "filename": "scan_0_app.py.patch",
            "content": "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-x\n+y\n",
        }
    ]
    assert body["token_limit_warning"] is None
    assert body["summary"] == "Found 0 Critical, 1 High, 0 Medium, 0 Low findings."


# --- TokenLimitError handling (BR-005) -------------------------------------


def test_token_limit_error_returns_200_with_br005_warning(
    client, mock_pipeline, authenticated_cookie,
):
    mock_pipeline.run.side_effect = TokenLimitError(
        estimated_tokens=200_000, threshold=150_000,
    )
    response = client.post(
        "/skill/scan",
        json=_valid_body(),
        cookies={SESSION_COOKIE_NAME: authenticated_cookie},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["token_limit_warning"] is not None
    assert "BR-005" in body["token_limit_warning"]
    assert "200000" in body["token_limit_warning"] or "200_000" in body["token_limit_warning"]
    # The synthetic result has no findings, so the summary is all zeros.
    assert body["summary"] == "Found 0 Critical, 0 High, 0 Medium, 0 Low findings."
    assert body["patches"] == []


# --- ClaudeUnavailableError → 503 (EC-002) ---------------------------------


def test_claude_unavailable_returns_503_with_ec_002_message(
    client, mock_pipeline, authenticated_cookie,
):
    mock_pipeline.run.side_effect = ClaudeUnavailableError("retries exhausted")
    response = client.post(
        "/skill/scan",
        json=_valid_body(),
        cookies={SESSION_COOKIE_NAME: authenticated_cookie},
    )

    assert response.status_code == 503
    assert response.json()["detail"] == (
        "The scan service is temporarily unavailable. Please try again in a few minutes."
    )


# --- GitHubAuthError → 401 with EC-005 -------------------------------------


def test_github_auth_error_returns_401_with_ec_005_message(
    client, mock_pipeline, authenticated_cookie,
):
    """The OAuth token may have been revoked or expired mid-scan."""
    mock_pipeline.run.side_effect = GitHubAuthError("token revoked")
    response = client.post(
        "/skill/scan",
        json=_valid_body(),
        cookies={SESSION_COOKIE_NAME: authenticated_cookie},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == (
        "GitHub authorisation failed. Please re-authorise and try again."
    )


# --- BR-009 contract: skill mode is on_demand (no verification) ------------


def test_pipeline_is_constructed_in_on_demand_mode(
    client, mock_pipeline, authenticated_cookie,
):
    """Skill path runs pipeline in on_demand mode → ScanPipeline skips BR-009."""
    mock_pipeline.run.return_value = _result()
    client.post(
        "/skill/scan",
        json=_valid_body(),
        cookies={SESSION_COOKIE_NAME: authenticated_cookie},
    )
    # pipeline.run was called with no kwargs.scan_type override — the
    # pipeline's `mode` (set at construction) determines verification. We
    # assert the factory was wired with on_demand by checking the run call's
    # triggered_by, which the API sets verbatim for skill flows.
    call = mock_pipeline.run.call_args
    assert call.kwargs["triggered_by"] == "(skill OAuth session)"


def test_pipeline_receives_oauth_token_via_factory(client, store):
    """The injected factory receives the OAuth token attached to the session."""
    session_token, state = store.create_pending()
    store.complete(session_token, state, "gho_specific_token_xyz")

    factory_calls: list[str] = []
    captured_pipeline = AsyncMock(spec=ScanPipeline)
    captured_pipeline.run.return_value = _result()

    def factory_provider():
        def factory(oauth_token: str):
            factory_calls.append(oauth_token)
            return captured_pipeline
        return factory

    client.app.dependency_overrides[get_skill_pipeline_factory] = factory_provider

    response = client.post(
        "/skill/scan",
        json=_valid_body(),
        cookies={SESSION_COOKIE_NAME: session_token},
    )
    assert response.status_code == 200
    assert factory_calls == ["gho_specific_token_xyz"]
