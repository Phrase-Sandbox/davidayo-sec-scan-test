"""Tests for POST /scan/local — two-channel architecture (D-12).

Proves the jurisdiction boundary: distinct token, no gate_decision, never
enforces. Tests the registry-mode (user_email-based) path where the server
loads the user's stored LLM settings from the DB instead of reading an
inline API key from the request body.
"""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from security_scanner.agent.api import get_pipeline
from security_scanner.agent.api import router as agent_router
from security_scanner.agent.local_scan import (
    AuthenticatedLocalCaller,
    verify_local_scan_token,
)
from security_scanner.agent.local_scan import (
    router as local_router,
)
from security_scanner.pipeline import ScanPipeline
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

_LOCAL_TOKEN = "local-advisory-token"  # noqa: S105 — test fixture
_CI_TOKEN = "ci-gate-token"  # noqa: S105 — test fixture
_USER_EMAIL = "dev@phrase.com"
_TOKEN_ID = "tok_abc123"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("LOCAL_SCAN_TOKEN", _LOCAL_TOKEN)
    monkeypatch.setenv("PHRASE_SCAN_TOKEN", _CI_TOKEN)
    monkeypatch.setenv("GITHUB_APP_ID", "1")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", "-----BEGIN PRIVATE KEY-----")
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_ID", "Iv1.test")
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_SECRET", "secret")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding(severity: Severity) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        vulnerability_id="A03:2021",
        severity=severity,
        confidence=Confidence.High,
        cvss_band={
            Severity.Critical: "9.0-10.0",
            Severity.High: "7.0-8.9",
            Severity.Medium: "4.0-6.9",
            Severity.Low: "0.1-3.9",
        }[severity],
        affected_file="app/db.py",
        affected_lines="6",
        description="SQL injection via string concatenation",
        suggested_fix="use parameterised queries",
        owasp_reference="https://owasp.org/Top10/A03_2021-Injection/",
        patch_file_path="patches/x.patch",
        exploit_scenario=(
            "Attacker sends a crafted payload via the username parameter to "
            "app/db.py bypassing the WHERE clause."
        ),
        verification_status=VerificationStatus.unverified,
    )


def _result(findings, *, gate_decision=GateDecision.advisory, warnings=None) -> ScanResult:
    return ScanResult(
        scan_id=uuid4(),
        repo_url="https://github.com/local/workspace",
        scan_target=ScanTarget.full_repo,
        scan_type=ScanType.on_demand,
        triggered_by="local-dev",
        timestamp=datetime(2026, 5, 19, tzinfo=UTC),
        findings_count=len(findings),
        gate_decision=gate_decision,
        partial_scan=False,
        unscanned_files=[],
        findings=findings,
        warnings=warnings or [],
        patches={},
    )


def _mock_user_llm_settings(provider: str = "anthropic", model: str = "claude-sonnet-4-6"):
    """Build a minimal mock UserLLMSettings ORM row."""
    from security_scanner.tokens.models import LLMProvider

    row = MagicMock()
    row.provider = LLMProvider.anthropic if provider == "anthropic" else LLMProvider.google
    row.model = model
    row.encrypted_api_key = b"fake-encrypted-key"
    return row


def _patch_scan_deps(mock_pipeline, monkeypatch, *, provider="anthropic"):
    """Patch the five collaborators scan_local() calls internally.

    Allows tests to control what the pipeline returns without touching the DB,
    Fernet crypto, or ``build_user_llm_client``.
    """
    monkeypatch.setattr(
        "security_scanner.agent.local_scan._load_user_llm_settings",
        AsyncMock(return_value=_mock_user_llm_settings(provider)),
    )
    # Admin model lookup: return None (provider uses its own default) so
    # existing tests don't need to worry about model selection.
    monkeypatch.setattr(
        "security_scanner.agent.local_scan._load_active_org_settings",
        AsyncMock(return_value=None),
    )
    monkeypatch.setattr(
        "security_scanner.tokens.crypto.decrypt",
        lambda _: "sk-ant-decrypted",
    )
    monkeypatch.setattr(
        "security_scanner.agent.local_scan.build_user_llm_client",
        lambda *_a, **_kw: MagicMock(),
    )
    monkeypatch.setattr(
        "security_scanner.agent.local_scan.ScanPipeline",
        lambda *_a, **_kw: mock_pipeline,
    )
    monkeypatch.setattr(
        "security_scanner.agent.local_scan._persist_scan_data",
        AsyncMock(),
    )


@pytest.fixture
def mock_pipeline() -> AsyncMock:
    pipeline = AsyncMock(spec=ScanPipeline)
    pipeline._github = MagicMock()
    pipeline._mode = ScanType.on_demand
    return pipeline


@pytest.fixture
def client(mock_pipeline):
    """FastAPI test client with auth + pipeline + persistence mocked out.

    Auth dep is overridden to return a registry-mode caller with a real
    user_email so individual tests focus on behaviour after auth succeeds.
    Tests that need to exercise the auth layer create their own bare app.
    """
    app = FastAPI()
    app.include_router(local_router)
    app.include_router(agent_router)

    def mock_auth():
        return AuthenticatedLocalCaller(
            token=_LOCAL_TOKEN,
            token_id=_TOKEN_ID,
            user_email=_USER_EMAIL,
        )

    app.dependency_overrides[verify_local_scan_token] = mock_auth
    app.dependency_overrides[get_pipeline] = lambda: mock_pipeline
    return TestClient(app)


def _post(client, *, token: str | None = _LOCAL_TOKEN, **body):
    payload = {
        "files": {"app/db.py": "q = 'SELECT '+u"},
        "repo_url": "https://github.com/local/workspace",
        **body,
    }
    return client.post(
        "/scan/local",
        json=payload,
        headers={"Authorization": f"Bearer {token}"} if token else {},
    )


# ---------------------------------------------------------------------------
# Happy-path
# ---------------------------------------------------------------------------


def test_local_scan_returns_report_and_NO_gate_decision(client, mock_pipeline, monkeypatch):
    """Response model has no gate_decision — structurally cannot enforce."""
    _patch_scan_deps(mock_pipeline, monkeypatch)
    mock_pipeline.run.return_value = _result([_finding(Severity.High)])
    r = _post(client)
    assert r.status_code == 200, r.text
    body = r.json()
    assert "gate_decision" not in body
    assert body["markdown"].startswith("# Security Scan Report")
    assert body["high"] == 1 and body["findings_count"] == 1


def test_severity_counts(client, mock_pipeline, monkeypatch):
    _patch_scan_deps(mock_pipeline, monkeypatch)
    mock_pipeline.run.return_value = _result(
        [_finding(Severity.Critical), _finding(Severity.High), _finding(Severity.Low)]
    )
    body = _post(client).json()
    assert (body["critical"], body["high"], body["low"]) == (1, 1, 1)


# ---------------------------------------------------------------------------
# LLM settings — 412 when not configured
# ---------------------------------------------------------------------------


def test_no_llm_settings_returns_412(client, monkeypatch):
    """User hasn't saved LLM settings yet → 412 with a portal pointer."""
    from fastapi import HTTPException

    monkeypatch.setattr(
        "security_scanner.agent.local_scan._load_user_llm_settings",
        AsyncMock(
            side_effect=HTTPException(
                status_code=412,
                detail=(
                    "No LLM provider configured for your account. "
                    "Visit /portal/settings to choose a provider and save your API key."
                ),
            )
        ),
    )
    r = _post(client)
    assert r.status_code == 412
    assert "/portal/settings" in r.json()["detail"]


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------


def test_scan_failed_returns_502_with_detail(client, mock_pipeline, monkeypatch):
    """Mid-scan LLM parse failure → 502, NOT a silent 200/0-findings."""
    _patch_scan_deps(mock_pipeline, monkeypatch)
    mock_pipeline.run.return_value = _result(
        [],
        gate_decision=GateDecision.scan_failed,
        warnings=["Claude response could not be parsed: Unterminated string"],
    )
    r = _post(client)
    assert r.status_code == 502
    detail = r.json()["detail"]
    assert detail["error"] == "scanner_upstream_error"
    assert "Unterminated string" in detail["message"]
    assert "scan_id" in detail


def test_llm_quota_exhausted_returns_502(client, mock_pipeline, monkeypatch):
    """BYO-key LLM quota exhausted → 502 + quota error code. No Slack alert."""
    _patch_scan_deps(mock_pipeline, monkeypatch)
    mock_pipeline.run.return_value = _result(
        [],
        gate_decision=GateDecision.advisory,
        warnings=["LLM upstream unavailable: RESOURCE_EXHAUSTED quota exceeded"],
    )
    r = _post(client)
    assert r.status_code == 502
    detail = r.json()["detail"]
    assert detail["error"] == "llm_quota_exhausted"
    assert detail["provider"] == "anthropic"
    assert "RESOURCE_EXHAUSTED" in detail["message"]


def test_llm_unavailable_non_quota_returns_502(client, mock_pipeline, monkeypatch):
    """BYO-key non-quota LLM failure → 502 + generic unavailable code."""
    _patch_scan_deps(mock_pipeline, monkeypatch)
    mock_pipeline.run.return_value = _result(
        [],
        gate_decision=GateDecision.advisory,
        warnings=["LLM upstream unavailable: connection refused"],
    )
    r = _post(client)
    assert r.status_code == 502
    detail = r.json()["detail"]
    assert detail["error"] == "llm_upstream_unavailable"


def test_empty_files_rejected(client, monkeypatch):
    monkeypatch.setattr(
        "security_scanner.agent.local_scan._load_user_llm_settings",
        AsyncMock(return_value=_mock_user_llm_settings()),
    )
    r = client.post(
        "/scan/local",
        json={"files": {}, "repo_url": "https://github.com/local/workspace"},
        headers={"Authorization": f"Bearer {_LOCAL_TOKEN}"},
    )
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# CI / agent-scan gate tests
# ---------------------------------------------------------------------------


def test_agent_scan_failed_streams_body(client, mock_pipeline):
    """scan_failed is returned as HTTP 200 with gate_decision in the body.

    The endpoint streams heartbeat newlines while the scan runs, so it cannot
    return HTTP 502 after headers are sent.  evaluate-findings reads
    gate_decision from the JSON body and fails the CI job instead.
    """
    mock_pipeline.run.return_value = _result(
        [],
        gate_decision=GateDecision.scan_failed,
        warnings=["Claude response could not be parsed: Unterminated string"],
    )
    r = client.post(
        "/agent/scan",
        json={
            "repo_url": "https://github.com/local/x",
            "scan_target": "full_repo",
            "triggered_by": "ci",
        },
        headers={"Authorization": f"Bearer {_CI_TOKEN}"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["gate_decision"] == "scan_failed"
    assert "Claude response could not be parsed" in body["warnings"][0]


# ---------------------------------------------------------------------------
# Auth boundary — separate bare apps (no auth override)
# ---------------------------------------------------------------------------


def _bare_local_app():
    app = FastAPI()
    app.include_router(local_router)
    return TestClient(app)


def _bare_agent_app():
    app = FastAPI()
    app.include_router(agent_router)
    return TestClient(app)


def test_ci_token_cannot_reach_local_jurisdiction(monkeypatch):
    """CI gate token must NOT be accepted at /scan/local (jurisdiction boundary)."""
    monkeypatch.setenv("USE_TOKEN_REGISTRY", "false")
    tc = _bare_local_app()
    r = tc.post(
        "/scan/local",
        json={"files": {"a.py": "x"}, "repo_url": "https://github.com/local/workspace"},
        headers={"Authorization": f"Bearer {_CI_TOKEN}"},
    )
    assert r.status_code == 401


def test_missing_token_rejected(monkeypatch):
    """No Authorization header → 401."""
    monkeypatch.setenv("USE_TOKEN_REGISTRY", "false")
    tc = _bare_local_app()
    r = tc.post(
        "/scan/local",
        json={"files": {"a.py": "x"}, "repo_url": "https://github.com/local/workspace"},
    )
    assert r.status_code == 401


def test_local_endpoint_disabled_when_token_unset(monkeypatch):
    """LOCAL_SCAN_TOKEN unset → every call 401s (endpoint effectively disabled)."""
    monkeypatch.setenv("USE_TOKEN_REGISTRY", "false")
    monkeypatch.delenv("LOCAL_SCAN_TOKEN", raising=False)
    tc = _bare_local_app()
    r = tc.post(
        "/scan/local",
        json={"files": {"a.py": "x"}, "repo_url": "https://github.com/local/workspace"},
        headers={"Authorization": f"Bearer {_LOCAL_TOKEN}"},
    )
    assert r.status_code == 401


def test_local_token_cannot_reach_ci_gate():
    """Local-advisory token must NOT pass the CI gate."""
    tc = _bare_agent_app()
    r = tc.post(
        "/agent/scan",
        json={
            "repo_url": "https://github.com/local/x",
            "scan_target": "full_repo",
            "triggered_by": "x",
        },
        headers={"Authorization": f"Bearer {_LOCAL_TOKEN}"},
    )
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# Backpressure
# ---------------------------------------------------------------------------


def test_content_length_over_cap_returns_413(client):
    """Fast-path reject before the body is read into memory."""
    r = client.post(
        "/scan/local",
        content=b'{"files": {"x": "y"}, "triggered_by": "t", "repo_url": "https://github.com/x/y"}',
        headers={
            "Authorization": f"Bearer {_LOCAL_TOKEN}",
            "Content-Length": str(200 * 1024 * 1024),  # 200 MB
        },
    )
    assert r.status_code == 413
    assert "Use --directory" in r.json()["detail"]


def test_max_concurrent_scans_env_var_override(monkeypatch):
    """The concurrency cap is tunable via MAX_CONCURRENT_SCANS."""
    from security_scanner.agent.local_scan import _read_max_concurrent_scans

    monkeypatch.setenv("MAX_CONCURRENT_SCANS", "12")
    assert _read_max_concurrent_scans() == 12

    monkeypatch.setenv("MAX_CONCURRENT_SCANS", "200")  # clamped to 64
    assert _read_max_concurrent_scans() == 64

    monkeypatch.setenv("MAX_CONCURRENT_SCANS", "-3")  # clamped to 1
    assert _read_max_concurrent_scans() == 1

    monkeypatch.setenv("MAX_CONCURRENT_SCANS", "not-a-number")  # falls back
    assert _read_max_concurrent_scans() == 4

    monkeypatch.delenv("MAX_CONCURRENT_SCANS", raising=False)
    assert _read_max_concurrent_scans() == 4


def test_returns_429_when_semaphore_is_drained(client):
    """Saturate the semaphore → 429 with Retry-After."""
    import security_scanner.agent.local_scan as ls_mod

    for _ in range(ls_mod._MAX_CONCURRENT_SCANS):
        ls_mod._scan_semaphore._value -= 1
    try:
        r = client.post(
            "/scan/local",
            json={
                "files": {"x.py": "print(1)"},
                "triggered_by": "tester",
                "repo_url": "https://github.com/x/y",
            },
            headers={"Authorization": f"Bearer {_LOCAL_TOKEN}"},
        )
    finally:
        for _ in range(ls_mod._MAX_CONCURRENT_SCANS):
            ls_mod._scan_semaphore._value += 1
    assert r.status_code == 429
    assert r.headers["Retry-After"] == "10"
    assert "at capacity" in r.json()["detail"]
