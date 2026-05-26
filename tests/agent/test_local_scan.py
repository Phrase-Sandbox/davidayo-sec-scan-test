"""Tests for the local-advisory jurisdiction — POST /scan/local (D-12).

Proves the jurisdiction boundary: distinct token, no gate_decision, never
enforces. Mirrors the test_endpoint test style.
"""

from datetime import UTC, datetime
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from security_scanner.agent.api import get_pipeline
from security_scanner.agent.api import router as agent_router
from security_scanner.agent.local_scan import get_local_pipeline_factory
from security_scanner.agent.local_scan import router as local_router
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


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("LOCAL_SCAN_TOKEN", _LOCAL_TOKEN)
    monkeypatch.setenv("PHRASE_SCAN_TOKEN", _CI_TOKEN)
    monkeypatch.setenv("GITHUB_APP_ID", "1")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", "-----BEGIN PRIVATE KEY-----")
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_ID", "Iv1.test")
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_SECRET", "secret")


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


@pytest.fixture
def mock_pipeline() -> AsyncMock:
    return AsyncMock(spec=ScanPipeline)


@pytest.fixture
def client(mock_pipeline):
    app = FastAPI()
    app.include_router(local_router)
    app.include_router(agent_router)

    def factory_provider():
        return lambda files, llm_override: mock_pipeline  # noqa: ARG005

    app.dependency_overrides[get_local_pipeline_factory] = factory_provider
    app.dependency_overrides[get_pipeline] = lambda: mock_pipeline
    return TestClient(app)


def _post(client, token, **body):
    payload = {"files": {"app/db.py": "q = 'SELECT '+u"}, **body}
    return client.post(
        "/scan/local",
        json=payload,
        headers={"Authorization": f"Bearer {token}"} if token else {},
    )


def test_local_scan_returns_report_and_NO_gate_decision(client, mock_pipeline):
    mock_pipeline.run.return_value = _result([_finding(Severity.High)])
    r = _post(client, _LOCAL_TOKEN)
    assert r.status_code == 200
    body = r.json()
    assert "gate_decision" not in body  # structurally cannot enforce
    assert body["markdown"].startswith("# Security Scan Report")
    assert body["high"] == 1 and body["findings_count"] == 1


def test_severity_counts(client, mock_pipeline):
    mock_pipeline.run.return_value = _result(
        [_finding(Severity.Critical), _finding(Severity.High), _finding(Severity.Low)]
    )
    body = _post(client, _LOCAL_TOKEN).json()
    assert (body["critical"], body["high"], body["low"]) == (1, 1, 1)


def test_ci_token_cannot_reach_local_jurisdiction(client):
    # The CI gate token must NOT be accepted here (jurisdiction boundary).
    assert _post(client, _CI_TOKEN).status_code == 401


def test_missing_token_rejected(client):
    assert _post(client, None).status_code == 401


def test_local_endpoint_disabled_when_token_unset(client, monkeypatch):
    monkeypatch.delenv("LOCAL_SCAN_TOKEN", raising=False)
    assert _post(client, _LOCAL_TOKEN).status_code == 401


def test_empty_files_rejected(client, mock_pipeline):
    mock_pipeline.run.return_value = _result([])
    r = client.post(
        "/scan/local",
        json={"files": {}},
        headers={"Authorization": f"Bearer {_LOCAL_TOKEN}"},
    )
    assert r.status_code == 422


def _result_llm_unavailable(reason="quota exceeded for model gemini-2.5-flash") -> ScanResult:
    """A pipeline result mirroring the 'LLM totally unavailable' path —
    every file unscanned, structured warning, advisory gate decision."""
    return ScanResult(
        scan_id=uuid4(),
        repo_url="https://github.com/local/workspace",
        scan_target=ScanTarget.full_repo,
        scan_type=ScanType.on_demand,
        triggered_by="local-dev",
        timestamp=datetime(2026, 5, 26, tzinfo=UTC),
        findings_count=0,
        gate_decision=GateDecision.advisory,
        partial_scan=True,
        unscanned_files=["app/db.py"],
        findings=[],
        warnings=[f"LLM upstream unavailable: {reason}"],
        patches={},
    )


def test_byo_key_llm_quota_exhausted_returns_502_quota_error(client, mock_pipeline, monkeypatch):
    """--local + LLM totally unavailable + quota in reason → HTTP 502 + quota error code."""
    mock_pipeline.run.return_value = _result_llm_unavailable(
        "Gemini unavailable after 2 attempts: RESOURCE_EXHAUSTED quota exceeded"
    )
    # Slack helper must NOT fire on the BYO-key path.
    slack_called = {"n": 0}

    async def fake_slack(*_a, **_kw):
        slack_called["n"] += 1

    monkeypatch.setattr(
        "security_scanner.agent.local_scan.send_llm_unavailable_alert",
        fake_slack,
    )

    r = client.post(
        "/scan/local",
        json={
            "files": {"app/db.py": "x = 1"},
            "llm_override": {
                "provider": "gemini",
                "api_key": "AIza-fake",
                "model": "gemini-2.5-flash",
            },
        },
        headers={"Authorization": f"Bearer {_LOCAL_TOKEN}"},
    )
    assert r.status_code == 502, r.text
    detail = r.json()["detail"]
    assert detail["error"] == "llm_quota_exhausted"
    assert detail["provider"] == "gemini"
    assert "RESOURCE_EXHAUSTED" in detail["message"]
    assert slack_called["n"] == 0  # BYO-key path must not Slack-notify


def test_default_mode_llm_unavailable_keeps_advisory_and_sends_slack(client, mock_pipeline, monkeypatch):
    """Default mode (no llm_override): keep advisory result, send Slack alert
    to security so the org key gets topped up."""
    mock_pipeline.run.return_value = _result_llm_unavailable(
        "Claude unavailable after 3 attempts: rate limited (429); waited 8.0s"
    )
    captured: dict[str, object] = {}

    async def fake_slack(**kw):
        captured.update(kw)

    monkeypatch.setattr(
        "security_scanner.agent.local_scan.send_llm_unavailable_alert",
        fake_slack,
    )

    r = _post(client, _LOCAL_TOKEN)  # default mode: no llm_override in body
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["findings_count"] == 0  # advisory partial — no findings
    # Slack was notified with the upstream reason.
    assert captured.get("scan_id")
    assert "rate limited" in str(captured.get("reason"))
    assert captured.get("triggered_by") == "local-dev"


def test_scan_failed_returns_502_with_detail(client, mock_pipeline):
    """Mid-scan LLM parse failure → HTTP 502, NOT a silent 200/0-findings."""
    mock_pipeline.run.return_value = _result(
        [],
        gate_decision=GateDecision.scan_failed,
        warnings=["Claude response could not be parsed: Unterminated string"],
    )
    r = _post(client, _LOCAL_TOKEN)
    assert r.status_code == 502
    detail = r.json()["detail"]
    assert detail["error"] == "scanner_upstream_error"
    assert "Unterminated string" in detail["message"]
    assert "scan_id" in detail


def test_agent_scan_failed_returns_502(client, mock_pipeline):
    """Same surfacing on the gate endpoint — CI sees an explicit failure."""
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
    assert r.status_code == 502
    detail = r.json()["detail"]
    assert detail["error"] == "scanner_upstream_error"


def test_local_token_cannot_reach_ci_gate(client):
    # The reverse boundary: the local-advisory token must NOT pass the CI gate.
    r = client.post(
        "/agent/scan",
        json={
            "repo_url": "https://github.com/local/x",
            "scan_target": "full_repo",
            "triggered_by": "x",
        },
        headers={"Authorization": f"Bearer {_LOCAL_TOKEN}"},
    )
    assert r.status_code == 401


# --- Backpressure: payload cap, concurrency cap ---------------------------


def test_content_length_over_cap_returns_413(client):
    """Fast-path reject before we read the body."""
    # Send a real (small) body but lie about Content-Length so we don't
    # actually have to transfer 100+ MB through the test client.
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
    """The cap is tunable for higher Anthropic tiers via env var."""
    from security_scanner.agent.local_scan import _read_max_concurrent_scans

    monkeypatch.setenv("MAX_CONCURRENT_SCANS", "12")
    assert _read_max_concurrent_scans() == 12

    monkeypatch.setenv("MAX_CONCURRENT_SCANS", "200")  # clamped down to 64
    assert _read_max_concurrent_scans() == 64

    monkeypatch.setenv("MAX_CONCURRENT_SCANS", "-3")  # clamped up to 1
    assert _read_max_concurrent_scans() == 1

    monkeypatch.setenv("MAX_CONCURRENT_SCANS", "not-a-number")  # falls back
    assert _read_max_concurrent_scans() == 4

    monkeypatch.delenv("MAX_CONCURRENT_SCANS", raising=False)
    assert _read_max_concurrent_scans() == 4


def test_get_local_pipeline_factory_no_override_uses_org_creds(monkeypatch):
    """Factory with llm_override=None → uses settings via build_llm_client."""
    from unittest.mock import MagicMock, patch

    fake_llm = MagicMock()
    with (
        patch(
            "security_scanner.agent.local_scan.build_llm_client",
            return_value=fake_llm,
        ) as mock_org_factory,
        patch(
            "security_scanner.agent.local_scan.build_local_llm_client",
        ) as mock_byo_factory,
    ):
        from security_scanner.agent.local_scan import get_local_pipeline_factory
        from security_scanner.shared.config import Settings

        settings = Settings()
        pipeline_factory = get_local_pipeline_factory(settings)
        assert callable(pipeline_factory)
        pipeline_factory({"a.py": "print(1)"}, None)
        mock_org_factory.assert_called_once_with(settings)
        mock_byo_factory.assert_not_called()


def test_get_local_pipeline_factory_with_override_uses_caller_key(monkeypatch):
    """Factory with llm_override set → uses build_local_llm_client w/ caller key."""
    from unittest.mock import MagicMock, patch

    from security_scanner.agent.local_scan import LLMOverride

    fake_llm = MagicMock()
    with (
        patch(
            "security_scanner.agent.local_scan.build_local_llm_client",
            return_value=fake_llm,
        ) as mock_byo_factory,
        patch(
            "security_scanner.agent.local_scan.build_llm_client",
        ) as mock_org_factory,
    ):
        from security_scanner.agent.local_scan import get_local_pipeline_factory
        from security_scanner.shared.config import Settings

        settings = Settings()
        pipeline_factory = get_local_pipeline_factory(settings)
        override = LLMOverride(
            provider="anthropic",
            api_key="sk-ant-caller-key-xxx",
            model="claude-sonnet-4-6",
        )
        pipeline_factory({"a.py": "print(1)"}, override)
        mock_byo_factory.assert_called_once_with(
            provider="anthropic",
            api_key="sk-ant-caller-key-xxx",
            model="claude-sonnet-4-6",
        )
        mock_org_factory.assert_not_called()


def test_llm_override_missing_api_key_returns_422(client):
    """Pydantic validation rejects an override without an api_key."""
    r = client.post(
        "/scan/local",
        json={
            "files": {"a.py": "print(1)"},
            "triggered_by": "tester",
            "repo_url": "https://github.com/x/y",
            "llm_override": {"provider": "anthropic"},  # missing api_key
        },
        headers={"Authorization": f"Bearer {_LOCAL_TOKEN}"},
    )
    assert r.status_code == 422
    assert "api_key" in r.text.lower()


def test_llm_override_empty_api_key_returns_422(client):
    """Pydantic validation rejects an empty api_key (min_length=1)."""
    r = client.post(
        "/scan/local",
        json={
            "files": {"a.py": "print(1)"},
            "triggered_by": "tester",
            "repo_url": "https://github.com/x/y",
            "llm_override": {"provider": "google", "api_key": ""},
        },
        headers={"Authorization": f"Bearer {_LOCAL_TOKEN}"},
    )
    assert r.status_code == 422


def test_llm_override_flows_through_to_factory(client, mock_pipeline):
    """End-to-end: llm_override in request body reaches the factory closure."""
    from unittest.mock import patch

    captured: dict = {}

    def real_factory_provider():
        def build(files, llm_override):
            captured["llm_override"] = llm_override
            return mock_pipeline
        return build

    mock_pipeline.run.return_value = _result([])
    from security_scanner.agent.local_scan import get_local_pipeline_factory

    client.app.dependency_overrides[get_local_pipeline_factory] = real_factory_provider
    try:
        r = client.post(
            "/scan/local",
            json={
                "files": {"a.py": "print(1)"},
                "triggered_by": "tester",
                "repo_url": "https://github.com/x/y",
                "llm_override": {
                    "provider": "google",
                    "api_key": "AIza-fake-key-for-test",
                    "model": "gemini-2.5-flash",
                },
            },
            headers={"Authorization": f"Bearer {_LOCAL_TOKEN}"},
        )
        assert r.status_code == 200, r.text
        assert captured["llm_override"] is not None
        assert captured["llm_override"].provider == "google"
        assert captured["llm_override"].api_key == "AIza-fake-key-for-test"
        assert captured["llm_override"].model == "gemini-2.5-flash"
    finally:
        # Restore the default mock factory for subsequent tests
        client.app.dependency_overrides[get_local_pipeline_factory] = lambda: (
            lambda files, llm_override: mock_pipeline  # noqa: ARG005
        )


def test_returns_429_when_semaphore_is_drained(client, monkeypatch):
    """Saturate the semaphore and verify a fresh request gets 429+Retry-After."""
    import security_scanner.agent.local_scan as ls_mod

    # Drain all slots manually to simulate other in-flight scans.
    drained = []
    for _ in range(ls_mod._MAX_CONCURRENT_SCANS):
        # ``locked()`` becomes True only once ``_value <= 0``. We push
        # the value to 0 by acquiring without awaiting (cheap in tests).
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
        # Restore the semaphore so subsequent tests aren't broken.
        for _ in range(ls_mod._MAX_CONCURRENT_SCANS):
            ls_mod._scan_semaphore._value += 1
    assert r.status_code == 429
    assert r.headers["Retry-After"] == "10"
    assert "at capacity" in r.json()["detail"]
