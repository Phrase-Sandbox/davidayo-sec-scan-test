"""Tests for POST /agent/bypass (BR-002 / EC-012)."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from security_scanner.agent import api as agent_api
from security_scanner.agent.api import router
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

_VALID_TOKEN = "phrase-scan-token-secret"  # noqa: S105 — test fixture


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("PHRASE_SCAN_TOKEN", _VALID_TOKEN)
    monkeypatch.setenv("GITHUB_APP_ID", "123")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", "-----BEGIN PRIVATE KEY-----")
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_ID", "Iv1.test")
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_SECRET", "secret")


@pytest.fixture
def alert(monkeypatch):
    mock = AsyncMock()
    monkeypatch.setattr(agent_api, "send_bypass_alert", mock)
    return mock


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def _finding(severity: Severity) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        vulnerability_id="A03:2021",
        severity=severity,
        confidence=Confidence.High,
        cvss_band="9.0-10.0" if severity == Severity.Critical else "7.0-8.9",
        affected_file="app/db.py",
        affected_lines="7",
        description="SQL injection.",
        suggested_fix="Use parameterised queries.",
        owasp_reference="https://owasp.org/Top10/A03_2021-Injection/",
        patch_file_path="",
        exploit_scenario="Attacker sends a payload to app/db.py to bypass the WHERE clause.",
        verification_status=VerificationStatus.verified,
    )


def _result(findings) -> dict:
    return ScanResult(
        scan_id=uuid4(),
        repo_url="https://github.com/davidayomide/VAmPI",
        scan_target=ScanTarget.full_repo,
        scan_type=ScanType.deployment_gate,
        triggered_by="ci",
        timestamp=datetime(2026, 5, 18, tzinfo=UTC),
        findings_count=len(findings),
        gate_decision=GateDecision.blocked,
        findings=findings,
    ).model_dump(mode="json")


def _body(findings, justification=None) -> dict:
    return {
        "result": _result(findings),
        "developer": "dave@example.com",
        "commit_sha": "abc123",
        "justification": justification,
    }


_AUTH = {"Authorization": f"Bearer {_VALID_TOKEN}"}


def test_critical_bypass_without_justification_is_rejected(client, alert):
    r = client.post("/agent/bypass", json=_body([_finding(Severity.Critical)]), headers=_AUTH)
    assert r.status_code == 422
    assert "justification" in r.json()["detail"].lower()
    alert.assert_not_awaited()


def test_critical_bypass_with_justification_succeeds(client, alert):
    r = client.post(
        "/agent/bypass",
        json=_body([_finding(Severity.Critical)], justification="hotfix, risk accepted"),
        headers=_AUTH,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["gate_decision"] == "bypassed"
    assert body["bypass_invoked"] is True
    assert body["triggered_by"] == "dave@example.com"
    alert.assert_awaited_once()


def test_high_only_bypass_needs_no_justification(client, alert):
    r = client.post("/agent/bypass", json=_body([_finding(Severity.High)]), headers=_AUTH)
    assert r.status_code == 200
    assert r.json()["gate_decision"] == "bypassed"
    alert.assert_awaited_once()


def test_bypass_requires_auth(client, alert):
    r = client.post("/agent/bypass", json=_body([_finding(Severity.High)]))
    assert r.status_code == 401
    alert.assert_not_awaited()
