"""Tests for the Slack bypass alerter (BR-002, EC-012)."""

import asyncio
import json
from datetime import UTC, datetime
from uuid import uuid4

import httpx
import pytest

from security_scanner.agent.slack_alert import (
    send_bypass_alert,
    send_pr_rejected_alert,
)
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

_WEBHOOK = "https://hooks.slack.example.com/services/T000/B000/abc"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    """Default-case settings — required by get_settings()."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("GITHUB_APP_ID", "1")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", "-----BEGIN PRIVATE KEY-----")
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_ID", "Iv1.test")
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_SECRET", "secret")
    monkeypatch.setenv("SLACK_WEBHOOK_URL", _WEBHOOK)


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
        affected_file="src/handlers/login.py",
        affected_lines="42-55",
        description="SQL injection.",
        suggested_fix="Use a parameterised query.",
        owasp_reference="https://owasp.org/Top10/A03_2021-Injection/",
        patch_file_path="patches/x.patch",
        exploit_scenario=(
            "Attacker sends a payload via the login parameter to "
            "src/handlers/login.py bypassing the WHERE clause."
        ),
        verification_status=VerificationStatus.verified,
    )


def _result(findings: list[VulnerabilityFinding] | None = None) -> ScanResult:
    fs = findings or []
    return ScanResult(
        scan_id=uuid4(),
        repo_url="https://github.com/Phrase-Launchpad/example",
        scan_target=ScanTarget.full_repo,
        scan_type=ScanType.deployment_gate,
        triggered_by="alice@phrase.com",
        timestamp=datetime(2026, 5, 18, 12, 0, 0, tzinfo=UTC),
        findings_count=len(fs),
        gate_decision=GateDecision.bypassed,
        partial_scan=False,
        unscanned_files=[],
        findings=fs,
    )


def _mock_client(handler) -> httpx.AsyncClient:
    transport = httpx.MockTransport(handler)
    return httpx.AsyncClient(transport=transport)


def _run(coro):
    return asyncio.run(coro)


# --- Message construction ---------------------------------------------------


def test_message_sent_with_correct_fields_to_webhook_url():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["body"] = json.loads(request.content)
        return httpx.Response(200)

    client = _mock_client(handler)
    result = _result([_finding(Severity.Critical, "A03:2021")])

    _run(
        send_bypass_alert(
            result,
            developer="alice@phrase.com",
            commit_sha="deadbeef1234567",
            http_client=client,
        )
    )

    assert captured["url"] == _WEBHOOK
    text = captured["body"]["text"]
    assert "alice@phrase.com" in text
    assert "https://github.com/Phrase-Launchpad/example" in text
    assert "deadbeef1234567" in text
    assert "2026-05-18T12:00:00+00:00" in text
    assert "Security scan bypass invoked" in text


def test_critical_high_counts_match_findings_list():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200)

    findings = [
        _finding(Severity.Critical, "A03:2021"),
        _finding(Severity.Critical, "A07:2021"),
        _finding(Severity.High, "A05:2021"),
        _finding(Severity.Medium, "A04:2021"),  # not counted
    ]
    client = _mock_client(handler)

    _run(
        send_bypass_alert(
            _result(findings),
            developer="bob",
            commit_sha="sha-xyz",
            http_client=client,
        )
    )

    assert "2 Critical, 1 High" in captured["body"]["text"]


def test_justification_included_when_provided():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200)

    _run(
        send_bypass_alert(
            _result([_finding(Severity.Critical, "A03:2021")]),
            developer="carol",
            commit_sha="abc123",
            justification="False positive — this is an internal admin tool.",
            http_client=_mock_client(handler),
        )
    )

    assert "Justification" in captured["body"]["text"]
    assert "False positive — this is an internal admin tool." in captured["body"]["text"]


def test_justification_omitted_when_none():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200)

    _run(
        send_bypass_alert(
            _result([_finding(Severity.High, "A05:2021")]),
            developer="dave",
            commit_sha="xyz789",
            justification=None,
            http_client=_mock_client(handler),
        )
    )

    assert "Justification" not in captured["body"]["text"]


# --- Webhook missing --------------------------------------------------------


def test_no_webhook_url_logs_warning_and_returns_silently(monkeypatch, capsys):
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)

    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200)

    client = _mock_client(handler)

    _run(
        send_bypass_alert(
            _result(),
            developer="alice",
            commit_sha="sha",
            http_client=client,
        )
    )

    assert calls == []  # no HTTP call made
    out = capsys.readouterr().out
    assert "slack webhook not configured" in out


# --- HTTP / network failures (must not raise) -------------------------------


def test_http_5xx_response_is_logged_not_raised(capsys):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="Internal Server Error")

    # send_bypass_alert must complete without raising.
    _run(
        send_bypass_alert(
            _result(),
            developer="alice",
            commit_sha="sha",
            http_client=_mock_client(handler),
        )
    )

    out = capsys.readouterr().out
    assert "slack bypass alert failed" in out
    assert "HTTPStatusError" in out


def test_http_4xx_response_is_logged_not_raised(capsys):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    _run(
        send_bypass_alert(
            _result(),
            developer="alice",
            commit_sha="sha",
            http_client=_mock_client(handler),
        )
    )

    assert "slack bypass alert failed" in capsys.readouterr().out


def test_network_error_is_logged_not_raised(capsys):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("simulated network blip")

    _run(
        send_bypass_alert(
            _result(),
            developer="alice",
            commit_sha="sha",
            http_client=_mock_client(handler),
        )
    )

    out = capsys.readouterr().out
    assert "slack bypass alert failed" in out
    assert "ConnectError" in out


# --- Logging discipline -----------------------------------------------------


def test_justification_body_never_appears_in_logs(capsys):
    """The justification may contain sensitive context — must not be logged."""
    secret_justification = "Customer ID 999999 is whitelisted per VP approval"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    _run(
        send_bypass_alert(
            _result([_finding(Severity.Critical, "A03:2021")]),
            developer="alice",
            commit_sha="sha",
            justification=secret_justification,
            http_client=_mock_client(handler),
        )
    )

    out = capsys.readouterr().out
    # The webhook payload contained it; the log line MUST NOT.
    assert secret_justification not in out


# --- PR-rejected alert (Appendix D-16) -------------------------------------


def _pr_kwargs(**kw):
    base = {
        "repo_url": "https://github.com/davidayomide/VAmPI",
        "pr_number": 5,
        "pr_url": "https://github.com/davidayomide/VAmPI/pull/5",
        "closed_by": "dave",
        "closed_at": "2026-05-19T03:00:00Z",
        "reason": "will fix manually next sprint",
        "critical": 2,
        "high": 1,
    }
    base.update(kw)
    return base


def test_pr_rejected_message_has_who_when_why_findings():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["text"] = json.loads(request.content)["text"]
        return httpx.Response(200)

    _run(send_pr_rejected_alert(**_pr_kwargs(), http_client=_mock_client(handler)))

    assert captured["url"] == _WEBHOOK
    t = captured["text"]
    assert "Security auto-fix PR rejected" in t
    assert "dave" in t  # who
    assert "2026-05-19T03:00:00Z" in t  # when
    assert "will fix manually next sprint" in t  # why
    assert "#5" in t
    assert "2 Critical, 1 High" in t


def test_pr_rejected_flags_missing_reason():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["text"] = json.loads(request.content)["text"]
        return httpx.Response(200)

    _run(send_pr_rejected_alert(**_pr_kwargs(reason=None), http_client=_mock_client(handler)))
    assert "REASON MISSING" in captured["text"]


def test_pr_rejected_http_error_logged_not_raised(capsys):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    _run(send_pr_rejected_alert(**_pr_kwargs(), http_client=_mock_client(handler)))
    assert "slack pr-rejected alert failed" in capsys.readouterr().out


def test_pr_rejected_no_webhook_skips(monkeypatch, capsys):
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    _run(send_pr_rejected_alert(**_pr_kwargs()))
    assert "slack webhook not configured" in capsys.readouterr().out
