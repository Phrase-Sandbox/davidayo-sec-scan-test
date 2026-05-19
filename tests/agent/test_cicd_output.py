"""Tests for the CI/CD output message formatter (spec §6.5, EC-012)."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from security_scanner.agent.cicd_output import format_cicd_message
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
from security_scanner.shared.severity.mapping import severity_to_cvss_band


def _finding(severity: Severity, vid: str) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        vulnerability_id=vid,
        severity=severity,
        confidence=Confidence.High,
        cvss_band=severity_to_cvss_band(severity),
        affected_file="src/app.py",
        affected_lines="10",
        description="X",
        suggested_fix="Y",
        owasp_reference="https://owasp.org/Top10/",
        patch_file_path="patches/x.patch",
        exploit_scenario="Attacker sends a payload to src/app.py via login parameter.",
        verification_status=VerificationStatus.verified,
    )


def _result(
    findings: list[VulnerabilityFinding],
    gate_decision: GateDecision,
    *,
    triggered_by: str = "alice@phrase.com",
    timestamp: datetime = datetime(2026, 5, 18, 12, 0, 0, tzinfo=UTC),
) -> ScanResult:
    return ScanResult(
        scan_id=uuid4(),
        repo_url="https://github.com/Phrase-Launchpad/example",
        scan_target=ScanTarget.full_repo,
        scan_type=ScanType.deployment_gate,
        triggered_by=triggered_by,
        timestamp=timestamp,
        findings_count=len(findings),
        gate_decision=gate_decision,
        partial_scan=False,
        unscanned_files=[],
        findings=findings,
        warnings=[],
    )


# --- BLOCKED ----------------------------------------------------------------


def test_blocked_message_matches_spec_with_correct_counts():
    findings = [
        _finding(Severity.Critical, "A03:2021"),
        _finding(Severity.Critical, "A07:2021"),
        _finding(Severity.High, "A05:2021"),
        _finding(Severity.Medium, "A04:2021"),  # not counted in summary
    ]
    msg = format_cicd_message(_result(findings, GateDecision.blocked))
    assert msg == (
        "Security scan failed: 2 Critical, 1 High findings detected. "
        "Deployment blocked. See report artifact for details and patches."
    )


def test_blocked_with_zero_findings_still_renders_zero_counts():
    """Edge case — gate_decision=blocked with no findings is theoretically possible."""
    msg = format_cicd_message(_result([], GateDecision.blocked))
    assert "0 Critical, 0 High findings detected" in msg


# --- PASS ------------------------------------------------------------------


def test_pass_message_matches_spec_and_counts_medium_low_only():
    findings = [
        _finding(Severity.Medium, "A04:2021"),
        _finding(Severity.Medium, "A06:2021"),
        _finding(Severity.Low, "A09:2021"),
    ]
    msg = format_cicd_message(_result(findings, GateDecision.pass_))
    assert msg == (
        "Security scan passed. 3 Medium/Low findings noted — "
        "see report for details."
    )


def test_pass_with_no_findings_shows_zero():
    msg = format_cicd_message(_result([], GateDecision.pass_))
    assert "0 Medium/Low findings noted" in msg


# --- ADVISORY --------------------------------------------------------------


def test_advisory_message_matches_spec_and_counts_total_findings():
    findings = [
        _finding(Severity.High, "A01:2021"),
        _finding(Severity.Critical, "A03:2021"),
    ]
    msg = format_cicd_message(_result(findings, GateDecision.advisory))
    assert msg == (
        "Security scan advisory: 2 findings present but not blocking "
        "(confidence or verification threshold not met). See report."
    )


# --- SCAN_FAILED -----------------------------------------------------------


def test_scan_failed_message_matches_spec_verbatim():
    msg = format_cicd_message(_result([], GateDecision.scan_failed))
    assert msg == (
        "Security scan unavailable. Deployment allowed to proceed — "
        "scan manually before release."
    )


# --- BYPASSED --------------------------------------------------------------


def test_bypassed_message_matches_spec_with_developer_timestamp_and_count():
    findings = [
        _finding(Severity.Critical, "A03:2021"),
        _finding(Severity.High, "A05:2021"),
    ]
    msg = format_cicd_message(
        _result(
            findings,
            GateDecision.bypassed,
            triggered_by="dave@phrase.com",
            timestamp=datetime(2026, 5, 18, 9, 30, 15, tzinfo=UTC),
        )
    )
    assert msg == (
        "Deployment gate bypassed by dave@phrase.com at "
        "2026-05-18T09:30:15+00:00. 2 High/Critical findings were "
        "present at time of bypass."
    )


# --- Misuse ----------------------------------------------------------------


def test_unhandled_gate_decision_raises_value_error():
    """Defensive: a future ``GateDecision`` value must not silently render nothing."""

    class _FakeDecision:
        # Cannot easily extend StrEnum at runtime; instead pass a sentinel
        # via model_copy(update=) bypassing validation — emulate the "unknown
        # enum" condition by patching the result.
        pass

    result = _result([], GateDecision.pass_)
    # Patch in an enum-typed value that we don't handle; using object.__setattr__
    # avoids Pydantic validation rejecting it.
    object.__setattr__(result, "gate_decision", "future_state")
    with pytest.raises(ValueError, match="Unhandled gate_decision"):
        format_cicd_message(result)
