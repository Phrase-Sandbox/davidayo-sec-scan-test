"""Tests for the agent-layer gate decision (BR-001, BR-001-A, BR-006, BR-009)."""

from datetime import UTC, datetime
from uuid import uuid4

from security_scanner.agent.gate_decision import make_gate_decision
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


def _finding(
    severity: Severity = Severity.High,
    confidence: Confidence = Confidence.High,
    verification_status: VerificationStatus = VerificationStatus.unverified,
    *,
    vid: str = "A03:2021",
) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        vulnerability_id=vid,
        severity=severity,
        confidence=confidence,
        cvss_band=severity_to_cvss_band(severity),
        affected_file="src/app.py",
        affected_lines="10",
        description="X",
        suggested_fix="Y",
        owasp_reference="https://owasp.org/Top10/",
        patch_file_path="patches/x.patch",
        exploit_scenario="Attacker sends a payload to src/app.py via login parameter.",
        verification_status=verification_status,
    )


def _result(
    *,
    findings: list[VulnerabilityFinding] | None = None,
    gate_decision: GateDecision = GateDecision.advisory,
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


# --- Rule 1: scan_failed is preserved (BR-006) -----------------------------


def test_scan_failed_is_preserved():
    result = _result(gate_decision=GateDecision.scan_failed)
    assert make_gate_decision(result).gate_decision == GateDecision.scan_failed


def test_scan_failed_preserved_even_when_findings_would_block():
    """BR-006 fail-open: infrastructure-failed scans never block, even if a
    blocking finding somehow exists in the partial result."""
    blocker = _finding(Severity.High, Confidence.High)
    result = _result(findings=[blocker], gate_decision=GateDecision.scan_failed)
    assert make_gate_decision(result).gate_decision == GateDecision.scan_failed


# --- Rule 2: should_block findings → BLOCKED -------------------------------


def test_high_confidence_high_severity_blocks():
    result = _result(findings=[_finding(Severity.High, Confidence.High)])
    assert make_gate_decision(result).gate_decision == GateDecision.blocked


def test_verified_critical_blocks():
    """BR-009: a Critical that the second pass concurred on does block."""
    finding = _finding(
        Severity.Critical, Confidence.High, VerificationStatus.verified,
    )
    result = _result(findings=[finding])
    assert make_gate_decision(result).gate_decision == GateDecision.blocked


def test_blocking_finding_wins_over_advisory_demotion():
    """A mix of one blocker and one demoted finding → BLOCKED (rule 2 wins)."""
    blocker = _finding(Severity.High, Confidence.High, vid="A01:2021")
    demoted = _finding(Severity.High, Confidence.Medium, vid="A05:2021")
    result = _result(findings=[blocker, demoted])
    assert make_gate_decision(result).gate_decision == GateDecision.blocked


# --- Rule 3: BR-001-A confidence demotion → ADVISORY -----------------------


def test_br001a_high_severity_with_medium_confidence_is_advisory_not_blocked():
    """BR-001-A: High + Medium confidence demotes to advisory."""
    finding = _finding(Severity.High, Confidence.Medium)
    result = _result(findings=[finding])
    out = make_gate_decision(result)
    assert out.gate_decision == GateDecision.advisory


def test_br001a_critical_with_low_confidence_is_advisory():
    finding = _finding(Severity.Critical, Confidence.Low)
    out = make_gate_decision(_result(findings=[finding]))
    assert out.gate_decision == GateDecision.advisory


# --- Rule 3: BR-009 verification conflict → ADVISORY -----------------------


def test_br009_critical_with_conflicting_verification_is_advisory():
    finding = _finding(
        Severity.Critical, Confidence.High, VerificationStatus.conflicting,
    )
    out = make_gate_decision(_result(findings=[finding]))
    assert out.gate_decision == GateDecision.advisory


# --- Rule 3: warning is appended on advisory --------------------------------


def test_advisory_decision_appends_header_warning():
    demoted = _finding(Severity.High, Confidence.Medium)
    out = make_gate_decision(_result(findings=[demoted]))
    assert out.gate_decision == GateDecision.advisory
    assert any("ADVISORY" in w for w in out.warnings)
    assert any("demoted" in w for w in out.warnings)


def test_advisory_warning_count_matches_demoted_count():
    findings = [
        _finding(Severity.High, Confidence.Medium, vid="A01:2021"),
        _finding(Severity.High, Confidence.Low, vid="A02:2021"),
        _finding(
            Severity.Critical,
            Confidence.High,
            VerificationStatus.conflicting,
            vid="A03:2021",
        ),
    ]
    out = make_gate_decision(_result(findings=findings))
    assert any("3 High/Critical findings" in w for w in out.warnings)


def test_existing_warnings_are_preserved():
    pre_existing = "pre-existing scan warning"
    out = make_gate_decision(
        _result(
            findings=[_finding(Severity.High, Confidence.Medium)],
            warnings=[pre_existing],
        )
    )
    assert pre_existing in out.warnings
    # Plus the new advisory warning.
    assert len(out.warnings) >= 2


# --- Rule 4: pass ----------------------------------------------------------


def test_no_findings_yields_pass():
    out = make_gate_decision(_result(findings=[]))
    assert out.gate_decision == GateDecision.pass_


def test_only_medium_findings_yields_pass():
    findings = [
        _finding(Severity.Medium, Confidence.High, vid="A01:2021"),
        _finding(Severity.Low, Confidence.High, vid="A02:2021"),
    ]
    out = make_gate_decision(_result(findings=findings))
    assert out.gate_decision == GateDecision.pass_


# --- Immutability ----------------------------------------------------------


def test_input_result_not_mutated():
    finding = _finding(Severity.High, Confidence.Medium)
    result = _result(findings=[finding], gate_decision=GateDecision.advisory)
    snapshot_decision = result.gate_decision
    snapshot_warnings = list(result.warnings)
    make_gate_decision(result)
    assert result.gate_decision == snapshot_decision
    assert result.warnings == snapshot_warnings
