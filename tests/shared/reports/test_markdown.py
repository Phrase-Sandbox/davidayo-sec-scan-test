"""Tests for the Markdown report generator (§2.2 step 6, §6.1, §6.2, BR-008)."""

from datetime import UTC, datetime
from uuid import UUID

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
from security_scanner.shared.reports.markdown import build_markdown_report


def _finding(
    *,
    severity: Severity = Severity.High,
    confidence: Confidence = Confidence.High,
    verification_status: VerificationStatus = VerificationStatus.unverified,
    affected_file: str = "src/app.py",
    vulnerability_id: str = "A03:2021",
) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        vulnerability_id=vulnerability_id,
        severity=severity,
        confidence=confidence,
        cvss_band={
            Severity.Critical: "9.0–10.0",
            Severity.High: "7.0–8.9",
            Severity.Medium: "4.0–6.9",
            Severity.Low: "0.1–3.9",
        }[severity],
        affected_file=affected_file,
        affected_lines="42-55",
        description="SQL injection in login.",
        suggested_fix="Use parameterised query.",
        owasp_reference="https://owasp.org/Top10/A03_2021-Injection/",
        patch_file_path="patches/A03-2021.patch",
        exploit_scenario=f"Attacker sends a payload to {affected_file}.",
        verification_status=verification_status,
    )


def _result(
    *,
    findings: list[VulnerabilityFinding] | None = None,
    scan_type: ScanType = ScanType.deployment_gate,
    gate_decision: GateDecision = GateDecision.advisory,
    partial_scan: bool = False,
    unscanned_files: list[str] | None = None,
    findings_count: int | None = None,
) -> ScanResult:
    fs = findings or []
    return ScanResult(
        scan_id=UUID("12345678-1234-5678-1234-567812345678"),
        repo_url="https://github.com/Phrase-Launchpad/example",
        scan_target=ScanTarget.full_repo,
        scan_type=scan_type,
        triggered_by="alice@phrase.com",
        timestamp=datetime(2026, 5, 18, 12, 0, 0, tzinfo=UTC),
        findings_count=findings_count if findings_count is not None else len(fs),
        gate_decision=gate_decision,
        partial_scan=partial_scan,
        unscanned_files=unscanned_files or [],
        findings=fs,
    )


# --- Structure ---------------------------------------------------------------


def test_report_has_top_level_header():
    assert build_markdown_report(_result()).startswith("# Security Scan Report")


def test_metadata_section_includes_all_required_fields():
    report = build_markdown_report(_result())
    assert "Scan metadata" in report
    assert "12345678-1234-5678-1234-567812345678" in report
    assert "https://github.com/Phrase-Launchpad/example" in report
    assert "2026-05-18T12:00:00+00:00" in report
    assert "deployment_gate" in report
    assert "alice@phrase.com" in report


def test_findings_table_present_when_findings_exist():
    report = build_markdown_report(_result(findings=[_finding()]))
    assert "## Findings (1)" in report
    assert "| A03:2021 |" in report


def test_findings_table_absent_when_no_findings():
    report = build_markdown_report(_result(findings=[]))
    assert "## Findings (" not in report


def test_gate_decision_shown_for_gate_scans():
    result = _result(scan_type=ScanType.deployment_gate, gate_decision=GateDecision.blocked)
    report = build_markdown_report(result)
    assert "Gate decision" in report
    assert "BLOCKED" in report


def test_gate_decision_omitted_for_skill_scans():
    result = _result(scan_type=ScanType.on_demand)
    assert "Gate decision" not in build_markdown_report(result)


def test_footer_includes_findings_count():
    report = build_markdown_report(_result(findings=[_finding(), _finding()]))
    assert "*Findings: 2*" in report


# --- Warning rendering (the four required cases) ----------------------------


def test_partial_scan_warning_appears_with_file_list():
    result = _result(
        partial_scan=True,
        unscanned_files=["src/a.py", "src/b.py"],
        findings=[_finding()],
    )
    report = build_markdown_report(result)
    assert "PARTIAL SCAN" in report
    assert "`src/a.py`" in report
    assert "`src/b.py`" in report


def test_conflicting_warning_appears_for_critical_conflicting_finding():
    finding = _finding(
        severity=Severity.Critical,
        confidence=Confidence.High,
        verification_status=VerificationStatus.conflicting,
    )
    report = build_markdown_report(_result(findings=[finding]))
    assert "CONFLICTING FINDINGS" in report
    assert "1 Critical findings were not confirmed" in report


def test_conflicting_warning_count_matches_number_of_conflicting_critical_findings():
    findings = [
        _finding(severity=Severity.Critical, verification_status=VerificationStatus.conflicting),
        _finding(severity=Severity.Critical, verification_status=VerificationStatus.conflicting),
        # Non-conflicting Critical should NOT be counted.
        _finding(severity=Severity.Critical, verification_status=VerificationStatus.verified),
        # High with conflicting (should never happen in practice; defensive: NOT counted).
        _finding(severity=Severity.High, verification_status=VerificationStatus.conflicting),
    ]
    report = build_markdown_report(_result(findings=findings))
    assert "2 Critical findings" in report


def test_advisory_warning_appears_for_high_critical_with_medium_low_confidence():
    findings = [
        _finding(severity=Severity.High, confidence=Confidence.Medium),
        _finding(severity=Severity.Critical, confidence=Confidence.Low),
    ]
    report = build_markdown_report(_result(findings=findings))
    assert "ADVISORY" in report
    assert "2 findings are High/Critical severity but have Medium/Low confidence" in report


def test_empty_findings_warning_appears_when_findings_list_is_empty():
    report = build_markdown_report(_result(findings=[]))
    assert "NO FINDINGS DETECTED" in report
    assert "acknowledgement required" in report


def test_no_warnings_section_when_clean_high_confidence_finding_only():
    """A normal verified Critical or High+High finding produces no warning banners."""
    findings = [
        _finding(
            severity=Severity.Critical,
            confidence=Confidence.High,
            verification_status=VerificationStatus.verified,
        ),
    ]
    report = build_markdown_report(_result(findings=findings))
    assert "## Warnings" not in report


def test_warnings_section_appears_before_findings_section():
    """Warnings must be visible at the top — above the findings table."""
    findings = [_finding(severity=Severity.High, confidence=Confidence.Low)]
    report = build_markdown_report(_result(findings=findings))
    assert report.index("## Warnings") < report.index("## Findings")


# --- Finding detail rendering ----------------------------------------------


def test_detail_section_renders_description_exploit_and_fix():
    finding = _finding()
    report = build_markdown_report(_result(findings=[finding]))
    assert "## Finding details" in report
    assert finding.description in report
    assert finding.exploit_scenario in report
    assert finding.suggested_fix in report
    assert finding.patch_file_path in report


def test_table_pipe_in_field_is_escaped_to_keep_table_intact():
    finding = _finding(affected_file="src/path|weird.py")
    report = build_markdown_report(_result(findings=[finding]))
    assert "src/path\\|weird.py" in report


# --- v2: advisory_real badge and context_summary ---------------------------


def test_advisory_real_badge_appears_in_detail():
    """advisory_real findings carry the auto-triaged badge phrase in Markdown."""
    f = _finding(verification_status=VerificationStatus.advisory_real)
    report = build_markdown_report(_result(findings=[f]))
    assert "Potential issue (auto-triaged, not blocking)" in report


def test_advisory_real_warning_in_header():
    """AUTO-TRIAGED warning appears when advisory_real findings are present."""
    f = _finding(verification_status=VerificationStatus.advisory_real)
    report = build_markdown_report(_result(findings=[f]))
    assert "AUTO-TRIAGED" in report


def test_non_advisory_real_has_no_badge():
    """verified findings must NOT carry the auto-triaged badge."""
    f = _finding(verification_status=VerificationStatus.verified)
    report = build_markdown_report(_result(findings=[f]))
    assert "Potential issue (auto-triaged, not blocking)" not in report


def test_context_summary_renders_in_detail_when_present():
    """When context_summary is set, a Cross-file context block appears."""
    f = _finding()
    f = f.model_copy(update={"context_summary": "ROUTES: GET /docs → get_doc"})
    report = build_markdown_report(_result(findings=[f]))
    assert "Cross-file context" in report
    assert "ROUTES: GET /docs" in report


def test_context_summary_absent_when_empty():
    """When context_summary is empty, no context block appears."""
    f = _finding()
    report = build_markdown_report(_result(findings=[f]))
    assert "Cross-file context" not in report


# --- v3: upload context panel (markdown) -------------------------------------


def test_upload_context_panel_rendered_in_markdown():
    """Finding with upload context_summary renders Upload context section in markdown."""
    f = _finding()
    upload_summary = (
        "Validation: none — Naming: preserved-user-filename — "
        "Storage: public-path — Limits: none — Access: none — "
        "Processing: archive-extract"
    )
    f = f.model_copy(update={"context_summary": upload_summary})
    report = build_markdown_report(_result(findings=[f]))
    assert "Upload context" in report
    assert "Validation:" in report
    assert "archive-extract" in report


def test_upload_context_panel_has_all_fields_in_markdown():
    """All 6 upload context labels appear in the markdown panel."""
    f = _finding()
    upload_summary = (
        "Validation: extension-allowlist — Naming: server-generated — "
        "Storage: outside-webroot — Limits: yes — Access: yes — "
        "Processing: none"
    )
    f = f.model_copy(update={"context_summary": upload_summary})
    report = build_markdown_report(_result(findings=[f]))
    for label in ("Validation:", "Naming:", "Storage:", "Limits:", "Access:", "Processing:"):
        assert label in report, f"Missing label {label!r} in upload context markdown panel"


def test_detected_by_renders_for_single_voter_claude_finding():
    """Fix #5: a Claude-only finding (sources=['claude']) must show Detected by: claude."""
    f = _finding(verification_status=VerificationStatus.verified)
    f = f.model_copy(update={"sources": ["claude"], "consensus_score": 1})
    report = build_markdown_report(_result(findings=[f]))
    assert "Detected by" in report
    assert "claude" in report


def test_detected_by_renders_for_multi_voter_finding():
    """Fix #5 regression: multi-voter findings still show Detected by: with voter count."""
    f = _finding(verification_status=VerificationStatus.verified)
    f = f.model_copy(update={"sources": ["claude", "bandit"], "consensus_score": 2})
    report = build_markdown_report(_result(findings=[f]))
    assert "Detected by" in report
    assert "claude" in report
    assert "bandit" in report
    assert "2 voter" in report


def test_detected_by_absent_when_sources_empty():
    """A finding with no sources must NOT emit a Detected by: line."""
    f = _finding(verification_status=VerificationStatus.unverified)
    f = f.model_copy(update={"sources": [], "consensus_score": 0})
    report = build_markdown_report(_result(findings=[f]))
    assert "Detected by" not in report


def test_non_upload_context_summary_renders_cross_file_in_markdown():
    """Non-upload context_summary still renders as Cross-file context in markdown."""
    f = _finding()
    f = f.model_copy(update={"context_summary": "ROUTES: GET /docs → get_doc"})
    report = build_markdown_report(_result(findings=[f]))
    assert "Cross-file context" in report
    assert "Upload context" not in report
