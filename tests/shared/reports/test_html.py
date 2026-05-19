"""Tests for the HTML report generator (§2.2 step 6, §6.1, §6.2, BR-008)."""

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
from security_scanner.shared.reports.html import build_html_report


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
        suggested_fix="Use a parameterised query.",
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
) -> ScanResult:
    fs = findings or []
    return ScanResult(
        scan_id=UUID("12345678-1234-5678-1234-567812345678"),
        repo_url="https://github.com/Phrase-Launchpad/example",
        scan_target=ScanTarget.full_repo,
        scan_type=scan_type,
        triggered_by="alice@phrase.com",
        timestamp=datetime(2026, 5, 18, 12, 0, 0, tzinfo=UTC),
        findings_count=len(fs),
        gate_decision=gate_decision,
        partial_scan=partial_scan,
        unscanned_files=unscanned_files or [],
        findings=fs,
    )


# --- Document structure -----------------------------------------------------


def test_report_is_self_contained_html_document():
    html = build_html_report(_result())
    assert html.startswith("<!DOCTYPE html>")
    assert "<title>Security Scan Report</title>" in html
    # CSS is inlined — no external <link rel=stylesheet> dependencies.
    assert "<style>" in html
    assert "<link" not in html


def test_report_contains_h1_header():
    assert "<h1>Security Scan Report</h1>" in build_html_report(_result())


def test_metadata_section_includes_all_fields():
    html = build_html_report(_result())
    assert "12345678-1234-5678-1234-567812345678" in html
    assert "https://github.com/Phrase-Launchpad/example" in html
    assert "2026-05-18T12:00:00+00:00" in html
    assert "deployment_gate" in html
    assert "alice@phrase.com" in html


def test_gate_decision_omitted_for_skill_scans():
    html = build_html_report(_result(scan_type=ScanType.on_demand))
    assert "Gate decision" not in html


def test_gate_decision_shown_with_label_for_gate_scans():
    html = build_html_report(_result(gate_decision=GateDecision.blocked))
    assert "Gate decision" in html
    assert "blocked" in html


# --- Severity colour coding (the user's explicit requirement) --------------


def test_critical_severity_uses_red_colour():
    finding = _finding(severity=Severity.Critical)
    html = build_html_report(_result(findings=[finding]))
    # Either via the inline style block or the CSS class — both must be present.
    assert "#c0392b" in html
    assert "severity-critical" in html


def test_high_severity_uses_orange_colour():
    finding = _finding(severity=Severity.High)
    html = build_html_report(_result(findings=[finding]))
    assert "#e67e22" in html
    assert "severity-high" in html


def test_medium_severity_uses_yellow_colour():
    finding = _finding(severity=Severity.Medium)
    html = build_html_report(_result(findings=[finding]))
    assert "#d4ac0d" in html
    assert "severity-medium" in html


def test_low_severity_uses_blue_colour():
    finding = _finding(severity=Severity.Low)
    html = build_html_report(_result(findings=[finding]))
    assert "#2980b9" in html
    assert "severity-low" in html


# --- Warning rendering (the four required cases) ---------------------------


def test_partial_scan_warning_appears_with_file_list():
    result = _result(
        partial_scan=True,
        unscanned_files=["src/a.py", "src/b.py"],
        findings=[_finding()],
    )
    html = build_html_report(result)
    assert "PARTIAL SCAN" in html
    assert "src/a.py" in html
    assert "src/b.py" in html


def test_conflicting_warning_appears_for_critical_conflicting_finding():
    finding = _finding(
        severity=Severity.Critical,
        confidence=Confidence.High,
        verification_status=VerificationStatus.conflicting,
    )
    html = build_html_report(_result(findings=[finding]))
    assert "CONFLICTING FINDINGS" in html
    assert "1 Critical findings were not confirmed" in html


def test_advisory_warning_appears_for_high_critical_with_medium_low_confidence():
    findings = [_finding(severity=Severity.High, confidence=Confidence.Medium)]
    html = build_html_report(_result(findings=findings))
    assert "ADVISORY" in html
    assert "1 findings are High/Critical severity" in html


def test_empty_findings_warning_appears_when_findings_list_is_empty():
    html = build_html_report(_result(findings=[]))
    assert "NO FINDINGS DETECTED" in html
    assert "acknowledgement required" in html


def test_no_warnings_section_when_clean_finding():
    findings = [
        _finding(
            severity=Severity.Critical,
            confidence=Confidence.High,
            verification_status=VerificationStatus.verified,
        ),
    ]
    html = build_html_report(_result(findings=findings))
    assert "<h2>Warnings</h2>" not in html


# --- XSS hygiene -----------------------------------------------------------


def test_html_special_chars_in_user_fields_are_escaped():
    finding = _finding(
        affected_file="src/<script>alert(1)</script>.py",
    )
    html = build_html_report(_result(findings=[finding]))
    # The dangerous tag must not appear unescaped.
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_owasp_reference_url_renders_as_anchor():
    finding = _finding()
    html = build_html_report(_result(findings=[finding]))
    assert '<a href="https://owasp.org/Top10/A03_2021-Injection/">' in html


# --- Finding detail rendering ---------------------------------------------


def test_detail_section_contains_description_exploit_and_fix():
    finding = _finding()
    html = build_html_report(_result(findings=[finding]))
    assert "Finding details" in html
    assert finding.description in html
    assert finding.exploit_scenario in html
    assert finding.suggested_fix in html
    assert finding.patch_file_path in html


def test_findings_table_present_when_findings_exist():
    html = build_html_report(_result(findings=[_finding()]))
    assert "<table>" in html
    assert "<thead>" in html
    assert "<tbody>" in html
