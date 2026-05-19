"""Tests for the skill response formatter (spec §6.1, BR-005)."""

from datetime import UTC, datetime
from uuid import uuid4

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
from security_scanner.skill.responses import format_skill_response


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
        description="X",
        suggested_fix="Y",
        owasp_reference="https://owasp.org/Top10/",
        patch_file_path="patches/x.patch",
        exploit_scenario="Attacker sends a payload to src/app.py via login parameter.",
        verification_status=VerificationStatus.unverified,
    )


def _result(
    *,
    findings: list[VulnerabilityFinding] | None = None,
    warnings: list[str] | None = None,
) -> ScanResult:
    fs = findings or []
    return ScanResult(
        scan_id=uuid4(),
        repo_url="https://github.com/Phrase-Launchpad/example",
        scan_target=ScanTarget.full_repo,
        scan_type=ScanType.on_demand,
        triggered_by="alice@phrase.com",
        timestamp=datetime(2026, 5, 18, tzinfo=UTC),
        findings_count=len(fs),
        gate_decision=GateDecision.advisory,
        partial_scan=False,
        unscanned_files=[],
        findings=fs,
        warnings=warnings or [],
    )


# --- Response shape --------------------------------------------------------


def test_returns_dict_with_required_keys():
    response = format_skill_response(_result(), {})
    assert set(response) >= {"report_markdown", "patches", "token_limit_warning", "summary"}


def test_report_markdown_renders_full_markdown_report():
    finding = _finding(Severity.High)
    response = format_skill_response(_result(findings=[finding]), {})
    assert response["report_markdown"].startswith("# Security Scan Report")
    assert "A03:2021" in response["report_markdown"]


def test_patches_are_serialised_as_list_of_filename_content_objects():
    patches = {
        "scan_0_login.py.patch": "--- a/x\n+++ b/x\n",
        "scan_1_users.py.patch": "--- a/y\n+++ b/y\n",
    }
    response = format_skill_response(_result(), patches)
    assert isinstance(response["patches"], list)
    assert len(response["patches"]) == 2
    filenames = {entry["filename"] for entry in response["patches"]}
    assert filenames == set(patches)
    for entry in response["patches"]:
        assert entry["content"] == patches[entry["filename"]]


def test_empty_patches_yields_empty_list():
    response = format_skill_response(_result(), {})
    assert response["patches"] == []


# --- Token-limit warning extraction ----------------------------------------


def test_token_limit_warning_extracted_from_br005_warning():
    warning = (
        "Repository exceeds scan size limit (~200000 tokens, max 150000). "
        "BR-005: recommend scanning by directory."
    )
    response = format_skill_response(_result(warnings=[warning]), {})
    assert response["token_limit_warning"] == warning


def test_token_limit_warning_recognised_by_scan_size_limit_phrase():
    """Even without the BR-005 marker, the literal 'scan size limit' phrase
    is enough to surface the warning prominently."""
    warning = "Repository exceeds scan size limit. Scope to a directory."
    response = format_skill_response(_result(warnings=[warning]), {})
    assert response["token_limit_warning"] == warning


def test_token_limit_warning_is_none_when_no_size_warning_present():
    response = format_skill_response(_result(warnings=["unrelated note"]), {})
    assert response["token_limit_warning"] is None


def test_token_limit_warning_is_none_when_warnings_empty():
    response = format_skill_response(_result(warnings=[]), {})
    assert response["token_limit_warning"] is None


# --- Summary line ----------------------------------------------------------


def test_summary_counts_findings_by_severity():
    findings = [
        _finding(Severity.Critical, vid="A01:2021"),
        _finding(Severity.Critical, vid="A02:2021"),
        _finding(Severity.High, vid="A03:2021"),
        _finding(Severity.Medium, vid="A04:2021"),
        _finding(Severity.Medium, vid="A05:2021"),
        _finding(Severity.Medium, vid="A06:2021"),
        _finding(Severity.Low, vid="A07:2021"),
    ]
    response = format_skill_response(_result(findings=findings), {})
    assert response["summary"] == "Found 2 Critical, 1 High, 3 Medium, 1 Low findings."


def test_summary_handles_zero_findings():
    response = format_skill_response(_result(findings=[]), {})
    assert response["summary"] == "Found 0 Critical, 0 High, 0 Medium, 0 Low findings."
