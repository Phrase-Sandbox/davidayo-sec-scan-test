from datetime import datetime
from uuid import UUID

import pytest
from pydantic import ValidationError

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

# --- Enums -------------------------------------------------------------------


def test_severity_members_match_spec():
    assert Severity.Critical.value == "Critical"
    assert Severity.High.value == "High"
    assert Severity.Medium.value == "Medium"
    assert Severity.Low.value == "Low"
    assert len(Severity) == 4


def test_confidence_members_match_spec():
    assert Confidence.High.value == "High"
    assert Confidence.Medium.value == "Medium"
    assert Confidence.Low.value == "Low"
    assert len(Confidence) == 3


def test_scan_type_members_match_spec():
    assert ScanType.on_demand.value == "on_demand"
    assert ScanType.deployment_gate.value == "deployment_gate"
    assert len(ScanType) == 2


def test_scan_target_members_match_spec():
    assert ScanTarget.full_repo.value == "full_repo"
    assert ScanTarget.diff.value == "diff"
    assert ScanTarget.directory.value == "directory"
    assert len(ScanTarget) == 3


def test_verification_status_members_match_spec():
    assert VerificationStatus.verified.value == "verified"
    assert VerificationStatus.unverified.value == "unverified"
    assert VerificationStatus.conflicting.value == "conflicting"
    assert len(VerificationStatus) == 3


def test_gate_decision_members_match_spec_and_pass_keyword_workaround():
    # 'pass' is a Python keyword — member name is `pass_`, value is "pass" per §3.1.
    assert GateDecision.pass_.value == "pass"
    assert GateDecision.blocked.value == "blocked"
    assert GateDecision.bypassed.value == "bypassed"
    assert GateDecision.advisory.value == "advisory"
    assert GateDecision.scan_failed.value == "scan_failed"
    assert len(GateDecision) == 5


# --- VulnerabilityFinding ----------------------------------------------------


def _valid_finding_kwargs() -> dict:
    return {
        "vulnerability_id": "A03:2021",
        "severity": Severity.High,
        "confidence": Confidence.High,
        "cvss_band": "7.0-8.9",
        "affected_file": "src/handlers/login.py",
        "affected_lines": "42-55",
        "description": "SQL injection in login handler.",
        "suggested_fix": "Use a parameterised query.",
        "owasp_reference": "https://owasp.org/Top10/A03_2021-Injection/",
        "patch_file_path": "patches/A03-2021_login.patch",
        "exploit_scenario": (
            "An attacker submits username=admin' OR '1'='1 to /login and bypasses the WHERE "
            "clause in src/handlers/login.py, returning admin credentials."
        ),
    }


def test_vulnerability_finding_accepts_valid_data():
    finding = VulnerabilityFinding(**_valid_finding_kwargs())
    assert finding.severity is Severity.High


def test_vulnerability_finding_verification_status_defaults_to_unverified():
    finding = VulnerabilityFinding(**_valid_finding_kwargs())
    assert finding.verification_status is VerificationStatus.unverified


def test_vulnerability_finding_affected_lines_is_optional():
    kwargs = _valid_finding_kwargs()
    del kwargs["affected_lines"]
    finding = VulnerabilityFinding(**kwargs)
    assert finding.affected_lines is None


@pytest.mark.parametrize(
    "missing_field",
    [
        "vulnerability_id",
        "severity",
        "confidence",
        "cvss_band",
        "affected_file",
        "description",
        "suggested_fix",
        "owasp_reference",
        "patch_file_path",
        "exploit_scenario",
    ],
)
def test_vulnerability_finding_rejects_missing_required_field(missing_field):
    kwargs = _valid_finding_kwargs()
    del kwargs[missing_field]
    with pytest.raises(ValidationError):
        VulnerabilityFinding(**kwargs)


def test_vulnerability_finding_rejects_invalid_severity():
    kwargs = _valid_finding_kwargs()
    kwargs["severity"] = "NotASeverity"
    with pytest.raises(ValidationError):
        VulnerabilityFinding(**kwargs)


# --- ScanResult --------------------------------------------------------------


def _valid_scan_kwargs() -> dict:
    return {
        "repo_url": "https://github.com/Phrase-Launchpad/example-service",
        "scan_target": ScanTarget.full_repo,
        "scan_type": ScanType.deployment_gate,
        "triggered_by": "alice@phrase.com",
    }


def test_scan_result_required_fields_must_be_supplied():
    with pytest.raises(ValidationError):
        ScanResult()  # type: ignore[call-arg]


def test_scan_result_defaults_match_spec():
    result = ScanResult(**_valid_scan_kwargs())
    assert isinstance(result.scan_id, UUID)
    assert isinstance(result.timestamp, datetime)
    assert result.findings_count == 0
    assert result.gate_decision is GateDecision.advisory
    assert result.bypass_invoked is False
    assert result.partial_scan is False
    assert result.unscanned_files == []
    assert result.findings == []


def test_scan_result_default_scan_id_is_unique_per_instance():
    a = ScanResult(**_valid_scan_kwargs())
    b = ScanResult(**_valid_scan_kwargs())
    assert a.scan_id != b.scan_id


def test_scan_result_default_lists_are_not_shared_across_instances():
    """Regression: mutable defaults must not be aliased — Field(default_factory=list)."""
    a = ScanResult(**_valid_scan_kwargs())
    b = ScanResult(**_valid_scan_kwargs())
    a.findings.append(VulnerabilityFinding(**_valid_finding_kwargs()))
    a.unscanned_files.append("src/some_file.py")
    assert b.findings == []
    assert b.unscanned_files == []


def test_scan_result_timestamp_is_timezone_aware_utc():
    result = ScanResult(**_valid_scan_kwargs())
    assert result.timestamp.tzinfo is not None
    assert result.timestamp.utcoffset().total_seconds() == 0
