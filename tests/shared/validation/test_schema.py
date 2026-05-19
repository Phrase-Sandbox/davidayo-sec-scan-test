"""Tests for the Claude output schema validator (spec §4.2)."""

from copy import deepcopy

import pytest

from security_scanner.shared.models.enums import (
    Confidence,
    Severity,
    VerificationStatus,
)
from security_scanner.shared.validation.schema import (
    EMPTY_FINDINGS_LINE_THRESHOLD,
    ValidationResult,
    validate,
)


def _valid_raw_finding(**overrides) -> dict:
    """A raw finding dict that passes every §4.2 rule. Override fields per test."""
    base = {
        "vulnerability_id": "A03:2021",
        "severity": "High",
        "confidence": "High",
        "cvss_band": "7.0-8.9",
        "affected_file": "src/handlers/login.py",
        "affected_lines": "42-55",
        "description": "SQL injection in login handler.",
        "suggested_fix": "Use a parameterised query.",
        "owasp_reference": "https://owasp.org/Top10/A03_2021-Injection/",
        "patch_file_path": "patches/A03-2021_login.patch",
        "exploit_scenario": (
            "An attacker submits username=admin' OR '1'='1 as the login payload "
            "to src/handlers/login.py, bypassing the WHERE clause."
        ),
        "verification_status": "unverified",
    }
    base.update(overrides)
    return base


# --- Result shape -----------------------------------------------------------


def test_validate_returns_validation_result_dataclass():
    result = validate([], total_source_lines=10)
    assert isinstance(result, ValidationResult)
    assert isinstance(result.valid_findings, list)
    assert isinstance(result.rejected_findings, list)
    assert isinstance(result.warnings, list)
    assert isinstance(result.scan_failed, bool)


def test_valid_finding_passes_all_rules():
    result = validate([_valid_raw_finding()], total_source_lines=100)
    assert len(result.valid_findings) == 1
    assert result.rejected_findings == []
    assert result.warnings == []
    assert result.scan_failed is False
    # Parsed into the Pydantic model.
    finding = result.valid_findings[0]
    assert finding.severity is Severity.High
    assert finding.confidence is Confidence.High
    assert finding.verification_status is VerificationStatus.unverified


# --- Rule 1: severity enum --------------------------------------------------


@pytest.mark.parametrize("bad_severity", ["critical", "CRITICAL", "Sev1", "", None, 7])
def test_rule_1_rejects_invalid_severity(bad_severity):
    raw = _valid_raw_finding(severity=bad_severity, cvss_band="9.0-10.0")
    result = validate([raw], total_source_lines=100)
    assert result.valid_findings == []
    assert raw in result.rejected_findings


# --- Rule 2: cvss_band matches severity ------------------------------------


def test_rule_2_rejects_cvss_band_mismatch():
    # High severity with Critical's band.
    raw = _valid_raw_finding(severity="High", cvss_band="9.0-10.0")
    result = validate([raw], total_source_lines=100)
    assert result.valid_findings == []
    assert raw in result.rejected_findings


def test_rule_2_accepts_en_dash_in_cvss_band():
    """§4.2 uses en-dash; we accept it as well as the ASCII hyphen."""
    raw = _valid_raw_finding(severity="High", cvss_band="7.0–8.9")  # en-dash
    result = validate([raw], total_source_lines=100)
    assert len(result.valid_findings) == 1
    assert result.rejected_findings == []


def test_rule_2_accepts_ascii_hyphen_in_cvss_band():
    raw = _valid_raw_finding(severity="High", cvss_band="7.0-8.9")  # ASCII hyphen
    result = validate([raw], total_source_lines=100)
    assert len(result.valid_findings) == 1


@pytest.mark.parametrize(
    ("severity", "band"),
    [
        ("Critical", "9.0-10.0"),
        ("High", "7.0-8.9"),
        ("Medium", "4.0-6.9"),
        ("Low", "0.1-3.9"),
    ],
)
def test_rule_2_every_severity_to_band_pair_matches(severity, band):
    raw = _valid_raw_finding(severity=severity, cvss_band=band)
    result = validate([raw], total_source_lines=100)
    assert len(result.valid_findings) == 1


# --- Rule 3: vulnerability_id OWASP format ---------------------------------


@pytest.mark.parametrize(
    "valid_id",
    ["A01:2021", "A03:2021", "A10:2021", "LLM01:2025", "LLM10:2025", "SECRET-001"],
)
def test_rule_3_accepts_owasp_id_formats(valid_id):
    raw = _valid_raw_finding(vulnerability_id=valid_id)
    # The exploit scenario must reference affected_file; the default already does.
    result = validate([raw], total_source_lines=100)
    assert len(result.valid_findings) == 1, f"{valid_id} should be accepted"


@pytest.mark.parametrize(
    "bad_id",
    [
        "A3:2021",       # missing leading zero
        "A03-2021",      # wrong separator
        "CVE-2024-1234", # wrong taxonomy
        "secret-001",    # wrong case
        "SECRET-002",    # not in allowed list (per BR-003 minimum is SECRET-001)
        "",
        None,
        1234,
    ],
)
def test_rule_3_rejects_non_owasp_id(bad_id):
    raw = _valid_raw_finding(vulnerability_id=bad_id)
    result = validate([raw], total_source_lines=100)
    assert result.valid_findings == []
    assert raw in result.rejected_findings


# --- Rule 4: exploit_scenario well-formedness ------------------------------


def test_rule_4_rejects_empty_exploit_scenario():
    raw = _valid_raw_finding(exploit_scenario="")
    result = validate([raw], total_source_lines=100)
    assert result.valid_findings == []
    assert raw in result.rejected_findings


def test_rule_4_rejects_whitespace_only_exploit_scenario():
    raw = _valid_raw_finding(exploit_scenario="   \n\n\t  ")
    result = validate([raw], total_source_lines=100)
    assert result.valid_findings == []


def test_rule_4_rejects_exploit_scenario_missing_affected_file_reference():
    raw = _valid_raw_finding(
        affected_file="src/handlers/login.py",
        # Scenario doesn't mention src/handlers/login.py — should be rejected.
        exploit_scenario=(
            "An attacker submits a payload that triggers an injection in "
            "the login handler."
        ),
    )
    result = validate([raw], total_source_lines=100)
    assert result.valid_findings == []
    assert raw in result.rejected_findings


def test_rule_4_rejects_exploit_scenario_missing_attacker_action_keyword():
    raw = _valid_raw_finding(
        # Mentions affected_file but no keyword from the required list.
        exploit_scenario=(
            "An attacker could exploit this in src/handlers/login.py."
        ),
    )
    result = validate([raw], total_source_lines=100)
    assert result.valid_findings == []
    assert raw in result.rejected_findings


@pytest.mark.parametrize(
    "keyword",
    ["payload", "request", "query", "parameter", "injection", "bypass", "forge"],
)
def test_rule_4_accepts_each_attacker_action_keyword(keyword):
    raw = _valid_raw_finding(
        affected_file="src/x.py",
        exploit_scenario=f"Attacker sends a {keyword} to src/x.py to exploit.",
    )
    result = validate([raw], total_source_lines=100)
    assert len(result.valid_findings) == 1, f"keyword {keyword!r} should be accepted"


# --- Rule 5: verification_status enum --------------------------------------


@pytest.mark.parametrize("bad_status", ["VERIFIED", "passed", "", None, 1])
def test_rule_5_rejects_invalid_verification_status(bad_status):
    raw = _valid_raw_finding(verification_status=bad_status)
    result = validate([raw], total_source_lines=100)
    assert result.valid_findings == []
    assert raw in result.rejected_findings


@pytest.mark.parametrize("status", ["verified", "unverified", "conflicting"])
def test_rule_5_accepts_each_verification_status(status):
    raw = _valid_raw_finding(verification_status=status)
    result = validate([raw], total_source_lines=100)
    assert len(result.valid_findings) == 1


# --- Pydantic backstop: missing required field ----------------------------


def test_pydantic_rejects_finding_missing_required_field():
    raw = _valid_raw_finding()
    del raw["description"]
    result = validate([raw], total_source_lines=100)
    assert result.valid_findings == []
    assert raw in result.rejected_findings


# --- Rule 6: BR-009 (Critical findings on gate path need verification) ----


def test_rule_6_critical_unverified_on_gate_path_marks_scan_failed():
    raw = _valid_raw_finding(
        severity="Critical",
        cvss_band="9.0-10.0",
        verification_status="unverified",
    )
    result = validate([raw], total_source_lines=100, is_gate_path=True)
    assert result.scan_failed is True
    # The finding is still surfaced in the valid list — the gate just can't decide on it.
    assert len(result.valid_findings) == 1
    assert any("BR-009" in w for w in result.warnings)


def test_rule_6_critical_verified_on_gate_path_does_not_fail():
    raw = _valid_raw_finding(
        severity="Critical",
        cvss_band="9.0-10.0",
        verification_status="verified",
    )
    result = validate([raw], total_source_lines=100, is_gate_path=True)
    assert result.scan_failed is False
    assert len(result.valid_findings) == 1


def test_rule_6_critical_conflicting_on_gate_path_does_not_fail():
    raw = _valid_raw_finding(
        severity="Critical",
        cvss_band="9.0-10.0",
        verification_status="conflicting",
    )
    result = validate([raw], total_source_lines=100, is_gate_path=True)
    assert result.scan_failed is False


def test_rule_6_critical_unverified_on_skill_path_does_not_fail():
    """Skill path skips BR-009 by design — unverified Critical is acceptable."""
    raw = _valid_raw_finding(
        severity="Critical",
        cvss_band="9.0-10.0",
        verification_status="unverified",
    )
    result = validate([raw], total_source_lines=100)  # default is_gate_path=False
    assert result.scan_failed is False


def test_rule_6_high_unverified_on_gate_path_does_not_fail():
    """Only Critical findings require verification — High is fine unverified."""
    raw = _valid_raw_finding(severity="High", cvss_band="7.0-8.9")
    result = validate([raw], total_source_lines=100, is_gate_path=True)
    assert result.scan_failed is False


# --- Rule 7: empty-findings warning ----------------------------------------


def test_rule_7_empty_findings_with_large_codebase_emits_warning():
    result = validate([], total_source_lines=EMPTY_FINDINGS_LINE_THRESHOLD + 1)
    assert any("non-trivial codebase" in w for w in result.warnings)
    assert result.scan_failed is False


def test_rule_7_empty_findings_with_small_codebase_emits_no_warning():
    result = validate([], total_source_lines=EMPTY_FINDINGS_LINE_THRESHOLD)
    assert result.warnings == []


def test_rule_7_empty_findings_with_exact_threshold_emits_no_warning():
    """Threshold is strictly greater-than per §4.2 ('more than 500 lines')."""
    result = validate([], total_source_lines=500)
    assert result.warnings == []


def test_rule_7_non_empty_findings_never_emits_empty_warning():
    raw = _valid_raw_finding()
    result = validate([raw], total_source_lines=10_000)
    assert not any("non-trivial" in w for w in result.warnings)


# --- Mixed input behaviour --------------------------------------------------


def test_mixed_findings_partitioned_correctly():
    good = _valid_raw_finding(vulnerability_id="A01:2021")
    bad_severity = _valid_raw_finding(severity="WhatEvenIsThis")
    bad_id = _valid_raw_finding(vulnerability_id="not-an-owasp-id")

    result = validate([good, bad_severity, bad_id], total_source_lines=100)
    assert len(result.valid_findings) == 1
    assert result.valid_findings[0].vulnerability_id == "A01:2021"
    assert len(result.rejected_findings) == 2


def test_validator_does_not_mutate_input_dicts():
    raw = _valid_raw_finding()
    snapshot = deepcopy(raw)
    validate([raw], total_source_lines=100)
    assert raw == snapshot
