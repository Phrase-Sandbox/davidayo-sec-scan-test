"""Tests for the severity / confidence / verification mapping (§4.2, BR-001-A)."""

import pytest

from security_scanner.shared.models.enums import (
    Confidence,
    Severity,
    VerificationStatus,
)
from security_scanner.shared.models.finding import VulnerabilityFinding
from security_scanner.shared.severity.mapping import (
    is_advisory_only,
    severity_to_cvss_band,
    should_block,
)

# --- Helper fixture ---------------------------------------------------------


def _finding(
    severity: Severity,
    confidence: Confidence = Confidence.High,
    verification_status: VerificationStatus = VerificationStatus.unverified,
) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        vulnerability_id="A03:2021",
        severity=severity,
        confidence=confidence,
        cvss_band=severity_to_cvss_band(severity),
        affected_file="src/app.py",
        affected_lines="10",
        description="dummy",
        suggested_fix="dummy",
        owasp_reference="https://owasp.org/Top10/",
        patch_file_path="patches/x.patch",
        exploit_scenario="Attacker sends a payload to src/app.py via login parameter.",
        verification_status=verification_status,
    )


# --- severity_to_cvss_band --------------------------------------------------


@pytest.mark.parametrize(
    ("severity", "band"),
    [
        (Severity.Critical, "9.0–10.0"),  # en-dash
        (Severity.High, "7.0–8.9"),
        (Severity.Medium, "4.0–6.9"),
        (Severity.Low, "0.1–3.9"),
    ],
)
def test_severity_to_cvss_band_matches_spec_table(severity, band):
    assert severity_to_cvss_band(severity) == band


def test_severity_to_cvss_band_uses_en_dash_not_hyphen():
    """§4.2 uses an en-dash in the band strings; this module emits the canonical form."""
    for severity in Severity:
        band = severity_to_cvss_band(severity)
        assert "–" in band  # en-dash U+2013
        assert "-" not in band  # plain hyphen-minus must be absent


# --- should_block: positive cases -------------------------------------------


def test_should_block_critical_high_confidence_verified_blocks():
    finding = _finding(Severity.Critical, Confidence.High, VerificationStatus.verified)
    assert should_block(finding) is True


def test_should_block_high_severity_high_confidence_blocks():
    """High + High confidence blocks regardless of verification_status (BR-009 is Critical-only).

    v2 note: advisory_real never blocks (it's the auto-triaged advisory lane).
    """
    for vs in VerificationStatus:
        if vs == VerificationStatus.advisory_real:
            continue  # advisory_real is always non-blocking regardless of severity
        finding = _finding(Severity.High, Confidence.High, vs)
        assert should_block(finding) is True, f"High/High should block when verif={vs.value}"


def test_should_block_false_for_advisory_real_regardless_of_severity():
    """advisory_real findings never block — they are auto-triaged advisory lane."""
    for severity in Severity:
        for confidence in Confidence:
            finding = _finding(severity, confidence, VerificationStatus.advisory_real)
            assert should_block(finding) is False, (
                f"advisory_real should not block: severity={severity.value}, conf={confidence.value}"
            )


def test_is_advisory_only_true_for_advisory_real_regardless_of_severity():
    """advisory_real findings are always advisory_only."""
    for severity in Severity:
        for confidence in Confidence:
            finding = _finding(severity, confidence, VerificationStatus.advisory_real)
            assert is_advisory_only(finding) is True, (
                f"advisory_real should be advisory_only: severity={severity.value}"
            )


# --- should_block: negatives caused by BR-001-A (confidence gate) ----------


@pytest.mark.parametrize("confidence", [Confidence.Medium, Confidence.Low])
@pytest.mark.parametrize("severity", [Severity.Critical, Severity.High])
def test_should_block_returns_false_when_confidence_not_high(severity, confidence):
    """BR-001-A — High/Critical with Medium/Low confidence is advisory only."""
    finding = _finding(severity, confidence, VerificationStatus.verified)
    assert should_block(finding) is False


# --- should_block: negatives caused by BR-009 (verification gate) ---------


@pytest.mark.parametrize(
    "verification_status",
    [VerificationStatus.unverified, VerificationStatus.conflicting],
)
def test_should_block_returns_false_for_critical_without_verified_status(
    verification_status,
):
    """BR-009 — Critical findings must be 'verified' before they block."""
    finding = _finding(Severity.Critical, Confidence.High, verification_status)
    assert should_block(finding) is False


# --- should_block: negatives caused by severity ----------------------------


@pytest.mark.parametrize("severity", [Severity.Medium, Severity.Low])
def test_should_block_returns_false_for_non_high_severity(severity):
    finding = _finding(severity, Confidence.High, VerificationStatus.verified)
    assert should_block(finding) is False


# --- is_advisory_only: positive cases (BR-001-A demotion) ------------------


@pytest.mark.parametrize("severity", [Severity.Critical, Severity.High])
@pytest.mark.parametrize("confidence", [Confidence.Medium, Confidence.Low])
def test_is_advisory_only_true_for_high_severity_low_confidence(severity, confidence):
    finding = _finding(severity, confidence, VerificationStatus.verified)
    assert is_advisory_only(finding) is True


# --- is_advisory_only: positive cases (BR-009 demotion) -------------------


def test_is_advisory_only_true_for_critical_with_conflicting_verification():
    finding = _finding(Severity.Critical, Confidence.High, VerificationStatus.conflicting)
    assert is_advisory_only(finding) is True


# --- is_advisory_only: negative cases --------------------------------------


def test_is_advisory_only_false_for_critical_high_confidence_verified():
    """This case blocks — it is NOT advisory."""
    finding = _finding(Severity.Critical, Confidence.High, VerificationStatus.verified)
    assert is_advisory_only(finding) is False


def test_is_advisory_only_false_for_high_severity_high_confidence():
    """High + High confidence blocks — not advisory unless explicitly set to advisory_real.

    v2 note: advisory_real is always advisory regardless of severity/confidence.
    The test excludes advisory_real which has its own separate test.
    """
    for vs in VerificationStatus:
        if vs == VerificationStatus.advisory_real:
            continue  # advisory_real is always advisory regardless of severity
        finding = _finding(Severity.High, Confidence.High, vs)
        assert is_advisory_only(finding) is False, f"High/High should not be advisory for vs={vs.value}"


def test_is_advisory_only_false_for_critical_high_confidence_unverified():
    """Critical + High + unverified does not block (BR-009) but is NOT flagged as advisory_only.

    Per the spec, the validator already sets scan_failed=True for this state (BR-009).
    Advisory_only is reserved for *demoted* findings — conflicting verification
    or low confidence — not for findings awaiting verification.
    """
    finding = _finding(Severity.Critical, Confidence.High, VerificationStatus.unverified)
    assert is_advisory_only(finding) is False


@pytest.mark.parametrize("severity", [Severity.Medium, Severity.Low])
@pytest.mark.parametrize("confidence", list(Confidence))
def test_is_advisory_only_false_for_medium_and_low_severity(severity, confidence):
    """Medium/Low are naturally advisory — they don't get the 'demoted-blocker' header warning.

    v2 note: tests only non-advisory_real statuses; advisory_real has its own test.
    """
    for vs in [VerificationStatus.verified, VerificationStatus.unverified, VerificationStatus.conflicting]:
        finding = _finding(severity, confidence, vs)
        assert is_advisory_only(finding) is False, (
            f"Medium/Low severity should not be advisory_only for vs={vs.value}"
        )


# --- Mutual exclusion sanity check -----------------------------------------


@pytest.mark.parametrize("severity", list(Severity))
@pytest.mark.parametrize("confidence", list(Confidence))
@pytest.mark.parametrize("verification_status", list(VerificationStatus))
def test_should_block_and_is_advisory_only_are_mutually_exclusive(
    severity, confidence, verification_status,
):
    """A finding can't simultaneously block *and* be flagged as demoted-to-advisory."""
    finding = _finding(severity, confidence, verification_status)
    assert not (should_block(finding) and is_advisory_only(finding))
