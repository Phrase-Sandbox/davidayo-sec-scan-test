"""Tests for the advisory lane (real+medium → advisory_real)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from security_scanner.shared.models.enums import VerificationStatus
from security_scanner.shared.scanners.types import CandidateForVerification
from security_scanner.shared.severity.mapping import is_advisory_only, should_block
from security_scanner.shared.verification.vulns import (
    _verify_batch,
    verify_vuln_candidates,
)
from security_scanner.shared.models.enums import Confidence, Severity
from security_scanner.shared.models.finding import VulnerabilityFinding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _candidate(
    file: str = "app/views.py",
    vuln_class: str = "idor",
    severity: str = "High",
) -> CandidateForVerification:
    return CandidateForVerification(
        file=file,
        vuln_class=vuln_class,
        line_start=10,
        line_end=20,
        severity=severity,
        confidence="High",
        description="IDOR in record access",
    )


def _mock_client_response(verdict: str, confidence: str) -> MagicMock:
    """Return a mock ClaudeClient that always returns a single-verdict response."""
    client = MagicMock()
    client.ask.return_value = (
        f"VERDICT #1: {verdict}\n"
        f"CONFIDENCE #1: {confidence}\n"
        f"REASON #1: Test reason.\n"
    )
    return client


# ---------------------------------------------------------------------------
# Tests: advisory_real lane
# ---------------------------------------------------------------------------

def test_real_medium_becomes_advisory_real():
    """real+medium verdict → kept as advisory_real (non-blocking)."""
    candidates = [_candidate()]
    files = {"app/views.py": "def get_record(id): return db.query(id)"}
    client = _mock_client_response("real", "medium")

    results = _verify_batch(
        candidates, files, client,
        keep_confidences=frozenset({"high"}),
        advisory_confidences=frozenset({"medium"}),
    )
    assert len(results) == 1
    finding = results[0]
    assert finding is not None
    assert finding.verification_status == VerificationStatus.advisory_real


def test_advisory_real_is_not_blocking():
    """advisory_real findings must not trigger should_block."""
    finding = VulnerabilityFinding(
        vulnerability_id="IDOR-001",
        severity=Severity.High,
        confidence=Confidence.High,
        cvss_band="7.0–8.9",
        affected_file="app/views.py",
        description="IDOR",
        suggested_fix="Add ownership check.",
        owasp_reference="https://owasp.org/",
        patch_file_path="",
        exploit_scenario="Attacker accesses other users' data.",
        verification_status=VerificationStatus.advisory_real,
    )
    assert not should_block(finding)


def test_advisory_real_is_advisory_only():
    """advisory_real findings must be flagged as advisory-only for report headers."""
    finding = VulnerabilityFinding(
        vulnerability_id="IDOR-001",
        severity=Severity.High,
        confidence=Confidence.High,
        cvss_band="7.0–8.9",
        affected_file="app/views.py",
        description="IDOR",
        suggested_fix="Add ownership check.",
        owasp_reference="https://owasp.org/",
        patch_file_path="",
        exploit_scenario="Attacker accesses other users' data.",
        verification_status=VerificationStatus.advisory_real,
    )
    assert is_advisory_only(finding)


def test_real_high_becomes_verified():
    """real+high verdict → verified (blocking-eligible)."""
    candidates = [_candidate()]
    files = {"app/views.py": "def get_record(id): return db.query(id)"}
    client = _mock_client_response("real", "high")

    results = _verify_batch(
        candidates, files, client,
        keep_confidences=frozenset({"high"}),
        advisory_confidences=frozenset({"medium"}),
    )
    assert results[0] is not None
    assert results[0].verification_status == VerificationStatus.verified


def test_false_positive_dropped():
    """false_positive verdict → None (dropped)."""
    candidates = [_candidate()]
    files = {"app/views.py": "def get_record(id): return db.query(id)"}
    client = _mock_client_response("false_positive", "high")

    results = _verify_batch(
        candidates, files, client,
        keep_confidences=frozenset({"high"}),
        advisory_confidences=frozenset({"medium"}),
    )
    assert results[0] is None


def test_real_low_dropped_on_normal_path():
    """real+low verdict → dropped (below both thresholds, not a high-risk path)."""
    candidates = [_candidate(file="utils/helpers.py")]
    files = {"utils/helpers.py": "def helper(): pass"}
    client = _mock_client_response("real", "low")

    results = _verify_batch(
        candidates, files, client,
        keep_confidences=frozenset({"high"}),
        advisory_confidences=frozenset({"medium"}),
    )
    assert results[0] is None


def test_verify_vuln_candidates_returns_advisory_real():
    """End-to-end: verify_vuln_candidates returns advisory_real when explicitly configured.

    The code default is now keep={high,medium}, advisory={low}. To test the advisory_real
    path we explicitly configure keep={high} and advisory={medium}.
    """
    candidates = [_candidate()]
    files = {"app/views.py": "def get_record(id): return db.query(id)"}
    client = _mock_client_response("real", "medium")

    results = verify_vuln_candidates(
        candidates, files, client,
        keep_confidences=frozenset({"high"}),
        advisory_confidences=frozenset({"medium"}),
    )
    advisory = [f for f in results if f.verification_status == VerificationStatus.advisory_real]
    assert len(advisory) == 1


def test_verify_vuln_candidates_medium_verified_by_default():
    """With the new default threshold (keep={high,medium}), a real/medium finding is verified."""
    candidates = [_candidate()]
    files = {"app/views.py": "def get_record(id): return db.query(id)"}
    client = _mock_client_response("real", "medium")

    results = verify_vuln_candidates(candidates, files, client)
    verified = [f for f in results if f.verification_status == VerificationStatus.verified]
    assert len(verified) == 1
