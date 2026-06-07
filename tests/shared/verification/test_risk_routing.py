"""Tests for risk-aware routing in the verifier."""

from __future__ import annotations

from unittest.mock import MagicMock

from security_scanner.shared.context.packager import is_high_risk_path
from security_scanner.shared.models.enums import VerificationStatus
from security_scanner.shared.scanners.types import CandidateForVerification
from security_scanner.shared.verification.vulns import _verify_batch


def _candidate(file: str) -> CandidateForVerification:
    return CandidateForVerification(
        file=file,
        vuln_class="idor",
        line_start=5,
        line_end=15,
        severity="High",
        confidence="High",
        description="IDOR",
    )


def _mock_client_medium_real() -> MagicMock:
    client = MagicMock()
    client.ask.return_value = (
        "VERDICT #1: real\nCONFIDENCE #1: medium\nREASON #1: Missing ownership check.\n"
    )
    return client


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_is_high_risk_path_auth():
    assert is_high_risk_path("auth/login.py")
    assert is_high_risk_path("src/auth/token.py")


def test_is_high_risk_path_admin():
    assert is_high_risk_path("admin/views.py")
    assert is_high_risk_path("myapp/admin/api.py")


def test_is_high_risk_path_billing():
    assert is_high_risk_path("billing/charge.py")
    assert is_high_risk_path("payments/stripe.py")


def test_is_not_high_risk_path_utils():
    assert not is_high_risk_path("utils/helpers.py")
    assert not is_high_risk_path("internal/utils/parser.py")


def test_is_not_high_risk_path_models():
    assert not is_high_risk_path("models/user.py")


def test_high_risk_path_medium_becomes_verified():
    """real+medium on a high-risk path → verified (blocking)."""
    candidate = _candidate("auth/views.py")
    files = {"auth/views.py": "def login(): pass"}
    client = _mock_client_medium_real()

    results = _verify_batch(
        [candidate], files, client,
        keep_confidences=frozenset({"high"}),
        advisory_confidences=frozenset({"medium"}),
    )
    assert results[0] is not None
    # High-risk path widens keep to {high, medium}, so medium → verified.
    assert results[0].verification_status == VerificationStatus.verified


def test_normal_path_medium_becomes_advisory_real():
    """real+medium on a normal path → advisory_real (non-blocking)."""
    candidate = _candidate("internal/utils/parser.py")
    files = {"internal/utils/parser.py": "def parse(): pass"}
    client = _mock_client_medium_real()

    results = _verify_batch(
        [candidate], files, client,
        keep_confidences=frozenset({"high"}),
        advisory_confidences=frozenset({"medium"}),
    )
    assert results[0] is not None
    assert results[0].verification_status == VerificationStatus.advisory_real


def test_accounts_path_is_high_risk():
    assert is_high_risk_path("accounts/views.py")


def test_webhooks_path_is_high_risk():
    assert is_high_risk_path("webhooks/handler.py")


def test_integrations_path_is_high_risk():
    assert is_high_risk_path("integrations/stripe.py")
