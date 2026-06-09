"""Tests for parallel blind verification of Critical findings (BR-009)."""

from unittest.mock import MagicMock

import pytest

from security_scanner.shared.claude.client import (
    ClaudeClient,
    ClaudeTimeoutError,
    ClaudeUnavailableError,
)
from security_scanner.shared.models.enums import (
    Confidence,
    Severity,
    VerificationStatus,
)
from security_scanner.shared.models.finding import VulnerabilityFinding
from security_scanner.shared.verification.parallel import (
    verify_critical_findings,
)

# --- Fixtures ----------------------------------------------------------------


_FIRST_PASS_DESCRIPTION = "FIRST_PASS_DESCRIPTION_MARKER_AAA"
_FIRST_PASS_EXPLOIT = "FIRST_PASS_EXPLOIT_SCENARIO_MARKER_BBB"
_FIRST_PASS_FIX = "FIRST_PASS_SUGGESTED_FIX_MARKER_CCC"


def _critical_finding(
    *,
    affected_file: str = "src/handlers/login.py",
    vulnerability_id: str = "A03:2021",
) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        vulnerability_id=vulnerability_id,
        severity=Severity.Critical,
        confidence=Confidence.High,
        cvss_band="9.0-10.0",
        affected_file=affected_file,
        affected_lines="42-55",
        description=_FIRST_PASS_DESCRIPTION,
        suggested_fix=_FIRST_PASS_FIX,
        owasp_reference="https://owasp.org/Top10/A03_2021-Injection/",
        patch_file_path="patches/A03-2021.patch",
        exploit_scenario=_FIRST_PASS_EXPLOIT,
        verification_status=VerificationStatus.unverified,
    )


def _high_finding(affected_file: str = "src/x.py") -> VulnerabilityFinding:
    return VulnerabilityFinding(
        vulnerability_id="A05:2021",
        severity=Severity.High,
        confidence=Confidence.High,
        cvss_band="7.0-8.9",
        affected_file=affected_file,
        affected_lines="10",
        description="High-sev finding",
        suggested_fix="Fix it",
        owasp_reference="https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        patch_file_path="patches/A05.patch",
        exploit_scenario=(f"Attacker sends a request to {affected_file} to bypass config."),
        verification_status=VerificationStatus.unverified,
    )


def _mock_client_returning(text: str) -> MagicMock:
    mock = MagicMock(spec=ClaudeClient)
    mock.ask.return_value = text
    return mock


def _mock_client_raising(exc: Exception) -> MagicMock:
    mock = MagicMock(spec=ClaudeClient)
    mock.ask.side_effect = exc
    return mock


_FILES = {"src/handlers/login.py": "def login(user):\n    return run(user)\n"}


# --- Verdict mapping --------------------------------------------------------


def test_verified_when_second_pass_says_yes():
    finding = _critical_finding()
    client = _mock_client_returning(
        "VERDICT: yes\nThis is a real SQL injection in the login handler."
    )

    out = verify_critical_findings([finding], _FILES, client)
    assert len(out) == 1
    assert out[0].verification_status is VerificationStatus.verified


def test_conflicting_when_second_pass_says_no():
    finding = _critical_finding()
    client = _mock_client_returning("VERDICT: no\nThe input is sanitised by middleware upstream.")

    out = verify_critical_findings([finding], _FILES, client)
    assert out[0].verification_status is VerificationStatus.conflicting


def test_conflicting_when_second_pass_says_uncertain():
    finding = _critical_finding()
    client = _mock_client_returning(
        "VERDICT: uncertain\nCannot determine without seeing the ORM layer."
    )

    out = verify_critical_findings([finding], _FILES, client)
    assert out[0].verification_status is VerificationStatus.conflicting


def test_conflicting_on_parse_failure():
    """Garbage response with no VERDICT line → conflicting (fail-safe)."""
    finding = _critical_finding()
    client = _mock_client_returning("Hello, I cannot determine the answer right now.")

    out = verify_critical_findings([finding], _FILES, client)
    assert out[0].verification_status is VerificationStatus.conflicting


@pytest.mark.parametrize(
    "verdict_text",
    [
        "verdict: yes",
        "VERDICT:yes",
        "  VERDICT: YES",
        "VERDICT: Yes\nreason ...",
    ],
)
def test_verdict_parsing_is_case_and_whitespace_tolerant(verdict_text):
    finding = _critical_finding()
    client = _mock_client_returning(verdict_text)

    out = verify_critical_findings([finding], _FILES, client)
    assert out[0].verification_status is VerificationStatus.verified


# --- Claude error fail-safes -----------------------------------------------


def test_claude_unavailable_returns_conflicting_not_scan_failed():
    finding = _critical_finding()
    client = _mock_client_raising(ClaudeUnavailableError("retries exhausted"))

    out = verify_critical_findings([finding], _FILES, client)
    # Fail-safe: finding stays in the list, marked conflicting.
    assert len(out) == 1
    assert out[0].verification_status is VerificationStatus.conflicting


def test_claude_timeout_returns_conflicting():
    finding = _critical_finding()
    client = _mock_client_raising(ClaudeTimeoutError("30s timeout"))

    out = verify_critical_findings([finding], _FILES, client)
    assert out[0].verification_status is VerificationStatus.conflicting


def test_missing_file_in_files_dict_returns_conflicting_without_calling_claude():
    finding = _critical_finding(affected_file="src/not_fetched.py")
    client = _mock_client_returning("VERDICT: yes")

    out = verify_critical_findings([finding], _FILES, client)
    assert out[0].verification_status is VerificationStatus.conflicting
    # The verifier short-circuits and does NOT make the Claude call.
    client.ask.assert_not_called()


# --- BR-009 invariant: blind prompt ----------------------------------------


def test_blind_prompt_does_not_contain_first_pass_reasoning():
    finding = _critical_finding()
    client = _mock_client_returning("VERDICT: yes")

    verify_critical_findings([finding], _FILES, client)

    # Inspect the user_message argument passed to ask().
    call = client.ask.call_args
    user_message = call.args[1] if len(call.args) >= 2 else call.kwargs["user_message"]
    assert _FIRST_PASS_DESCRIPTION not in user_message
    assert _FIRST_PASS_EXPLOIT not in user_message
    assert _FIRST_PASS_FIX not in user_message


def test_blind_prompt_does_contain_required_metadata():
    finding = _critical_finding(vulnerability_id="A07:2021")
    client = _mock_client_returning("VERDICT: yes")

    verify_critical_findings([finding], _FILES, client)
    call = client.ask.call_args
    user_message = call.args[1] if len(call.args) >= 2 else call.kwargs["user_message"]
    assert "A07:2021" in user_message
    assert "42-55" in user_message
    # The file content is wrapped in <source_code> tags.
    assert '<source_code filename="src/handlers/login.py">' in user_message


# --- Non-Critical passthrough ----------------------------------------------


def test_non_critical_findings_passed_through_unchanged_without_claude_call():
    high = _high_finding()
    client = _mock_client_returning("VERDICT: yes")

    out = verify_critical_findings([high], _FILES, client)
    assert out == [high]
    client.ask.assert_not_called()


def test_mixed_critical_and_non_critical_partitioned_correctly():
    crit = _critical_finding()
    high = _high_finding()
    client = _mock_client_returning("VERDICT: yes")

    out = verify_critical_findings([high, crit, high], _FILES, client)
    assert len(out) == 3
    assert out[0] == high
    assert out[1].verification_status is VerificationStatus.verified
    assert out[2] == high
    # Only the Critical triggered the Claude call.
    assert client.ask.call_count == 1


# --- Output invariants -----------------------------------------------------


def test_order_preserved():
    files = {
        "a.py": "x = 1",
        "b.py": "y = 2",
        "c.py": "z = 3",
    }
    findings = [
        _critical_finding(affected_file="a.py", vulnerability_id="A01:2021"),
        _critical_finding(affected_file="b.py", vulnerability_id="A02:2021"),
        _critical_finding(affected_file="c.py", vulnerability_id="A03:2021"),
    ]
    client = _mock_client_returning("VERDICT: yes")

    out = verify_critical_findings(findings, files, client)
    assert [f.vulnerability_id for f in out] == ["A01:2021", "A02:2021", "A03:2021"]


def test_original_findings_are_not_mutated():
    finding = _critical_finding()
    client = _mock_client_returning("VERDICT: yes")

    verify_critical_findings([finding], _FILES, client)
    # The input instance is untouched.
    assert finding.verification_status is VerificationStatus.unverified


def test_empty_input_returns_empty_list():
    client = _mock_client_returning("VERDICT: yes")
    assert verify_critical_findings([], {}, client) == []
    client.ask.assert_not_called()


def test_each_critical_finding_makes_exactly_one_ask_call():
    files = {f"f_{i}.py": "x = 1" for i in range(5)}
    findings = [
        _critical_finding(affected_file=f"f_{i}.py", vulnerability_id=f"A0{i + 1}:2021")
        for i in range(5)
    ]
    client = _mock_client_returning("VERDICT: yes")

    verify_critical_findings(findings, files, client)
    assert client.ask.call_count == 5
