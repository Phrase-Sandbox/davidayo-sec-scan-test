"""Tests for the post-processing filter (§4.1 build notes, §12, §13.5)."""

import json

import pytest

from security_scanner.shared.filters.post_filter import filter_findings
from security_scanner.shared.models.enums import (
    Confidence,
    Severity,
    VerificationStatus,
)
from security_scanner.shared.models.finding import VulnerabilityFinding


def _finding(
    affected_file: str,
    *,
    confidence: Confidence = Confidence.High,
    severity: Severity = Severity.High,
    vulnerability_id: str = "A03:2021",
) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        vulnerability_id=vulnerability_id,
        severity=severity,
        confidence=confidence,
        cvss_band={
            Severity.Critical: "9.0-10.0",
            Severity.High: "7.0-8.9",
            Severity.Medium: "4.0-6.9",
            Severity.Low: "0.1-3.9",
        }[severity],
        affected_file=affected_file,
        affected_lines="42-55",
        description="SQL injection in handler.",
        suggested_fix="Use a parameterised query.",
        owasp_reference="https://owasp.org/Top10/A03_2021-Injection/",
        patch_file_path="patches/x.patch",
        exploit_scenario=(
            f"Attacker submits a crafted parameter to {affected_file} via the "
            "login payload."
        ),
        verification_status=VerificationStatus.unverified,
    )


# --- Rule 1: test / fixture / mock paths ------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        # Directory markers — leading slash variations.
        "test/foo.py",
        "tests/foo.py",
        "src/tests/foo.py",
        "a/b/c/tests/foo.py",
        "spec/foo.rb",
        "specs/foo.rb",
        "__tests__/foo.tsx",
        "frontend/__tests__/Modal.test.tsx",
        "fixtures/sample.json",
        "mocks/api.py",
        "stubs/server.js",
        # Filename suffix patterns.
        "src/handlers/login_test.py",
        "src/login_spec.rb",
        "src/components/Modal.test.js",
        "src/components/Modal.test.ts",
        "src/components/Modal.spec.js",
        "src/components/Modal.spec.ts",
    ],
)
def test_rule_1_drops_test_or_fixture_path(path):
    finding = _finding(path)
    assert filter_findings([finding]) == []


def test_rule_1_does_not_match_substring_in_directory_name():
    """``contests/`` is not ``tests/`` — exact directory segment match required."""
    finding = _finding("contests/app.py")
    assert filter_findings([finding]) == [finding]


def test_rule_1_does_not_match_filename_containing_test_substring():
    """``latest.py`` is not a test file — only the listed suffixes count."""
    finding = _finding("src/latest.py")
    assert filter_findings([finding]) == [finding]


# --- Rule 2: lockfiles & vendored dependencies -----------------------------


@pytest.mark.parametrize(
    "path",
    [
        "node_modules/express/index.js",
        "frontend/node_modules/react/index.js",
        "vendor/lib/foo.go",
        "vendor/auto/bar.py",
        "third_party/some_lib/index.py",
        "package-lock.json",
        "yarn.lock",
        "poetry.lock",
        "Pipfile.lock",
    ],
)
def test_rule_2_drops_lockfile_or_vendored_path(path):
    finding = _finding(path)
    assert filter_findings([finding]) == []


# --- Rule 3: low confidence ------------------------------------------------


def test_rule_3_drops_low_confidence_finding_in_source_path():
    finding = _finding("src/app.py", confidence=Confidence.Low)
    assert filter_findings([finding]) == []


def test_rule_3_keeps_medium_confidence_finding():
    finding = _finding("src/app.py", confidence=Confidence.Medium)
    assert filter_findings([finding]) == [finding]


def test_rule_3_keeps_high_confidence_finding():
    finding = _finding("src/app.py", confidence=Confidence.High)
    assert filter_findings([finding]) == [finding]


# --- Interaction between rules ---------------------------------------------


def test_high_confidence_finding_in_test_path_is_still_dropped():
    """Rule 1 wins over confidence — even High-confidence test-code findings are noise."""
    finding = _finding("tests/test_login.py", confidence=Confidence.High)
    assert filter_findings([finding]) == []


def test_high_confidence_finding_in_source_path_is_kept():
    finding = _finding("src/handlers/login.py", confidence=Confidence.High)
    assert filter_findings([finding]) == [finding]


# --- Mixed input & invariants ----------------------------------------------


def test_mixed_input_correctly_partitioned():
    keep_1 = _finding("src/app.py", confidence=Confidence.High)
    keep_2 = _finding("src/handlers/login.py", confidence=Confidence.Medium)
    drop_test = _finding("tests/test_app.py", confidence=Confidence.High)
    drop_lock = _finding("yarn.lock")
    drop_low = _finding("src/x.py", confidence=Confidence.Low)

    survivors = filter_findings([keep_1, keep_2, drop_test, drop_lock, drop_low])
    assert survivors == [keep_1, keep_2]


def test_input_list_is_not_mutated():
    findings = [
        _finding("tests/foo.py"),
        _finding("src/app.py"),
    ]
    snapshot = list(findings)
    filter_findings(findings)
    assert findings == snapshot


def test_empty_input_returns_empty():
    assert filter_findings([]) == []


# --- Logging discipline ----------------------------------------------------


def test_drop_emits_log_with_filename_and_rule(capsys):
    finding = _finding("tests/foo.py")
    filter_findings([finding])
    captured = capsys.readouterr().out.strip().splitlines()
    assert captured, "expected at least one log line"
    record = json.loads(captured[-1])
    assert record["affected_file"] == "tests/foo.py"
    assert record["rule"] == "test_or_fixture_path"
    assert record["vulnerability_id"] == "A03:2021"


def test_log_never_contains_description_or_exploit_scenario(capsys):
    """§11 / 'What NOT to Do' #1 — finding content must not appear in logs."""
    finding = _finding("yarn.lock")
    filter_findings([finding])
    out = capsys.readouterr().out
    assert finding.description not in out
    assert finding.exploit_scenario not in out
    assert finding.suggested_fix not in out


def test_kept_finding_emits_no_drop_log(capsys):
    finding = _finding("src/app.py", confidence=Confidence.High)
    filter_findings([finding])
    out = capsys.readouterr().out
    assert "post-filter dropped" not in out
