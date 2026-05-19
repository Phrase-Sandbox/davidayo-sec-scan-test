"""Tests for the per-finding patch generator (§2.2 step 6, §3.1)."""

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
from security_scanner.shared.reports.patch import (
    generate_all_patches,
    generate_patch,
)

# --- Fixtures ---------------------------------------------------------------


def _finding(
    *,
    suggested_fix: str,
    affected_lines: str | None = "2-3",
    affected_file: str = "src/app.py",
    vulnerability_id: str = "A03:2021",
) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        vulnerability_id=vulnerability_id,
        severity=Severity.High,
        confidence=Confidence.High,
        cvss_band="7.0-8.9",
        affected_file=affected_file,
        affected_lines=affected_lines,
        description="SQL injection in handler.",
        suggested_fix=suggested_fix,
        owasp_reference="https://owasp.org/Top10/A03_2021-Injection/",
        patch_file_path="patches/proposed.patch",
        exploit_scenario=f"Attacker sends a payload via the login parameter to {affected_file}.",
        verification_status=VerificationStatus.unverified,
    )


def _scan_result(findings: list[VulnerabilityFinding]) -> ScanResult:
    return ScanResult(
        scan_id=UUID("12345678-1234-5678-1234-567812345678"),
        repo_url="https://github.com/Phrase-Launchpad/example",
        scan_target=ScanTarget.full_repo,
        scan_type=ScanType.deployment_gate,
        triggered_by="alice@phrase.com",
        timestamp=datetime(2026, 5, 18, tzinfo=UTC),
        findings_count=len(findings),
        gate_decision=GateDecision.advisory,
        partial_scan=False,
        unscanned_files=[],
        findings=findings,
    )


_FILE_CONTENT = "line 1\nline 2\nline 3\nline 4\nline 5\n"


# --- generate_patch: valid path ---------------------------------------------


def test_generates_unified_diff_for_simple_fix():
    finding = _finding(
        suggested_fix="Use this instead:\n```python\nnew_line_2\nnew_line_3\n```\n",
        affected_lines="2-3",
    )
    patch = generate_patch(finding, _FILE_CONTENT)
    assert patch is not None
    assert patch.startswith("--- a/src/app.py\n+++ b/src/app.py\n")
    # The old lines are marked with "-", new lines with "+".
    assert "-line 2\n" in patch
    assert "-line 3\n" in patch
    assert "+new_line_2\n" in patch
    assert "+new_line_3\n" in patch
    # Surrounding context shows up but the original file is not duplicated.
    assert patch.count("--- a/src/app.py") == 1


def test_generates_patch_for_single_line_range():
    finding = _finding(
        suggested_fix="```python\nreplacement\n```",
        affected_lines="3",
    )
    patch = generate_patch(finding, _FILE_CONTENT)
    assert patch is not None
    assert "-line 3\n" in patch
    assert "+replacement\n" in patch


def test_extracts_code_block_with_language_tag():
    finding = _finding(
        suggested_fix="Try:\n```python\nfixed = 1\n```",
        affected_lines="2",
    )
    patch = generate_patch(finding, _FILE_CONTENT)
    assert patch is not None
    assert "+fixed = 1\n" in patch


def test_extracts_code_block_with_no_language_tag():
    finding = _finding(
        suggested_fix="```\nfixed_code\n```",
        affected_lines="2",
    )
    patch = generate_patch(finding, _FILE_CONTENT)
    assert patch is not None
    assert "+fixed_code\n" in patch


def test_uses_first_code_block_when_multiple_present():
    finding = _finding(
        suggested_fix="```\nFIRST\n```\n\nor maybe\n\n```\nSECOND\n```",
        affected_lines="2",
    )
    patch = generate_patch(finding, _FILE_CONTENT)
    assert patch is not None
    assert "+FIRST\n" in patch
    assert "+SECOND\n" not in patch


def test_accepts_en_dash_in_affected_lines():
    finding = _finding(
        suggested_fix="```\nreplacement\n```",
        affected_lines="2–3",  # en-dash
    )
    patch = generate_patch(finding, _FILE_CONTENT)
    assert patch is not None
    assert "-line 2\n" in patch
    assert "-line 3\n" in patch


# --- generate_patch: None paths --------------------------------------------


def test_returns_none_for_architectural_fix_with_no_code_block():
    finding = _finding(
        suggested_fix=(
            "Refactor the authentication module to use the centralised "
            "middleware pattern. This requires coordinating with the "
            "frontend team before any code changes."
        ),
    )
    assert generate_patch(finding, _FILE_CONTENT) is None
    # patch_file_path is cleared as a side effect.
    assert finding.patch_file_path == ""


def test_returns_none_when_affected_lines_is_none():
    finding = _finding(
        suggested_fix="```\nfix\n```",
        affected_lines=None,
    )
    assert generate_patch(finding, _FILE_CONTENT) is None
    assert finding.patch_file_path == ""


def test_returns_none_for_unparseable_affected_lines():
    finding = _finding(
        suggested_fix="```\nfix\n```",
        affected_lines="not a number",
    )
    assert generate_patch(finding, _FILE_CONTENT) is None
    assert finding.patch_file_path == ""


def test_returns_none_when_line_range_exceeds_file_length():
    finding = _finding(
        suggested_fix="```\nfix\n```",
        affected_lines="100-200",
    )
    assert generate_patch(finding, _FILE_CONTENT) is None
    assert finding.patch_file_path == ""


def test_returns_none_when_start_greater_than_end():
    finding = _finding(
        suggested_fix="```\nfix\n```",
        affected_lines="5-2",
    )
    assert generate_patch(finding, _FILE_CONTENT) is None


# --- Patch content invariants ----------------------------------------------


def test_patch_does_not_contain_full_file_unchanged_regions():
    """n=3 context — for a 100-line file, the patch must NOT include all 100 lines."""
    long_file = "\n".join(f"line {i}" for i in range(1, 101)) + "\n"
    finding = _finding(
        suggested_fix="```\nreplacement\n```",
        affected_lines="50",
    )
    patch = generate_patch(finding, long_file)
    assert patch is not None
    # Lines from the start and end of the file are NOT included as context.
    assert "line 1\n" not in patch
    assert "line 100\n" not in patch
    # But the context near the change IS present.
    assert "line 49\n" in patch
    assert "line 51\n" in patch


# --- generate_all_patches --------------------------------------------------


def test_generate_all_patches_filename_format():
    finding = _finding(
        suggested_fix="```\nfix\n```",
        affected_lines="2",
    )
    result = _scan_result([finding])
    patches = generate_all_patches(result, {"src/app.py": _FILE_CONTENT})

    expected_filename = "12345678-1234-5678-1234-567812345678_0_app.py.patch"
    assert expected_filename in patches
    # The finding's patch_file_path is updated to match.
    assert finding.patch_file_path == expected_filename


def test_generate_all_patches_returns_one_entry_per_patchable_finding():
    f1 = _finding(suggested_fix="```\nA\n```", affected_lines="2", vulnerability_id="A01:2021")
    f2 = _finding(suggested_fix="```\nB\n```", affected_lines="3", vulnerability_id="A02:2021")
    result = _scan_result([f1, f2])
    patches = generate_all_patches(result, {"src/app.py": _FILE_CONTENT})

    assert len(patches) == 2
    assert any("_0_app.py.patch" in name for name in patches)
    assert any("_1_app.py.patch" in name for name in patches)


def test_generate_all_patches_skips_findings_with_no_code_block():
    patchable = _finding(
        suggested_fix="```\nA\n```",
        affected_lines="2",
        vulnerability_id="A01:2021",
    )
    architectural = _finding(
        suggested_fix="Restructure the auth flow.",
        affected_lines="3",
        vulnerability_id="A02:2021",
    )
    result = _scan_result([patchable, architectural])
    patches = generate_all_patches(result, {"src/app.py": _FILE_CONTENT})

    assert len(patches) == 1
    assert patchable.patch_file_path != ""
    assert architectural.patch_file_path == ""


def test_generate_all_patches_skips_findings_with_missing_file_content():
    finding = _finding(
        suggested_fix="```\nA\n```",
        affected_lines="2",
        affected_file="src/not_fetched.py",
    )
    result = _scan_result([finding])
    patches = generate_all_patches(result, {"src/app.py": _FILE_CONTENT})

    assert patches == {}
    assert finding.patch_file_path == ""


def test_generate_all_patches_uses_basename_only_in_filename():
    """A nested path like ``src/handlers/login.py`` shows up as just ``login.py``."""
    finding = _finding(
        suggested_fix="```\nA\n```",
        affected_lines="2",
        affected_file="src/handlers/login.py",
    )
    result = _scan_result([finding])
    patches = generate_all_patches(result, {"src/handlers/login.py": _FILE_CONTENT})
    assert any(name.endswith("_0_login.py.patch") for name in patches)
