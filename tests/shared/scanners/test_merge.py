"""Tests for LLM+scanner merge logic."""

from __future__ import annotations

from security_scanner.shared.models.enums import Confidence, Severity, VerificationStatus
from security_scanner.shared.models.finding import VulnerabilityFinding
from security_scanner.shared.scanners.merge import merge_with_llm_findings
from security_scanner.shared.scanners.models import AggregatedCandidate


def _llm_finding(
    file: str = "app.py",
    vuln_id: str = "A03:2021",
    lines: str = "10",
    description: str = "SQL injection",
    exploit: str = "payload injection",
    fix: str = "use parameterised queries",
) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        vulnerability_id=vuln_id,
        severity=Severity.High,
        confidence=Confidence.High,
        cvss_band="7.0-8.9",
        affected_file=file,
        affected_lines=lines,
        description=description,
        suggested_fix=fix,
        owasp_reference="https://owasp.org/Top10/A03_2021-Injection/",
        patch_file_path="",
        exploit_scenario=exploit,
        verification_status=VerificationStatus.unverified,
    )


def _agg_candidate(
    file: str = "app.py",
    vuln_class: str = "sqli",
    ls: int = 10,
    le: int = 10,
    sources: list[str] | None = None,
) -> AggregatedCandidate:
    return AggregatedCandidate(
        vuln_class=vuln_class,
        file=file,
        line_start=ls,
        line_end=le,
        message="SQL injection found",
        sources=sources or ["bandit"],
        consensus_score=len(sources or ["bandit"]),
        raw_rule_ids=["B608"],
    )


def test_claude_only_finding_passes_through() -> None:
    """A Claude finding with no scanner match becomes a claude-only candidate."""
    llm = [_llm_finding()]
    result = merge_with_llm_findings(llm, [])
    assert len(result) == 1
    assert result[0].sources == ["claude"]
    assert result[0].consensus_score == 1


def test_scanner_only_finding_passes_through() -> None:
    """A scanner candidate with no Claude match becomes a scanner-only candidate."""
    agg = [_agg_candidate()]
    result = merge_with_llm_findings([], agg)
    assert len(result) == 1
    assert "bandit" in result[0].sources
    assert result[0].sources[0] != "claude"


def test_overlapping_findings_merge() -> None:
    """Claude + scanner on the same location merge into one candidate."""
    llm = [_llm_finding(lines="10")]
    agg = [_agg_candidate(ls=10, le=10)]
    result = merge_with_llm_findings(llm, agg)
    assert len(result) == 1
    c = result[0]
    assert "claude" in c.sources
    assert "bandit" in c.sources
    assert c.consensus_score >= 2


def test_claude_fields_preserved_on_merge() -> None:
    """After merging, Claude's description/exploit/fix are preserved."""
    llm = [_llm_finding(
        description="Specific SQLi description",
        exploit="Exploit via payload",
        fix="Fix via parameterised",
    )]
    agg = [_agg_candidate(ls=10, le=10)]
    result = merge_with_llm_findings(llm, agg)
    assert result[0].description == "Specific SQLi description"
    assert result[0].exploit_scenario == "Exploit via payload"
    assert result[0].suggested_fix == "Fix via parameterised"


def test_non_overlapping_lines_stay_separate() -> None:
    """Claude on line 10, scanner on line 50 → two separate candidates."""
    llm = [_llm_finding(lines="10")]
    agg = [_agg_candidate(ls=50, le=50)]
    result = merge_with_llm_findings(llm, agg)
    assert len(result) == 2


def test_different_files_stay_separate() -> None:
    """Claude in app.py, scanner in models.py → two separate candidates."""
    llm = [_llm_finding(file="app.py", lines="10")]
    agg = [_agg_candidate(file="models.py", ls=10, le=10)]
    result = merge_with_llm_findings(llm, agg)
    assert len(result) == 2


def test_empty_inputs_returns_empty() -> None:
    assert merge_with_llm_findings([], []) == []


# --- A03:2021 multi-class merge (XSS / command injection / code injection) --


def test_a03_xss_llm_finding_merges_with_xss_scanner_candidate() -> None:
    """LLM A03:2021 XSS finding merges with a scanner 'xss' candidate at the same lines."""
    llm = [_llm_finding(
        vuln_id="A03:2021",
        lines="20",
        description="Cross-Site Scripting via innerHTML assignment.",
    )]
    agg = [_agg_candidate(vuln_class="xss", ls=20, le=20)]
    result = merge_with_llm_findings(llm, agg)
    assert len(result) == 1
    assert result[0].vuln_class == "xss"
    assert "claude" in result[0].sources
    assert result[0].consensus_score >= 2


def test_a03_command_injection_llm_finding_merges_with_command_injection_scanner_candidate() -> None:
    """LLM A03:2021 command-injection finding merges with a scanner 'command_injection' candidate."""
    llm = [_llm_finding(
        vuln_id="A03:2021",
        lines="15",
        description="Command injection via subprocess with shell=True.",
    )]
    agg = [_agg_candidate(vuln_class="command_injection", ls=15, le=15)]
    result = merge_with_llm_findings(llm, agg)
    assert len(result) == 1
    assert result[0].vuln_class == "command_injection"
    assert "claude" in result[0].sources


def test_a03_sqli_merge_still_works_after_multi_class_change() -> None:
    """Existing SQLi merge behaviour is unaffected — regression guard."""
    llm = [_llm_finding(vuln_id="A03:2021", lines="10", description="SQL injection")]
    agg = [_agg_candidate(vuln_class="sqli", ls=10, le=10)]
    result = merge_with_llm_findings(llm, agg)
    assert len(result) == 1
    assert result[0].vuln_class == "sqli"
    assert "claude" in result[0].sources


def test_a03_xss_llm_only_uses_description_inferred_class() -> None:
    """Claude-only A03:2021 XSS finding (no scanner match) gets vuln_class='xss'."""
    llm = [_llm_finding(
        vuln_id="A03:2021",
        lines="30",
        description="Cross-Site Scripting vulnerability via innerHTML.",
    )]
    result = merge_with_llm_findings(llm, [])
    assert len(result) == 1
    assert result[0].vuln_class == "xss"
    assert result[0].sources == ["claude"]


def test_a03_sqli_llm_only_still_defaults_to_sqli() -> None:
    """Claude-only A03:2021 SQLi finding (no scanner match) keeps vuln_class='sqli'."""
    llm = [_llm_finding(
        vuln_id="A03:2021",
        lines="5",
        description="SQL injection in login query.",
    )]
    result = merge_with_llm_findings(llm, [])
    assert len(result) == 1
    assert result[0].vuln_class == "sqli"


def test_a03_xss_and_sqli_scanner_candidates_do_not_cross_merge() -> None:
    """XSS LLM finding must not accidentally merge with a SQLi scanner candidate."""
    llm = [_llm_finding(
        vuln_id="A03:2021",
        lines="10",
        description="Cross-Site Scripting via innerHTML.",
    )]
    # SQLi scanner finding at the same location — must NOT merge with the XSS LLM finding.
    sqli_cand = _agg_candidate(vuln_class="sqli", ls=10, le=10)
    xss_cand = _agg_candidate(vuln_class="xss", ls=10, le=10)
    result = merge_with_llm_findings(llm, [sqli_cand, xss_cand])
    # Should merge with xss_cand and leave sqli_cand unmatched.
    assert len(result) == 2
    merged = next(c for c in result if "claude" in c.sources)
    assert merged.vuln_class == "xss"


# ---------------------------------------------------------------------------
# V7: overlap tolerance — _OVERLAP_TOLERANCE = 5
# ---------------------------------------------------------------------------

def test_merge_tolerance_3_lines_apart_merges() -> None:
    """LLM at line 10, scanner at line 13 — within ±5 tolerance, should merge."""
    llm = [_llm_finding(lines="10")]
    cand = _agg_candidate(ls=13, le=13)
    result = merge_with_llm_findings(llm, [cand])
    assert len(result) == 1
    assert "claude" in result[0].sources
    assert any(s != "claude" for s in result[0].sources)


def test_merge_tolerance_5_lines_apart_merges() -> None:
    """LLM at line 10, scanner at line 15 — exactly at ±5 tolerance boundary."""
    llm = [_llm_finding(lines="10")]
    cand = _agg_candidate(ls=15, le=15)
    result = merge_with_llm_findings(llm, [cand])
    assert len(result) == 1
    assert "claude" in result[0].sources


def test_merge_tolerance_6_lines_apart_does_not_merge() -> None:
    """LLM at line 10, scanner at line 16 — just outside tolerance, must not merge."""
    llm = [_llm_finding(lines="10")]
    cand = _agg_candidate(ls=16, le=16)
    result = merge_with_llm_findings(llm, [cand])
    assert len(result) == 2
    claude_only = next(c for c in result if c.sources == ["claude"])
    scanner_only = next(c for c in result if "claude" not in c.sources)
    assert claude_only is not None
    assert scanner_only is not None
