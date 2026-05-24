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
