"""Tests for the consensus aggregation logic."""

from __future__ import annotations

from security_scanner.shared.scanners.consensus import aggregate
from security_scanner.shared.scanners.models import ScannerCandidate


def _make(tool: str, vuln_class: str, file: str, ls: int, le: int) -> ScannerCandidate:
    return ScannerCandidate(
        tool=tool,
        vuln_class=vuln_class,
        file=file,
        line_start=ls,
        line_end=le,
        message=f"{tool} found {vuln_class}",
        raw_rule_id="RULE-1",
    )


def test_same_class_overlapping_lines_merges() -> None:
    """Two candidates with the same vuln_class and overlapping lines → one aggregate."""
    cands = [
        _make("semgrep", "sqli", "app.py", 10, 10),
        _make("bandit", "sqli", "app.py", 11, 11),
    ]
    result = aggregate(cands)
    assert len(result) == 1
    agg = result[0]
    assert agg.consensus_score == 2
    assert set(agg.sources) == {"semgrep", "bandit"}
    assert agg.line_start == 10
    assert agg.line_end == 11


def test_different_vuln_class_does_not_merge() -> None:
    """Candidates with different vuln_classes stay separate even if lines overlap."""
    cands = [
        _make("semgrep", "sqli", "app.py", 10, 10),
        _make("bandit", "xss", "app.py", 10, 10),
    ]
    result = aggregate(cands)
    assert len(result) == 2


def test_different_file_does_not_merge() -> None:
    """Candidates in different files never merge."""
    cands = [
        _make("semgrep", "sqli", "app.py", 10, 10),
        _make("bandit", "sqli", "other.py", 10, 10),
    ]
    result = aggregate(cands)
    assert len(result) == 2


def test_overlap_within_tolerance() -> None:
    """Lines within ±2 of each other still merge."""
    cands = [
        _make("semgrep", "sqli", "app.py", 10, 10),
        _make("bandit", "sqli", "app.py", 12, 12),  # exactly tolerance=2
    ]
    result = aggregate(cands)
    assert len(result) == 1
    assert result[0].consensus_score == 2


def test_no_overlap_beyond_tolerance() -> None:
    """Lines more than ±2 apart stay separate."""
    cands = [
        _make("semgrep", "sqli", "app.py", 10, 10),
        _make("bandit", "sqli", "app.py", 15, 15),  # 5 lines apart
    ]
    result = aggregate(cands)
    assert len(result) == 2


def test_single_candidate_passes_through() -> None:
    """A single candidate becomes a score=1 aggregate."""
    cands = [_make("semgrep", "sqli", "app.py", 5, 5)]
    result = aggregate(cands)
    assert len(result) == 1
    assert result[0].consensus_score == 1
    assert result[0].sources == ["semgrep"]


def test_empty_input() -> None:
    assert aggregate([]) == []


def test_three_tools_same_location() -> None:
    """Three tools pointing at the same location produce score=3."""
    cands = [
        _make("semgrep", "sqli", "db.py", 20, 20),
        _make("bandit", "sqli", "db.py", 20, 21),
        _make("gosec", "sqli", "db.py", 19, 20),
    ]
    result = aggregate(cands)
    assert len(result) == 1
    assert result[0].consensus_score == 3
