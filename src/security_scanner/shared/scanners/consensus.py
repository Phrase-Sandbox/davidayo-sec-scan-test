"""Consensus aggregator for raw scanner candidates.

Groups ``ScannerCandidate`` objects by ``(file, vuln_class)`` and merges
those whose line ranges overlap within a ±2-line tolerance.  Candidates that
survive merging become ``AggregatedCandidate`` objects with:

- ``sources``: the list of tool names that voted
- ``consensus_score``: number of distinct tools
- ``line_start`` / ``line_end``: union of all voter line ranges
- ``raw_rule_ids``: all raw rule IDs from voters
- ``message``: from the first (highest-priority) voter

Two candidates overlap when:

    max(a.line_start, b.line_start) - min(a.line_end, b.line_end) <= 2

This tolerates off-by-one differences across tools (e.g. Semgrep pointing to
the ``cursor.execute(`` call on line 10 while Bandit points to line 11).
"""

from __future__ import annotations

from security_scanner.shared.scanners.models import AggregatedCandidate, ScannerCandidate

_OVERLAP_TOLERANCE = 2


def _lines_overlap(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    """Return True if the two line ranges overlap within ±OVERLAP_TOLERANCE."""
    # Overlap: max(starts) <= min(ends) + tolerance
    return max(a_start, b_start) <= min(a_end, b_end) + _OVERLAP_TOLERANCE


def aggregate(candidates: list[ScannerCandidate]) -> list[AggregatedCandidate]:
    """Merge overlapping same-class candidates into consensus aggregates.

    Algorithm
    ---------
    1. Group all candidates by ``(file, vuln_class)``.
    2. Within each group, greedily merge candidates whose line ranges overlap
       (within tolerance).  The merge order follows input order so the
       "first voter wins" principle applies to ``message`` and
       ``severity_hint``.
    3. Build and return one ``AggregatedCandidate`` per merged group.

    Parameters
    ----------
    candidates:
        Raw per-tool candidates (may be from multiple tools and files).

    Returns
    -------
    list[AggregatedCandidate]
        Deduplicated, consensus-scored candidates.
    """
    if not candidates:
        return []

    # Group by (file, vuln_class).
    groups: dict[tuple[str, str], list[ScannerCandidate]] = {}
    for c in candidates:
        key = (c.file, c.vuln_class)
        groups.setdefault(key, []).append(c)

    aggregated: list[AggregatedCandidate] = []

    for (_file, _vuln_class), group in groups.items():
        # Within the group merge overlapping line ranges.
        clusters: list[list[ScannerCandidate]] = []
        for cand in group:
            placed = False
            for cluster in clusters:
                # Merge into the first cluster that overlaps.
                merged_start = min(c.line_start for c in cluster)
                merged_end = max(c.line_end for c in cluster)
                if _lines_overlap(cand.line_start, cand.line_end, merged_start, merged_end):
                    cluster.append(cand)
                    placed = True
                    break
            if not placed:
                clusters.append([cand])

        for cluster in clusters:
            first = cluster[0]
            sources = list(dict.fromkeys(c.tool for c in cluster))  # dedup, preserve order
            aggregated.append(
                AggregatedCandidate(
                    vuln_class=first.vuln_class,
                    file=first.file,
                    line_start=min(c.line_start for c in cluster),
                    line_end=max(c.line_end for c in cluster),
                    message=first.message,
                    sources=sources,
                    consensus_score=len(sources),
                    raw_rule_ids=[c.raw_rule_id for c in cluster],
                    severity_hint=first.severity_hint,
                )
            )

    return aggregated
