"""Merge LLM findings with aggregated scanner candidates.

Strategy
--------
1. Index LLM findings by ``(file, vuln_class_or_id, line_range)`` with ±2
   line-range tolerance.
2. For each aggregated scanner candidate, check if a Claude finding covers
   the same location and vulnerability class.
3. If a match exists: create a ``CandidateForVerification`` that combines
   both.  Claude's ``description``, ``exploit_scenario``, and ``suggested_fix``
   are preserved; sources/consensus_score are extended.
4. Unmatched scanner candidates and unmatched Claude findings both flow
   through as standalone candidates.

The result is a ``list[CandidateForVerification]`` ready for the
production-mode vuln verifier.
"""

from __future__ import annotations

import logging

from security_scanner.shared.models.finding import VulnerabilityFinding
from security_scanner.shared.scanners.models import AggregatedCandidate
from security_scanner.shared.scanners.normalize import normalize
from security_scanner.shared.scanners.types import CandidateForVerification

log = logging.getLogger(__name__)

_OVERLAP_TOLERANCE = 2


def _parse_affected_lines(affected_lines: str | None) -> tuple[int, int]:
    """Parse ``"42"`` or ``"42-55"`` into ``(start, end)``.  Returns ``(0,0)`` on failure."""
    if not affected_lines:
        return 0, 0
    try:
        if "-" in affected_lines:
            parts = affected_lines.split("-", 1)
            return int(parts[0].strip()), int(parts[1].strip())
        return int(affected_lines.strip()), int(affected_lines.strip())
    except (ValueError, IndexError):
        return 0, 0


def _overlap(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    """Return True if two line ranges overlap within ±OVERLAP_TOLERANCE."""
    if a_start == 0 or b_start == 0:
        return False  # unknown line → no merge
    return max(a_start, b_start) <= min(a_end, b_end) + _OVERLAP_TOLERANCE


def _llm_vuln_class(finding: VulnerabilityFinding) -> str:
    """Best-effort vuln_class from a Claude finding's vulnerability_id.

    Uses the OWASP→vuln_class mapping first, falling back to the general
    normalizer.  ``normalize("owasp", "a03:2021")`` → ``"sqli"`` so that
    Claude's Injection findings can merge with Bandit's ``sqli`` candidates.
    """
    return normalize("owasp", finding.vulnerability_id.lower())


def merge_with_llm_findings(
    llm_findings: list[VulnerabilityFinding],
    aggregated: list[AggregatedCandidate],
) -> list[CandidateForVerification]:
    """Merge Claude first-pass findings with scanner aggregated candidates.

    Parameters
    ----------
    llm_findings:
        Validated, post-filtered findings from the Claude first pass.
        Each has ``sources == []`` initially; this function sets them to
        ``["claude"]``.
    aggregated:
        Consensus-aggregated scanner candidates.

    Returns
    -------
    list[CandidateForVerification]
        Combined list ready for the production-mode verifier.
    """
    # Tag Claude findings.
    result: list[CandidateForVerification] = []
    # Track which scanner candidates were merged (by index).
    matched_scanner: set[int] = set()

    # Index scanner candidates by (file, vuln_class).
    scanner_index: dict[tuple[str, str], list[tuple[int, AggregatedCandidate]]] = {}
    for idx, cand in enumerate(aggregated):
        key = (cand.file, cand.vuln_class)
        scanner_index.setdefault(key, []).append((idx, cand))

    for llm_f in llm_findings:
        l_start, l_end = _parse_affected_lines(llm_f.affected_lines)
        l_vuln_class = _llm_vuln_class(llm_f)
        matched = False

        # Look for a scanner candidate in the same file/class with overlapping lines.
        for idx, cand in scanner_index.get((llm_f.affected_file, l_vuln_class), []):
            if _overlap(l_start, l_end, cand.line_start, cand.line_end):
                # Merged candidate.
                merged_sources = ["claude"] + [s for s in cand.sources if s != "claude"]
                result.append(CandidateForVerification(
                    file=llm_f.affected_file,
                    line_start=min(l_start, cand.line_start) if l_start else cand.line_start,
                    line_end=max(l_end, cand.line_end) if l_end else cand.line_end,
                    vuln_class=l_vuln_class,
                    vulnerability_id=llm_f.vulnerability_id,
                    severity=llm_f.severity.value,
                    confidence=llm_f.confidence.value,
                    cvss_band=llm_f.cvss_band,
                    description=llm_f.description,
                    suggested_fix=llm_f.suggested_fix,
                    owasp_reference=llm_f.owasp_reference,
                    exploit_scenario=llm_f.exploit_scenario,
                    sources=merged_sources,
                    consensus_score=len(set(merged_sources)),
                    raw_rule_ids=cand.raw_rule_ids,
                    scanner_message=cand.message,
                ))
                matched_scanner.add(idx)
                matched = True
                break  # merge with first match only

        if not matched:
            # Claude-only candidate.
            result.append(CandidateForVerification(
                file=llm_f.affected_file,
                line_start=l_start,
                line_end=l_end,
                vuln_class=l_vuln_class,
                vulnerability_id=llm_f.vulnerability_id,
                severity=llm_f.severity.value,
                confidence=llm_f.confidence.value,
                cvss_band=llm_f.cvss_band,
                description=llm_f.description,
                suggested_fix=llm_f.suggested_fix,
                owasp_reference=llm_f.owasp_reference,
                exploit_scenario=llm_f.exploit_scenario,
                sources=["claude"],
                consensus_score=1,
                raw_rule_ids=[],
                scanner_message="",
            ))

    # Unmatched scanner candidates (scanner-only).
    for idx, cand in enumerate(aggregated):
        if idx in matched_scanner:
            continue
        result.append(CandidateForVerification(
            file=cand.file,
            line_start=cand.line_start,
            line_end=cand.line_end,
            vuln_class=cand.vuln_class,
            vulnerability_id="",
            severity=cand.severity_hint.capitalize(),
            confidence="Medium",
            cvss_band="4.0-6.9",
            description=cand.message,
            suggested_fix="",
            owasp_reference="",
            exploit_scenario="",
            sources=cand.sources,
            consensus_score=cand.consensus_score,
            raw_rule_ids=cand.raw_rule_ids,
            scanner_message=cand.message,
        ))

    log.debug(
        "merge_with_llm_findings",
        llm_count=len(llm_findings),
        scanner_count=len(aggregated),
        merged_count=len(result),
    )
    return result
