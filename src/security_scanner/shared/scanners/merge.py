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
import re

from security_scanner.shared.models.finding import VulnerabilityFinding
from security_scanner.shared.scanners.models import AggregatedCandidate
from security_scanner.shared.scanners.normalize import normalize
from security_scanner.shared.scanners.types import CandidateForVerification

log = logging.getLogger(__name__)

_OVERLAP_TOLERANCE = 2

# A03:2021 covers multiple injection subtypes. The LLM always emits A03:2021
# for all of them (XSS, command injection, code injection, unsafe YAML, SQLi),
# but scanner tools index findings under their specific subtype class.
# We try every A03 subclass when searching the scanner index so a mismatch
# between the LLM's broad OWASP ID and the scanner's specific class does not
# silently prevent the two findings from merging.
_A03_CLASSES: frozenset[str] = frozenset({
    "sqli", "xss", "command_injection", "code_injection", "unsafe_yaml",
})

# Patterns used to infer the specific vuln_class from an LLM description when
# a scanner match was not found and the OWASP ID alone is too broad.
# Evaluated in order; first match wins.  Falls back to the primary normalized
# class (usually "sqli" for A03:2021) when nothing matches.
_DESCRIPTION_CLASS_HINTS: list[tuple[re.Pattern[str], str]] = [
    # XSS first — DOM sinks and XSS terminology before code_injection so that
    # descriptions mentioning "eval" in an XSS context are not misclassified.
    (re.compile(
        r"cross.site scripting|\bxss\b|innerHTML|outerHTML|dangerouslySetInnerHTML"
        r"|document\.write|html.*inject|reflected.*html|stored.*html|autoescape.*false"
        r"|jinja.*\bsafe\b",
        re.IGNORECASE,
    ), "xss"),
    # Command injection — shell execution patterns.
    (re.compile(
        r"command.injection|subprocess.*shell|os\.system|os\.popen"
        r"|child_process|shell=True|shell.*true",
        re.IGNORECASE,
    ), "command_injection"),
    # Code injection / SSTI — eval, exec, server-side template injection.
    (re.compile(
        r"code.injection|\beval\b|\bexec\b|server.side template|\bssti\b|template.*inject",
        re.IGNORECASE,
    ), "code_injection"),
    # Unsafe YAML deserialization.
    (re.compile(r"unsafe.yaml|yaml\.load", re.IGNORECASE), "unsafe_yaml"),
    # SQL injection — explicit match so the fallback is never silently reached.
    (re.compile(
        r"\bsql\b.*inject|inject.*\bsql\b|\bsql.*quer|cursor\.execute"
        r"|raw.*quer|orm.*raw|prepared.*statement",
        re.IGNORECASE,
    ), "sqli"),
    # Path traversal / file inclusion (LLM sometimes tags these A03:2021).
    (re.compile(
        r"path.*travers|directory.*travers|zip.*slip|tar.*slip"
        r"|arbitrary.*file|\blfi\b|\brfi\b|file.*inclus|\.\./",
        re.IGNORECASE,
    ), "path_traversal"),
    # Open redirect.
    (re.compile(r"open.*redirect|unvalidated.*redirect", re.IGNORECASE), "open_redirect"),
    # Deserialization (non-YAML).
    (re.compile(
        r"deserializ|pickle|marshal|java.*serial|untrusted.*object",
        re.IGNORECASE,
    ), "deserialization"),
    # File upload / MIME / extension checks.
    (re.compile(
        r"file.*upload|upload.*file|mime.*type|arbitrary.*upload|file.*ext(?:ension)?",
        re.IGNORECASE,
    ), "unsafe_file_upload"),
]


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
    """Primary vuln_class from a Claude finding's OWASP vulnerability_id."""
    return normalize("owasp", finding.vulnerability_id.lower())


def _infer_class_from_description(description: str, fallback: str) -> str:
    """Return a specific vuln_class inferred from an LLM description string.

    Falls back to the normalised primary class (usually "sqli" for A03:2021)
    when no pattern matches, which is no worse than the previous behaviour.
    """
    for pattern, vuln_class in _DESCRIPTION_CLASS_HINTS:
        if pattern.search(description):
            return vuln_class
    return fallback


def _llm_candidate_classes(finding: VulnerabilityFinding) -> list[str]:
    """All scanner vuln_classes to try when matching this LLM finding.

    A03:2021 is used for all injection types (SQLi, XSS, command injection,
    code injection, unsafe YAML).  For A03:2021 findings, the description-
    inferred class is tried first (most specific), then every other A03
    subtype as a fallback.  For other OWASP IDs this is a single-element list.
    """
    primary = _llm_vuln_class(finding)
    if finding.vulnerability_id.upper() == "A03:2021":
        inferred = _infer_class_from_description(finding.description or "", primary)
        extras = sorted(_A03_CLASSES - {inferred})
        return [inferred] + extras
    return [primary]


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
        # First element is always the description-inferred (most specific) class.
        l_candidate_classes = _llm_candidate_classes(llm_f)
        matched = False

        # Try each candidate class against the scanner index.  For A03:2021
        # this covers all injection subtypes; for other OWASP IDs it is a
        # single-element list and behaves identically to before.
        for candidate_class in l_candidate_classes:
            for idx, cand in scanner_index.get((llm_f.affected_file, candidate_class), []):
                if _overlap(l_start, l_end, cand.line_start, cand.line_end):
                    merged_sources = ["claude"] + [s for s in cand.sources if s != "claude"]
                    result.append(CandidateForVerification(
                        file=llm_f.affected_file,
                        line_start=min(l_start, cand.line_start) if l_start else cand.line_start,
                        line_end=max(l_end, cand.line_end) if l_end else cand.line_end,
                        # Use the scanner's specific class — it is always more
                        # precise than the LLM's broad OWASP-derived class.
                        vuln_class=cand.vuln_class,
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
            if matched:
                break

        if not matched:
            # Claude-only candidate.  Use the description-inferred class
            # (l_candidate_classes[0]) so the verifier receives the correct
            # label (e.g. "xss") rather than the OWASP fallback ("sqli").
            result.append(CandidateForVerification(
                file=llm_f.affected_file,
                line_start=l_start,
                line_end=l_end,
                vuln_class=l_candidate_classes[0],
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
