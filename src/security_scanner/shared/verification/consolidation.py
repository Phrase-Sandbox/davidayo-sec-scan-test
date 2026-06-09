"""Consolidation verifier — single LLM pass reviewing the complete set of
confirmed findings together.

This runs AFTER the per-finding verifier (step 13) as a non-destructive
accuracy layer.  It cannot drop findings; it can only:

* Promote a finding's severity when a cross-finding combined risk is detected
  (e.g. auth bypass + SQLi = unauthenticated SQLi path → Critical).
* Log combined risk patterns for operational awareness.

Design constraints:
- One LLM call (not per-finding).
- Input: the final kept list of VulnerabilityFinding objects.
- Fail-safe: any LLM error returns the input list unchanged.
- Most useful for 5–30 findings.  Above ~50 the prompt grows large; the
  function logs a warning but still attempts the call.
"""

from __future__ import annotations

import re

from security_scanner.shared.claude.client import ClaudeClient
from security_scanner.shared.logging_util import get_logger
from security_scanner.shared.models.enums import Severity
from security_scanner.shared.models.finding import VulnerabilityFinding

log = get_logger(__name__)

_WARN_FINDING_COUNT = 50

_SYSTEM_PROMPT = """\
You are a senior application security engineer performing a final review of a \
set of confirmed vulnerabilities found in a single codebase.

Your task is to look across ALL findings together and identify:
1. Combined-risk patterns — pairs or groups of findings where the combination \
creates a higher-impact attack chain than any single finding alone.
2. Any finding whose severity should be promoted to CRITICAL because of its \
role in a combined attack path.

Rules:
- You MUST NOT reject or discard any finding.  All findings have already been \
individually verified.
- You may only PROMOTE severity (never demote).
- Only promote to CRITICAL when there is a concrete, exploitable combined path \
(e.g. an unauthenticated endpoint directly leads to a SQLi or RCE sink).

Response format — use EXACTLY this structure, one entry per combined risk found:

COMBINED_RISK: <one-sentence description of the combined attack path>
PROMOTES: <comma-separated 1-based finding numbers that should become Critical, \
or NONE if no promotion>

If there are no meaningful combined risks, output only:
NO_COMBINED_RISKS
"""


_PROMOTE_RE = re.compile(
    r"^PROMOTES\s*:\s*(.+)$",
    re.IGNORECASE | re.MULTILINE,
)
_COMBINED_RISK_RE = re.compile(
    r"^COMBINED_RISK\s*:\s*(.+)$",
    re.IGNORECASE | re.MULTILINE,
)


def _build_user_message(findings: list[VulnerabilityFinding]) -> str:
    lines = ["Here are the confirmed findings (1-based numbering):\n"]
    for i, f in enumerate(findings, start=1):
        lines.append(
            f"#{i}: [{f.vulnerability_id}] {f.severity.value.upper()} — "
            f"{f.affected_file} — {f.description[:200]}"
        )
    lines.append("\nAnalyse the findings above for combined risks.")
    return "\n".join(lines)


def _parse_promotions(response: str, count: int) -> set[int]:
    """Return 0-based indices of findings to promote to Critical."""
    promote_indices: set[int] = set()
    for m in _PROMOTE_RE.finditer(response):
        raw = m.group(1).strip()
        if raw.upper() == "NONE":
            continue
        for token in re.split(r"[\s,]+", raw):
            token = token.strip().rstrip(".")
            try:
                idx = int(token) - 1
                if 0 <= idx < count:
                    promote_indices.add(idx)
            except ValueError:
                pass
    return promote_indices


def consolidate_findings(
    findings: list[VulnerabilityFinding],
    claude: ClaudeClient,
) -> list[VulnerabilityFinding]:
    """Review all confirmed findings together; return (possibly updated) list.

    Fail-safe: any exception returns the original list unchanged.
    """
    if len(findings) < 2:
        return findings

    if len(findings) > _WARN_FINDING_COUNT:
        log.warning(
            "consolidation_verifier: large finding set — prompt may be imprecise",
            count=len(findings),
        )

    try:
        user_message = _build_user_message(findings)
        response = claude.ask(_SYSTEM_PROMPT, user_message)
    except Exception as exc:  # noqa: BLE001
        log.warning("consolidation_verifier: LLM call failed — returning unchanged", error=str(exc))
        return findings

    # Log combined risk descriptions for operational awareness.
    for m in _COMBINED_RISK_RE.finditer(response):
        log.info("consolidation_verifier: combined_risk", description=m.group(1).strip())

    # Apply severity promotions (non-destructive — Critical only goes up).
    promote_indices = _parse_promotions(response, len(findings))
    if not promote_indices:
        return findings

    updated = list(findings)
    for idx in promote_indices:
        f = updated[idx]
        if f.severity != Severity.critical:
            log.info(
                "consolidation_verifier: promoting finding to critical",
                file=f.affected_file,
                vuln_id=f.vulnerability_id,
            )
            updated[idx] = f.model_copy(update={"severity": Severity.critical})

    return updated
