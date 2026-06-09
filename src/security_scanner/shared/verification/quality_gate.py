"""Post-verification fix quality gate.

An optional LLM pass that regenerates ``suggested_fix`` and ``exploit_scenario``
for verified findings where the fix lacks a fenced code block.  Never drops
findings — on any error the original finding is returned unchanged.

Only fires for vuln classes that are fixable-in-code (injection classes,
deserialization, etc.).  Secret findings and advisory-only classes are skipped.
"""

from __future__ import annotations

import re

from security_scanner.shared.claude.client import ClaudeClient, ClaudeError
from security_scanner.shared.logging_util import get_logger
from security_scanner.shared.models.finding import VulnerabilityFinding

log = get_logger(__name__)

_BATCH_SIZE = 5

# Classes for which a code-block fix is expected and worth regenerating.
_FIXABLE_IN_CODE_CLASSES: frozenset[str] = frozenset({
    "sqli", "xss", "command_injection", "ssrf", "path_traversal",
    "code_injection", "deserialization", "unsafe_yaml", "xxe",
    "ldap_injection", "nosqli", "open_redirect", "csrf",
})

_IMPROVED_FIX_RE = re.compile(
    r"^\s*IMPROVED_FIX\s*#?\s*(\d+)\s*:\s*(.+?)(?=\s*IMPROVED_FIX\s*#|\s*IMPROVED_SCENARIO\s*#|\Z)",
    re.IGNORECASE | re.MULTILINE | re.DOTALL,
)
_IMPROVED_SCENARIO_RE = re.compile(
    r"^\s*IMPROVED_SCENARIO\s*#?\s*(\d+)\s*:\s*(.+?)(?=\s*IMPROVED_FIX\s*#|\s*IMPROVED_SCENARIO\s*#|\Z)",
    re.IGNORECASE | re.MULTILINE | re.DOTALL,
)

_SYSTEM_PROMPT = """\
You are a security remediation writer. Your task is to strengthen weak vulnerability reports.

For each finding (labelled FINDING #N), produce:
1. IMPROVED_FIX #N: A concrete suggested_fix that includes EXACTLY ONE fenced code block
   showing the vulnerable pattern and the safe replacement. The block must be copy-paste-ready.
2. IMPROVED_SCENARIO #N: A step-by-step exploit_scenario that names the exact file,
   the attacker-controlled parameter, and the specific payload string.

Rules:
- Never drop or weaken security. The fix must close the vulnerability.
- The code block must show BEFORE and AFTER — label them with comments.
- The exploit scenario must name the payload (e.g. `' OR '1'='1`, `../../../etc/passwd`).
- Return ONLY the IMPROVED_FIX and IMPROVED_SCENARIO blocks. No prose, no preamble.
- Use N matching the input finding number.
"""


def _needs_strengthening(finding: VulnerabilityFinding) -> bool:
    """Return True if the finding's fix lacks a code block and the class is fixable-in-code."""
    vuln_class = (finding.vulnerability_id or "").lower()
    # Try to extract class from sources or description as fallback
    # The primary check is the suggested_fix content
    has_code_block = "```" in (finding.suggested_fix or "")
    if has_code_block:
        return False
    # Only strengthen known fixable-in-code classes (infer from vuln_id or description).
    # We check if any fixable keyword appears in the finding's context.
    context = (
        (finding.description or "") + " " +
        (finding.suggested_fix or "")
    ).lower()
    return any(cls in context for cls in _FIXABLE_IN_CODE_CLASSES)


def _build_user_message(batch: list[VulnerabilityFinding], files: dict[str, str]) -> str:
    parts: list[str] = []
    for i, finding in enumerate(batch, 1):
        file_content = files.get(finding.affected_file, "")
        snippet = ""
        if finding.affected_lines and file_content:
            lines = file_content.splitlines()
            try:
                if "-" in finding.affected_lines:
                    lo_s, hi_s = finding.affected_lines.split("-", 1)
                    lo = max(0, int(lo_s.strip()) - 6)
                    hi = min(len(lines), int(hi_s.strip()) + 6)
                else:
                    anchor = int(finding.affected_lines.strip())
                    lo = max(0, anchor - 6)
                    hi = min(len(lines), anchor + 6)
                snippet = "\n".join(lines[lo:hi])
            except (ValueError, IndexError):
                snippet = file_content[:1500]
        elif file_content:
            snippet = file_content[:1500]

        parts.append(
            f"FINDING #{i}\n"
            f"FILE: {finding.affected_file}\n"
            f"LINES: {finding.affected_lines or 'unknown'}\n"
            f"DESCRIPTION: {finding.description[:400] if finding.description else ''}\n"
            f"CURRENT FIX (weak — no code block): {finding.suggested_fix[:300] if finding.suggested_fix else '(empty)'}\n"
            f"CODE:\n{snippet[:1200] if snippet else '(unavailable)'}"
        )
    return "\n\n".join(parts)


def _parse_response(
    response: str, batch_size: int
) -> dict[int, tuple[str, str]]:
    """Return ``{0-based-index: (improved_fix, improved_scenario)}``."""
    fixes: dict[int, str] = {}
    for m in _IMPROVED_FIX_RE.finditer(response):
        idx = int(m.group(1)) - 1
        if 0 <= idx < batch_size:
            fixes[idx] = m.group(2).strip()

    scenarios: dict[int, str] = {}
    for m in _IMPROVED_SCENARIO_RE.finditer(response):
        idx = int(m.group(1)) - 1
        if 0 <= idx < batch_size:
            scenarios[idx] = m.group(2).strip()

    result: dict[int, tuple[str, str]] = {}
    for idx in range(batch_size):
        if idx in fixes or idx in scenarios:
            result[idx] = (fixes.get(idx, ""), scenarios.get(idx, ""))
    return result


def _strengthen_batch(
    batch: list[VulnerabilityFinding],
    files: dict[str, str],
    claude: ClaudeClient,
) -> list[VulnerabilityFinding]:
    """Run one LLM call to strengthen a batch. Returns findings unchanged on error."""
    try:
        user_msg = _build_user_message(batch, files)
        response = claude.ask(_SYSTEM_PROMPT, user_msg)
    except ClaudeError as exc:
        log.warning(
            "quality_gate: claude error — keeping originals",
            batch_size=len(batch),
            error=type(exc).__name__,
        )
        return list(batch)

    parsed = _parse_response(response or "", len(batch))
    result: list[VulnerabilityFinding] = []
    for idx, finding in enumerate(batch):
        if idx not in parsed:
            result.append(finding)
            continue
        improved_fix, improved_scenario = parsed[idx]
        updates: dict[str, str] = {}
        if improved_fix and "```" in improved_fix:
            updates["suggested_fix"] = improved_fix
        if improved_scenario:
            updates["exploit_scenario"] = improved_scenario
        if updates:
            log.info(
                "quality_gate: strengthened finding",
                file=finding.affected_file,
                fields=list(updates.keys()),
            )
            finding = finding.model_copy(update=updates)
        result.append(finding)
    return result


def strengthen_fix_quality(
    findings: list[VulnerabilityFinding],
    files: dict[str, str],
    claude: ClaudeClient,
) -> list[VulnerabilityFinding]:
    """Regenerate suggested_fix/exploit_scenario for findings with weak fix content.

    Fires at most one LLM call per batch of 5 findings that need strengthening.
    Never drops findings — on any error the original finding is returned unchanged.
    Findings with an existing code block are passed through without an LLM call.
    """
    to_strengthen = [f for f in findings if _needs_strengthening(f)]
    if not to_strengthen:
        return findings

    log.info("quality_gate: strengthening findings", count=len(to_strengthen))

    # Build a mutable copy indexed by identity for update.
    strengthened_map: dict[int, VulnerabilityFinding] = {}
    for i in range(0, len(to_strengthen), _BATCH_SIZE):
        batch = to_strengthen[i : i + _BATCH_SIZE]
        improved = _strengthen_batch(batch, files, claude)
        for original, updated in zip(batch, improved, strict=True):
            strengthened_map[id(original)] = updated

    return [strengthened_map.get(id(f), f) for f in findings]
