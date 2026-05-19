"""Output schema validator for Claude API responses (spec §4.2).

Every Claude response passes through this validator before any gate decision.
The validator's purpose is to guarantee that Claude's severity assessments
cannot drive an incorrect block/pass outcome via malformed output or a
successful prompt-injection bypass.

A finding is **rejected** (removed from ``valid_findings``) if it fails any of
rules 1–5 below. The scan as a whole is marked ``scan_failed`` (rule 6) when
a Critical finding on the gate path is missing parallel-verification status —
the gate cannot decide until BR-009 has run. Rule 7 emits a non-fatal warning
when Claude returned nothing for a large codebase.

Per BR-006 the gate does not block on validation failure alone — the
orchestrator treats ``scan_failed=True`` as advisory and proceeds.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from pydantic import ValidationError

from security_scanner.shared.logging_util import get_logger
from security_scanner.shared.models.enums import Severity, VerificationStatus
from security_scanner.shared.models.finding import VulnerabilityFinding

log = get_logger(__name__)

EMPTY_FINDINGS_LINE_THRESHOLD = 500

_VALID_SEVERITIES: frozenset[str] = frozenset({"Critical", "High", "Medium", "Low"})
_VALID_VERIFICATION_STATUSES: frozenset[str] = frozenset({"verified", "unverified", "conflicting"})

# CVSS bands keyed by severity. Both ASCII hyphen and en-dash are accepted
# because §4.2 uses an en-dash while the model is likely to emit a hyphen.
_CVSS_BANDS: dict[str, frozenset[str]] = {
    "Critical": frozenset({"9.0-10.0", "9.0–10.0"}),
    "High": frozenset({"7.0-8.9", "7.0–8.9"}),
    "Medium": frozenset({"4.0-6.9", "4.0–6.9"}),
    "Low": frozenset({"0.1-3.9", "0.1–3.9"}),
}

# vulnerability_id patterns: A\d\d:20\d\d, LLM\d\d:20\d\d, SECRET-001 (BR-003).
_VULNERABILITY_ID_RE: re.Pattern[str] = re.compile(
    r"^(A\d{2}:20\d{2}|LLM\d{2}:20\d{2}|SECRET-001)$"
)

# Concrete attacker-action keywords required in every exploit_scenario.
_EXPLOIT_KEYWORDS: frozenset[str] = frozenset(
    {"payload", "request", "query", "parameter", "injection", "bypass", "forge"}
)


@dataclass
class ValidationResult:
    valid_findings: list[VulnerabilityFinding]
    rejected_findings: list[dict]
    warnings: list[str]
    scan_failed: bool = False


def validate(
    raw_findings: list[dict],
    total_source_lines: int,
    *,
    is_gate_path: bool = False,
) -> ValidationResult:
    """Validate raw findings from Claude and return a structured result.

    ``is_gate_path`` (keyword-only) controls rule 6 — BR-009 verification gating.
    The skill path defaults to False because it skips parallel verification for
    cost (see ``shared/verification/parallel.py``).
    """
    valid_findings: list[VulnerabilityFinding] = []
    rejected_findings: list[dict] = []
    warnings: list[str] = []
    scan_failed = False

    # Rule 7 — non-trivial codebase + empty Claude output → warning header.
    if not raw_findings and total_source_lines > EMPTY_FINDINGS_LINE_THRESHOLD:
        warnings.append(
            f"Claude returned no findings for a non-trivial codebase "
            f"({total_source_lines} lines). Developer acknowledgement required "
            "before this scan can be treated as a clean pass."
        )

    for raw in raw_findings:
        rejection_reason = _custom_rule_reject_reason(raw)
        if rejection_reason is not None:
            rejected_findings.append(raw)
            log.warning(
                "schema validation rejected finding",
                vulnerability_id=raw.get("vulnerability_id"),
                reason=rejection_reason,
            )
            continue

        try:
            finding = VulnerabilityFinding.model_validate(raw)
        except ValidationError as exc:
            rejected_findings.append(raw)
            log.warning(
                "schema validation rejected finding (pydantic)",
                vulnerability_id=raw.get("vulnerability_id"),
                reason=f"pydantic: {len(exc.errors())} field error(s)",
            )
            continue

        # Rule 6 — BR-009 on gate path only.
        if (
            is_gate_path
            and finding.severity == Severity.Critical
            and finding.verification_status == VerificationStatus.unverified
        ):
            scan_failed = True
            warnings.append(
                f"Critical finding {finding.vulnerability_id} in "
                f"{finding.affected_file} has verification_status=unverified. "
                "BR-009 requires parallel verification before the gate can "
                "decide. Treating as scan_failed (BR-006 fail-open applies)."
            )

        valid_findings.append(finding)

    return ValidationResult(
        valid_findings=valid_findings,
        rejected_findings=rejected_findings,
        warnings=warnings,
        scan_failed=scan_failed,
    )


def _custom_rule_reject_reason(raw: dict) -> str | None:
    """Apply spec §4.2 rules 1–5 to a raw finding dict; return reason or None."""
    # Rule 1 — severity enum.
    severity = raw.get("severity")
    if severity not in _VALID_SEVERITIES:
        return f"invalid severity: {severity!r}"

    # Rule 2 — cvss_band matches severity.
    cvss_band = raw.get("cvss_band")
    if cvss_band not in _CVSS_BANDS[severity]:
        return f"cvss_band {cvss_band!r} does not match severity {severity!r}"

    # Rule 3 — vulnerability_id OWASP format.
    vid = raw.get("vulnerability_id")
    if not isinstance(vid, str) or not _VULNERABILITY_ID_RE.match(vid):
        return f"invalid vulnerability_id format: {vid!r}"

    # Rule 5 — verification_status enum (default to "unverified" if absent).
    vs = raw.get("verification_status", "unverified")
    if vs not in _VALID_VERIFICATION_STATUSES:
        return f"invalid verification_status: {vs!r}"

    # Rule 4 — exploit_scenario well-formedness.
    scenario = raw.get("exploit_scenario")
    affected_file = raw.get("affected_file")
    if not _is_well_formed_exploit_scenario(scenario, affected_file):
        return "exploit_scenario is empty, omits affected_file, or lacks attacker-action keyword"

    return None


def _is_well_formed_exploit_scenario(scenario: object, affected_file: object) -> bool:
    if not isinstance(scenario, str) or not scenario.strip():
        return False
    if not isinstance(affected_file, str) or not affected_file:
        return False
    if affected_file not in scenario:
        return False
    lowered = scenario.lower()
    return any(keyword in lowered for keyword in _EXPLOIT_KEYWORDS)
