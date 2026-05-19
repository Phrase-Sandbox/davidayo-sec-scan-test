"""Final gate-decision rule applied at the agent layer (BR-001 / BR-001-A / BR-006).

The pipeline produces a *draft* ``gate_decision`` based on the same
``should_block`` predicate. This module is the authoritative finaliser for
the deployment gate — it re-derives the decision against the rules the user
specified for the agent path, in order:

1. ``GateDecision.scan_failed`` is **sticky** — the scan didn't complete
   normally and per BR-006 the gate must fail open (i.e. not block).
2. Any finding for which ``should_block()`` is True (Critical+High-confidence
   +verified, or High+High-confidence) → ``GateDecision.blocked``.
3. Any finding for which ``is_advisory_only()`` is True (High/Critical with
   Medium/Low confidence per BR-001-A, or Critical with conflicting
   verification per BR-009) → ``GateDecision.advisory`` + a header warning.
4. Otherwise → ``GateDecision.pass_``.

Note: ``result.scan_failed`` in the user's instruction refers to the
``GateDecision.scan_failed`` enum value on ``ScanResult.gate_decision``;
``ScanResult`` does not carry a separate boolean field.

⚠️  DO NOT naively call this as a post-``pipeline.run`` finaliser in
``agent/api.py``. The pipeline's BR-006 fallback (Claude unavailable on the
gate path) returns ``GateDecision.advisory`` *with* the deterministic
``SECRET-001`` Critical findings still attached. ``make_gate_decision``
Rule 2 would see ``should_block`` is True for those secret findings and
re-escalate that result to ``blocked`` — directly violating BR-006
("infrastructure failure must be non-blocking"). The pipeline's
``_decide_gate`` is intentionally the live authority. Reconciling the two
(e.g. making ``advisory`` from a Claude-unavailable run sticky here, or
emitting ``scan_failed`` instead) is a deliberate change that needs its own
review and test updates — it is **out of scope** as a drive-by cleanup.
"""

from __future__ import annotations

from security_scanner.shared.models.enums import GateDecision
from security_scanner.shared.models.finding import VulnerabilityFinding
from security_scanner.shared.models.scan_result import ScanResult
from security_scanner.shared.severity.mapping import is_advisory_only, should_block


def make_gate_decision(result: ScanResult) -> ScanResult:
    """Apply the BR-001 / BR-001-A / BR-009 gate rules and return an updated copy.

    The input ``ScanResult`` is not mutated — a fresh instance is returned
    via ``model_copy(update=…)``.
    """
    # Rule 1: scan_failed is preserved (BR-006 fail-open).
    if result.gate_decision == GateDecision.scan_failed:
        return result

    # Rule 2: any blocking finding wins.
    if any(should_block(f) for f in result.findings):
        return result.model_copy(update={"gate_decision": GateDecision.blocked})

    # Rule 3: any demotion-to-advisory finding → advisory + warning.
    demoted = [f for f in result.findings if is_advisory_only(f)]
    if demoted:
        warning = _advisory_warning(demoted)
        return result.model_copy(
            update={
                "gate_decision": GateDecision.advisory,
                "warnings": [*result.warnings, warning],
            }
        )

    # Rule 4: nothing notable — pass.
    return result.model_copy(update={"gate_decision": GateDecision.pass_})


def _advisory_warning(demoted: list[VulnerabilityFinding]) -> str:
    return (
        f"⚠️ ADVISORY: {len(demoted)} High/Critical findings demoted to "
        "advisory (confidence or verification threshold not met) — not "
        "blocking deployment."
    )
