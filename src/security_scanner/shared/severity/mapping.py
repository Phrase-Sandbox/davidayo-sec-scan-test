"""Severity / confidence / verification → gate-decision mapping.

Implements the §4.2 severity-to-CVSS-band table and the confidence-gated
blocking rule from BR-001-A (combined with BR-009 for Critical findings).

Three rules in human terms:

- ``should_block`` — the gate emits a *block* decision only when the finding
  is High/Critical, the model's confidence is High, and (for Critical) the
  parallel verification pass concurred. Anything weaker is advisory.
- ``is_advisory_only`` — flags findings that *look* like blockers (High or
  Critical severity) but were demoted to advisory by BR-001-A
  (confidence-gated) or BR-009 (conflicting verification). These deserve a
  prominent header warning in the report so a developer reading "advisory"
  understands it was almost a block.
- ``severity_to_cvss_band`` — canonical band strings per §4.2.

§4.2 uses en-dashes in the band strings. The schema validator accepts both
en-dash and ASCII hyphen; this module emits the canonical en-dash form.
"""

from __future__ import annotations

from security_scanner.shared.models.enums import (
    Confidence,
    Severity,
    VerificationStatus,
)
from security_scanner.shared.models.finding import VulnerabilityFinding

_SEVERITY_TO_CVSS_BAND: dict[Severity, str] = {
    Severity.Critical: "9.0–10.0",
    Severity.High: "7.0–8.9",
    Severity.Medium: "4.0–6.9",
    Severity.Low: "0.1–3.9",
}

_BLOCKING_SEVERITIES: frozenset[Severity] = frozenset({Severity.Critical, Severity.High})
_LOW_CONFIDENCES: frozenset[Confidence] = frozenset({Confidence.Medium, Confidence.Low})


def severity_to_cvss_band(severity: Severity) -> str:
    """Return the canonical CVSS band string for *severity* (§4.2)."""
    return _SEVERITY_TO_CVSS_BAND[severity]


def should_block(finding: VulnerabilityFinding) -> bool:
    """Return True iff this finding causes the gate to fail the deployment.

    BR-001 + BR-001-A + BR-009 combined:
    - Severity must be Critical or High.
    - Confidence must be High (BR-001-A — low-confidence findings are advisory).
    - For Critical findings only: ``verification_status`` must be ``verified``
      (BR-009 — unverified or conflicting Criticals are advisory).
    - advisory_real findings never block (they are auto-triaged advisory).
    """
    if finding.verification_status == VerificationStatus.advisory_real:
        return False
    if finding.severity not in _BLOCKING_SEVERITIES:
        return False
    if finding.confidence != Confidence.High:
        return False
    if finding.severity == Severity.Critical:
        return finding.verification_status == VerificationStatus.verified
    return True  # High + High confidence — no verification gate.


def is_advisory_only(finding: VulnerabilityFinding) -> bool:
    """Return True iff this finding deserves a *prominent advisory warning* in the report header.

    These are findings that "look like blockers" but were demoted:
    - High/Critical severity with Medium/Low confidence (BR-001-A demotion).
    - Critical with ``verification_status == conflicting`` (BR-009 demotion).
    - Any finding with ``verification_status == advisory_real`` (auto-triaged lane).

    Medium/Low findings are *not* flagged here — they are naturally advisory
    and need no extra header warning.
    """
    if finding.verification_status == VerificationStatus.advisory_real:
        return True
    if finding.severity in _BLOCKING_SEVERITIES and finding.confidence in _LOW_CONFIDENCES:
        return True
    if (
        finding.severity == Severity.Critical
        and finding.verification_status == VerificationStatus.conflicting
    ):
        return True
    return False
