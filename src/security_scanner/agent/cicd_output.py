"""CI/CD job-output strings for each gate decision (spec §6.5, EC-012).

Exactly one line per scan, matching the wording in §6.5. The GitHub Action
prints this to its step output so the developer reading the failed-job log
sees the canonical message and nothing else.
"""

from __future__ import annotations

from security_scanner.shared.models.enums import GateDecision, Severity
from security_scanner.shared.models.scan_result import ScanResult

_SCAN_FAILED_MESSAGE = (
    "Security scan unavailable. Deployment allowed to proceed — "
    "scan manually before release."
)


def format_cicd_message(result: ScanResult) -> str:
    """Return the single-line CI/CD message for ``result.gate_decision``."""
    decision = result.gate_decision
    if decision == GateDecision.blocked:
        return _blocked(result)
    if decision == GateDecision.pass_:
        return _pass(result)
    if decision == GateDecision.advisory:
        return _advisory(result)
    if decision == GateDecision.scan_failed:
        return _SCAN_FAILED_MESSAGE
    if decision == GateDecision.bypassed:
        return _bypassed(result)
    raise ValueError(f"Unhandled gate_decision: {decision!r}")


def _blocked(result: ScanResult) -> str:
    critical = _count(result, Severity.Critical)
    high = _count(result, Severity.High)
    return (
        f"Security scan failed: {critical} Critical, {high} High findings "
        "detected. Deployment blocked. See report artifact for details and "
        "patches."
    )


def _pass(result: ScanResult) -> str:
    medium_low = _count(result, Severity.Medium) + _count(result, Severity.Low)
    return (
        f"Security scan passed. {medium_low} Medium/Low findings noted — "
        "see report for details."
    )


def _advisory(result: ScanResult) -> str:
    return (
        f"Security scan advisory: {len(result.findings)} findings present "
        "but not blocking (confidence or verification threshold not met). "
        "See report."
    )


def _bypassed(result: ScanResult) -> str:
    high_or_critical = _count(result, Severity.Critical) + _count(result, Severity.High)
    return (
        f"Deployment gate bypassed by {result.triggered_by} at "
        f"{result.timestamp.isoformat()}. {high_or_critical} High/Critical "
        "findings were present at time of bypass."
    )


def _count(result: ScanResult, severity: Severity) -> int:
    return sum(1 for f in result.findings if f.severity == severity)
