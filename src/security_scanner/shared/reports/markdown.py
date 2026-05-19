"""Markdown report generator (spec §2.2 step 6, §6.1, §6.2, BR-008).

Renders a ``ScanResult`` into the developer-facing Markdown report. The
report's warnings section is shown **at the top**, before findings, so a
developer scrolling past the header sees blockers and demotions immediately.

Warnings derive from the result itself — no separate ``warnings`` list is
passed in. Concretely:

- ``partial_scan=True`` → BR-008 partial-scan banner.
- Any Critical finding with ``verification_status == conflicting`` → BR-009
  demotion banner.
- Any High/Critical finding with Medium/Low confidence → BR-001-A demotion
  banner.
- Empty findings list → "no findings detected" acknowledgement banner.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from security_scanner.shared.models.enums import (
    Confidence,
    GateDecision,
    ScanType,
    Severity,
    VerificationStatus,
)
from security_scanner.shared.models.finding import VulnerabilityFinding
from security_scanner.shared.models.scan_result import ScanResult


def build_markdown_report(result: ScanResult) -> str:
    """Render *result* as a self-contained Markdown report."""
    parts: list[str] = ["# Security Scan Report"]
    parts.append(_metadata_section(result))

    warnings = _gather_warnings(result)
    if warnings:
        parts.append(_warnings_section(warnings))

    if result.scan_type == ScanType.deployment_gate:
        parts.append(_gate_decision_section(result.gate_decision))

    if result.findings:
        parts.append(_findings_table(result.findings))
        parts.append(_detailed_findings(result.findings))

    parts.append(_footer(result.findings_count))
    return "\n\n".join(parts) + "\n"


# --- Sections --------------------------------------------------------------


def _metadata_section(result: ScanResult) -> str:
    return (
        "## Scan metadata\n"
        f"- **Scan ID**: `{_fmt_uuid(result.scan_id)}`\n"
        f"- **Repository**: {result.repo_url}\n"
        f"- **Timestamp**: {_fmt_timestamp(result.timestamp)}\n"
        f"- **Scan type**: `{result.scan_type.value}`\n"
        f"- **Scan target**: `{result.scan_target.value}`\n"
        f"- **Triggered by**: {result.triggered_by}"
    )


def _gather_warnings(result: ScanResult) -> list[str]:
    warnings: list[str] = []

    if result.partial_scan:
        files_text = (
            ", ".join(f"`{p}`" for p in result.unscanned_files)
            if result.unscanned_files
            else "_(none listed)_"
        )
        warnings.append(
            "⚠️ **PARTIAL SCAN** — the following files were not analysed: "
            f"{files_text}"
        )

    conflicting = [
        f
        for f in result.findings
        if f.severity == Severity.Critical
        and f.verification_status == VerificationStatus.conflicting
    ]
    if conflicting:
        warnings.append(
            f"⚠️ **CONFLICTING FINDINGS** — {len(conflicting)} Critical "
            "findings were not confirmed by the verification pass. These "
            "are reported as advisories."
        )

    advisory_demotions = [
        f
        for f in result.findings
        if f.severity in {Severity.Critical, Severity.High}
        and f.confidence in {Confidence.Medium, Confidence.Low}
    ]
    if advisory_demotions:
        warnings.append(
            f"⚠️ **ADVISORY** — {len(advisory_demotions)} findings are "
            "High/Critical severity but have Medium/Low confidence. These "
            "are not blocking."
        )

    if not result.findings:
        warnings.append(
            "⚠️ **NO FINDINGS DETECTED** — developer acknowledgement "
            "required before gate passes."
        )

    return warnings


def _warnings_section(warnings: list[str]) -> str:
    body = "\n\n".join(warnings)
    return f"## Warnings\n\n{body}"


def _gate_decision_section(decision: GateDecision) -> str:
    return f"## Gate decision: `{decision.value.upper()}`"


def _findings_table(findings: list[VulnerabilityFinding]) -> str:
    lines = [
        f"## Findings ({len(findings)})",
        "",
        "| ID | Severity | Confidence | Verification | File | Lines | OWASP reference |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for f in findings:
        lines.append(
            "| "
            + " | ".join(
                _md_cell(c)
                for c in (
                    f.vulnerability_id,
                    f.severity.value,
                    f.confidence.value,
                    f.verification_status.value,
                    f.affected_file,
                    f.affected_lines or "—",
                    f.owasp_reference,
                )
            )
            + " |"
        )
    return "\n".join(lines)


def _detailed_findings(findings: list[VulnerabilityFinding]) -> str:
    sections = ["## Finding details"]
    for f in findings:
        location = (
            f"`{f.affected_file}:{f.affected_lines}`"
            if f.affected_lines
            else f"`{f.affected_file}`"
        )
        sections.append(
            f"### {f.vulnerability_id} — {f.severity.value} "
            f"(confidence: {f.confidence.value}, verification: "
            f"{f.verification_status.value})\n"
            f"\n"
            f"- **Location**: {location}\n"
            f"- **OWASP reference**: {f.owasp_reference}\n"
            f"- **Patch file**: `{f.patch_file_path}`\n"
            f"\n"
            f"**Description**\n\n"
            f"{f.description}\n"
            f"\n"
            f"**Exploit scenario**\n\n"
            f"{f.exploit_scenario}\n"
            f"\n"
            f"**Suggested fix**\n\n"
            f"{f.suggested_fix}"
        )
    return "\n\n---\n\n".join(sections)


def _footer(findings_count: int) -> str:
    return f"---\n\n*Findings: {findings_count}*"


# --- Helpers ---------------------------------------------------------------


def _md_cell(value: str) -> str:
    """Escape pipe characters that would otherwise break a Markdown table row."""
    return str(value).replace("|", "\\|").replace("\n", " ")


def _fmt_timestamp(ts: datetime) -> str:
    return ts.isoformat()


def _fmt_uuid(value: UUID) -> str:
    return str(value)
