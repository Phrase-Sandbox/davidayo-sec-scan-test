"""HTML report generator (spec §2.2 step 6, §6.1, §6.2, BR-008).

Self-contained HTML file — all CSS is inlined in a ``<style>`` block so the
report renders correctly when downloaded as a CI/CD artifact and opened
without a network connection.

Severity colour coding per the user spec:
- Critical → red (#c0392b)
- High → orange (#e67e22)
- Medium → yellow (#d4ac0d)
- Low → blue (#2980b9)

Every value derived from user-controlled input (filenames, descriptions,
exploit scenarios, owasp references) is passed through ``html.escape`` to
prevent XSS in a rendered report.
"""

from __future__ import annotations

from datetime import datetime
from html import escape
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

_SEVERITY_COLOURS: dict[Severity, str] = {
    Severity.Critical: "#c0392b",
    Severity.High: "#e67e22",
    Severity.Medium: "#d4ac0d",
    Severity.Low: "#2980b9",
}

_GATE_COLOURS: dict[GateDecision, str] = {
    GateDecision.blocked: "#c0392b",
    GateDecision.pass_: "#27ae60",
    GateDecision.advisory: "#7f8c8d",
    GateDecision.bypassed: "#e67e22",
    GateDecision.scan_failed: "#c0392b",
}

_STYLE = """
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  max-width: 960px;
  margin: 2em auto;
  padding: 0 1em;
  color: #2c3e50;
  line-height: 1.5;
}
h1 { border-bottom: 2px solid #2c3e50; padding-bottom: 0.25em; }
h2 { margin-top: 2em; border-bottom: 1px solid #ecf0f1; padding-bottom: 0.2em; }
h3 { margin-top: 1.5em; }
.metadata { background: #f8f9fa; padding: 1em; border-radius: 4px; }
.metadata dt { font-weight: bold; float: left; clear: left; width: 12em; }
.warning {
  background: #fff8e1;
  border-left: 4px solid #ffb300;
  padding: 0.75em 1em;
  margin: 0.75em 0;
}
.severity-critical { color: #c0392b; font-weight: bold; }
.severity-high { color: #e67e22; font-weight: bold; }
.severity-medium { color: #d4ac0d; font-weight: bold; }
.severity-low { color: #2980b9; }
.gate-decision {
  display: inline-block;
  padding: 0.4em 0.8em;
  border-radius: 4px;
  color: white;
  font-weight: bold;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}
table { border-collapse: collapse; width: 100%; margin-top: 0.5em; }
th, td { padding: 0.5em 0.75em; border: 1px solid #dfe6e9; text-align: left; }
th { background: #ecf0f1; }
tr:nth-child(even) td { background: #fafbfc; }
code { background: #ecf0f1; padding: 0.1em 0.4em; border-radius: 3px; font-size: 0.9em; }
pre { background: #f8f9fa; padding: 1em; border-radius: 4px; overflow-x: auto; }
.finding-block {
  border: 1px solid #dfe6e9;
  border-radius: 6px;
  padding: 1em 1.25em;
  margin: 1em 0;
}
.footer {
  margin-top: 3em;
  padding-top: 1em;
  border-top: 1px solid #ecf0f1;
  color: #7f8c8d;
  font-size: 0.9em;
}
"""


def build_html_report(result: ScanResult) -> str:
    """Render *result* as a self-contained HTML document."""
    sections: list[str] = [_metadata_section(result)]

    warnings = _gather_warnings(result)
    if warnings:
        sections.append(_warnings_section(warnings))

    if result.scan_type == ScanType.deployment_gate:
        sections.append(_gate_decision_section(result.gate_decision))

    if result.findings:
        sections.append(_findings_table(result.findings))
        sections.append(_detailed_findings(result.findings))

    sections.append(_footer(result.findings_count))

    body = "\n".join(sections)
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        "<title>Security Scan Report</title>\n"
        f"<style>{_STYLE}</style>\n"
        "</head>\n"
        "<body>\n"
        "<h1>Security Scan Report</h1>\n"
        f"{body}\n"
        "</body>\n"
        "</html>\n"
    )


# --- Sections --------------------------------------------------------------


def _metadata_section(result: ScanResult) -> str:
    rows = [
        ("Scan ID", _code(_fmt_uuid(result.scan_id))),
        ("Repository", escape(result.repo_url)),
        ("Timestamp", escape(_fmt_timestamp(result.timestamp))),
        ("Scan type", _code(result.scan_type.value)),
        ("Scan target", _code(result.scan_target.value)),
        ("Triggered by", escape(result.triggered_by)),
    ]
    items = "\n".join(
        f"<dt>{escape(label)}</dt><dd>{value}</dd>" for label, value in rows
    )
    return (
        '<section class="metadata">\n'
        "<h2>Scan metadata</h2>\n"
        f"<dl>\n{items}\n</dl>\n"
        "</section>"
    )


def _gather_warnings(result: ScanResult) -> list[str]:
    warnings: list[str] = []

    if result.partial_scan:
        files_html = (
            ", ".join(_code(p) for p in result.unscanned_files)
            if result.unscanned_files
            else "<em>(none listed)</em>"
        )
        warnings.append(
            "<strong>⚠️ PARTIAL SCAN</strong> — the following files were not "
            f"analysed: {files_html}"
        )

    conflicting = [
        f
        for f in result.findings
        if f.severity == Severity.Critical
        and f.verification_status == VerificationStatus.conflicting
    ]
    if conflicting:
        warnings.append(
            "<strong>⚠️ CONFLICTING FINDINGS</strong> — "
            f"{len(conflicting)} Critical findings were not confirmed by "
            "the verification pass. These are reported as advisories."
        )

    advisory_demotions = [
        f
        for f in result.findings
        if f.severity in {Severity.Critical, Severity.High}
        and f.confidence in {Confidence.Medium, Confidence.Low}
    ]
    if advisory_demotions:
        warnings.append(
            "<strong>⚠️ ADVISORY</strong> — "
            f"{len(advisory_demotions)} findings are High/Critical severity "
            "but have Medium/Low confidence. These are not blocking."
        )

    if not result.findings:
        warnings.append(
            "<strong>⚠️ NO FINDINGS DETECTED</strong> — developer "
            "acknowledgement required before gate passes."
        )

    return warnings


def _warnings_section(warnings: list[str]) -> str:
    blocks = "\n".join(f'<div class="warning">{w}</div>' for w in warnings)
    return f"<section>\n<h2>Warnings</h2>\n{blocks}\n</section>"


def _gate_decision_section(decision: GateDecision) -> str:
    colour = _GATE_COLOURS.get(decision, "#7f8c8d")
    return (
        "<section>\n"
        "<h2>Gate decision</h2>\n"
        f'<span class="gate-decision" style="background:{colour}">'
        f"{escape(decision.value)}</span>\n"
        "</section>"
    )


def _findings_table(findings: list[VulnerabilityFinding]) -> str:
    rows = "\n".join(_findings_table_row(f) for f in findings)
    return (
        "<section>\n"
        f"<h2>Findings ({len(findings)})</h2>\n"
        "<table>\n"
        "<thead><tr>"
        "<th>ID</th><th>Severity</th><th>Confidence</th>"
        "<th>Verification</th><th>File</th><th>Lines</th>"
        "<th>OWASP reference</th>"
        "</tr></thead>\n"
        f"<tbody>\n{rows}\n</tbody>\n"
        "</table>\n"
        "</section>"
    )


def _findings_table_row(f: VulnerabilityFinding) -> str:
    return (
        "<tr>"
        f"<td>{escape(f.vulnerability_id)}</td>"
        f"<td>{_severity_span(f.severity)}</td>"
        f"<td>{escape(f.confidence.value)}</td>"
        f"<td>{escape(f.verification_status.value)}</td>"
        f"<td>{_code(f.affected_file)}</td>"
        f"<td>{escape(f.affected_lines or '—')}</td>"
        f"<td>{_owasp_link(f.owasp_reference)}</td>"
        "</tr>"
    )


def _detailed_findings(findings: list[VulnerabilityFinding]) -> str:
    blocks = "\n".join(_finding_block(f) for f in findings)
    return f"<section>\n<h2>Finding details</h2>\n{blocks}\n</section>"


def _finding_block(f: VulnerabilityFinding) -> str:
    location = (
        f"{_code(f.affected_file)}:{escape(f.affected_lines)}"
        if f.affected_lines
        else _code(f.affected_file)
    )
    return (
        '<article class="finding-block">\n'
        f"<h3>{escape(f.vulnerability_id)} — {_severity_span(f.severity)}</h3>\n"
        "<p>"
        f"<strong>Confidence:</strong> {escape(f.confidence.value)} &middot; "
        f"<strong>Verification:</strong> {escape(f.verification_status.value)} &middot; "
        f"<strong>Location:</strong> {location} &middot; "
        f"<strong>OWASP:</strong> {_owasp_link(f.owasp_reference)} &middot; "
        f"<strong>Patch:</strong> {_code(f.patch_file_path)}"
        "</p>\n"
        f"<h4>Description</h4>\n<p>{escape(f.description)}</p>\n"
        f"<h4>Exploit scenario</h4>\n<p>{escape(f.exploit_scenario)}</p>\n"
        f"<h4>Suggested fix</h4>\n<p>{escape(f.suggested_fix)}</p>\n"
        "</article>"
    )


def _footer(findings_count: int) -> str:
    return f'<div class="footer">Findings: {findings_count}</div>'


# --- Helpers ---------------------------------------------------------------


def _severity_span(severity: Severity) -> str:
    cls = f"severity-{severity.value.lower()}"
    return f'<span class="{cls}">{escape(severity.value)}</span>'


def _owasp_link(reference: str) -> str:
    if reference.startswith(("http://", "https://")):
        return f'<a href="{escape(reference, quote=True)}">{escape(reference)}</a>'
    return escape(reference)


def _code(value: str) -> str:
    return f"<code>{escape(value)}</code>"


def _fmt_timestamp(ts: datetime) -> str:
    return ts.isoformat()


def _fmt_uuid(value: UUID) -> str:
    return str(value)
