"""HTML report generator (spec §2.2 step 6, §6.1, §6.2, BR-008).

Self-contained HTML — all CSS inlined, no JS — so a CI artifact opens
offline. Findings are split into three severity buckets ("Urgent",
"Cleanup", "Advisory"); Cleanup findings sharing the same
(vulnerability_id, severity) collapse into one group card with a combined
paste-prompt covering every location. Each card carries a synthesized
"PASTE THIS INTO YOUR AI EDITOR" block and a nested "Show vulnerable code"
toggle that reveals the actual lines from the scanned file when the caller
supplies the original file content.

Every user-controlled string is funnelled through ``html.escape`` to
prevent XSS in a rendered report.
"""

from __future__ import annotations

import base64
import re
from collections import OrderedDict
from datetime import datetime
from html import escape
from pathlib import Path
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
    Severity.Critical: "#b94a4a",
    Severity.High: "#c97a2a",
    Severity.Medium: "#b8902a",
    Severity.Low: "#4a7da3",
}

_GATE_COLOURS: dict[GateDecision, str] = {
    GateDecision.blocked: "#b94a4a",
    GateDecision.pass_: "#3f8a5a",
    GateDecision.advisory: "#7c8896",
    GateDecision.bypassed: "#c97a2a",
    GateDecision.scan_failed: "#b94a4a",
}

# Severities that auto-open in the detail section.
_OPEN_BY_DEFAULT: frozenset[Severity] = frozenset({Severity.Critical, Severity.High})

# Severity → bucket label.
_URGENT = (Severity.Critical, Severity.High)
_CLEANUP = (Severity.Medium,)
_ADVISORY = (Severity.Low,)

# Stable OWASP edition movements. Keys are 2021 IDs (or SECRET-001); values
# render as a footnote under each card. Categories with no movement omit.
_OWASP_2021_TO_2025: dict[str, str] = {
    "A03:2021": "Injection moved to A05:2025 in the latest edition.",
    "A07:2021": "Auth Failures absorbed into A05:2025 Security Misconfiguration.",
    "SECRET-001": "Hard-coded credentials relate to A05:2025 Security Misconfiguration.",
}

# Permissive `affected_lines` parser. Accepts "42", "42-55", "42, 43".
_LINES_RE = re.compile(r"(\d+)(?:\s*[-–]\s*(\d+))?")

# Phrase logo PNG, base64-embedded so the report stays a single
# self-contained HTML file (no external image refs).
_LOGO_PATH = Path(__file__).parent / "assets" / "phrase-logo.png"
_LOGO_DATA_URI = "data:image/png;base64," + base64.b64encode(_LOGO_PATH.read_bytes()).decode(
    "ascii"
)

_BRAND_HEADER = (
    '<div class="brand-header">'
    f'<img class="brand-logo" src="{_LOGO_DATA_URI}" alt="Phrase">'
    '<span class="brand-divider"></span>'
    '<span class="brand-tag">Security Scanner</span>'
    "</div>"
)


_STYLE = """
:root {
  --bg: #fafaf7;
  --surface: #ffffff;
  --text: #0a0a0a;
  --muted: #6b7480;
  --border: #e3e6ea;
  --row-tint: #f5f5f1;
  --brand: #2dd4a8;
  --brand-ink: #0a0a0a;
  --accent: #4a7da3;
  --critical: #b94a4a;
  --critical-tint: #f6e7e7;
  --high: #c97a2a;
  --high-tint: #f9ece0;
  --medium: #b8902a;
  --medium-tint: #f7f0d9;
  --low: #4a7da3;
  --low-tint: #e6eef5;
  --code-bg: #1c2027;
  --code-fg: #e6e8eb;
  --code-accent: #8fb3d4;
}
* { box-sizing: border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Inter",
               "Helvetica Neue", Arial, sans-serif;
  max-width: 960px;
  margin: 2.5em auto;
  padding: 0 1.25em 4em;
  background: var(--bg);
  color: var(--text);
  line-height: 1.65;
  font-size: 16px;
}
h1 {
  font-size: 1.8em;
  margin: 0 0 1em;
  padding-bottom: 0.4em;
  border-bottom: 2px solid var(--brand);
  letter-spacing: -0.01em;
}

.brand-header {
  display: flex;
  align-items: center;
  gap: 0.7em;
  margin: 0 0 1.4em;
}
.brand-header .brand-logo {
  flex: 0 0 auto;
  display: block;
  height: 40px;
  width: auto;
}
.brand-header .brand-divider {
  flex: 1 1 auto;
  height: 1px;
  background: var(--border);
  margin-left: 0.4em;
}
.brand-header .brand-tag {
  font-size: 0.78em;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: 0.08em;
  font-weight: 600;
}
h2 {
  font-size: 1.25em;
  margin-top: 2.25em;
  margin-bottom: 0.75em;
  padding-bottom: 0.3em;
  border-bottom: 1px solid var(--border);
  letter-spacing: -0.005em;
}
h3 { font-size: 1.05em; margin-top: 1.5em; margin-bottom: 0.4em; }
h4 { font-size: 0.95em; margin: 1em 0 0.3em; color: var(--muted);
     text-transform: uppercase; letter-spacing: 0.06em; }

.metadata {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1.25em 1.5em;
}
.metadata dl {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: 0.45em 1.5em;
  margin: 0;
}
.metadata dt { font-weight: 600; color: var(--muted); margin: 0; }
.metadata dd { margin: 0; }

.summary-bar {
  display: flex;
  flex-wrap: wrap;
  gap: 0.6em;
  margin: 1em 0 1.5em;
}
.summary-pill {
  display: inline-flex;
  align-items: baseline;
  gap: 0.5em;
  padding: 0.4em 0.9em;
  border-radius: 999px;
  background: var(--surface);
  border: 1px solid var(--border);
  font-size: 0.9em;
}
.summary-pill strong { font-weight: 600; }
.summary-pill.critical { background: var(--critical-tint); border-color: var(--critical); }
.summary-pill.high     { background: var(--high-tint);     border-color: var(--high); }
.summary-pill.medium   { background: var(--medium-tint);   border-color: var(--medium); }
.summary-pill.low      { background: var(--low-tint);      border-color: var(--low); }

.severity-pill {
  display: inline-block;
  padding: 0.15em 0.7em;
  border-radius: 999px;
  font-size: 0.8em;
  font-weight: 600;
  letter-spacing: 0.03em;
}
.severity-critical { background: var(--critical-tint); color: var(--critical); }
.severity-high     { background: var(--high-tint);     color: var(--high); }
.severity-medium   { background: var(--medium-tint);   color: var(--medium); }
.severity-low      { background: var(--low-tint);      color: var(--low); }

.warning {
  background: #fdf6e3;
  border-left: 4px solid var(--high);
  padding: 0.8em 1.1em;
  margin: 0.75em 0;
  border-radius: 0 6px 6px 0;
}

.gate-decision {
  display: inline-block;
  padding: 0.45em 1em;
  border-radius: 6px;
  color: white;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  font-size: 0.9em;
}

table {
  border-collapse: separate;
  border-spacing: 0;
  width: 100%;
  margin-top: 0.75em;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  overflow: hidden;
}
th, td {
  padding: 0.65em 0.9em;
  border-bottom: 1px solid var(--border);
  text-align: left;
  vertical-align: top;
}
thead th {
  background: var(--row-tint);
  font-size: 0.85em;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--muted);
  position: sticky;
  top: 0;
  z-index: 1;
}
tbody tr:nth-child(even) td { background: var(--row-tint); }
tbody tr:hover td { background: #ecedf0; }
tbody tr:last-child td { border-bottom: 0; }
td a.finding-link {
  color: var(--accent);
  text-decoration: none;
  font-weight: 600;
}
td a.finding-link:hover { text-decoration: underline; }

code {
  background: var(--row-tint);
  padding: 0.1em 0.45em;
  border-radius: 4px;
  font-size: 0.88em;
  font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
}
pre {
  background: var(--surface);
  border: 1px solid var(--border);
  padding: 1em;
  border-radius: 6px;
  overflow-x: auto;
  font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  font-size: 0.88em;
}

/* Bucket headers — section dividers above each severity tier. */
.bucket-header {
  margin: 2em 0 0.5em;
  padding: 0.4em 0.9em;
  border-left: 4px solid var(--border);
  font-size: 1.05em;
  font-weight: 600;
}
.bucket-header.bucket-urgent   { border-left-color: var(--critical); color: var(--critical); }
.bucket-header.bucket-cleanup  { border-left-color: var(--medium);   color: var(--medium); }
.bucket-header.bucket-advisory { border-left-color: var(--low);      color: var(--low); }
.bucket-header .bucket-hint {
  font-size: 0.8em;
  font-weight: 400;
  color: var(--muted);
  margin-left: 0.6em;
  letter-spacing: 0.02em;
}

/* Finding cards — collapsible, anchor target gets a gentle nudge. */
details.finding-block {
  background: var(--surface);
  border: 1px solid var(--border);
  border-left-width: 4px;
  border-radius: 6px;
  padding: 0 1.25em;
  margin: 0.8em 0;
  transition: border-color 0.15s ease;
}
details.finding-block.sev-critical { border-left-color: var(--critical); }
details.finding-block.sev-high     { border-left-color: var(--high); }
details.finding-block.sev-medium   { border-left-color: var(--medium); }
details.finding-block.sev-low      { border-left-color: var(--low); }
details.finding-block:target,
details.finding-block:has(:target) { box-shadow: 0 0 0 3px rgba(74, 125, 163, 0.18); }
details.finding-block > summary {
  cursor: pointer;
  list-style: none;
  padding: 0.9em 0;
  font-weight: 600;
  display: flex;
  align-items: center;
  gap: 0.7em;
  flex-wrap: wrap;
}
details.finding-block > summary::-webkit-details-marker { display: none; }
details.finding-block > summary::before {
  content: "▸";
  color: var(--muted);
  font-size: 0.9em;
  transition: transform 0.15s ease;
}
details.finding-block[open] > summary::before { transform: rotate(90deg); }
details.finding-block .meta-row {
  font-size: 0.85em;
  color: var(--muted);
  margin: 0.5em 0 1em;
}
details.finding-block .meta-row strong { color: var(--text); font-weight: 600; }
details.finding-block > *:last-child { margin-bottom: 1em; }

/* Quick-fix badge. */
.fix-badge {
  display: inline-block;
  padding: 0.1em 0.6em;
  border-radius: 999px;
  font-size: 0.72em;
  font-weight: 600;
  letter-spacing: 0.03em;
  background: var(--low-tint);
  color: var(--accent);
  margin-left: auto;
}

/* Risk callout — soft red band, not screaming. */
.risk-callout {
  background: var(--critical-tint);
  color: var(--critical);
  border-left: 3px solid var(--critical);
  padding: 0.6em 0.9em;
  border-radius: 0 6px 6px 0;
  margin: 0.6em 0 0.9em;
  font-size: 0.95em;
}
.risk-callout::before { content: "⚠ Risk: "; font-weight: 600; }

/* "PASTE THIS INTO YOUR AI EDITOR" — dark surface, always visible when
   the card is open (no JS, no copy button). */
.ai-prompt {
  background: var(--code-bg);
  color: var(--code-fg);
  border-radius: 6px;
  padding: 0.9em 1em;
  margin: 0.5em 0 1em;
  font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  font-size: 0.86em;
  line-height: 1.55;
  white-space: pre-wrap;
  word-break: break-word;
}
.ai-prompt-header {
  display: block;
  color: var(--code-accent);
  font-size: 0.72em;
  font-weight: 600;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  margin-bottom: 0.6em;
}

/* Nested code-reveal toggle inside a finding card. */
details.code-toggle {
  margin: 0.4em 0 1em;
  border: 1px dashed var(--border);
  border-radius: 6px;
  padding: 0 0.9em;
  background: var(--row-tint);
}
details.code-toggle > summary {
  cursor: pointer;
  list-style: none;
  padding: 0.55em 0;
  font-size: 0.85em;
  color: var(--muted);
  font-weight: 600;
}
details.code-toggle > summary::-webkit-details-marker { display: none; }
details.code-toggle > summary::before {
  content: "▸ ";
  color: var(--muted);
  font-size: 0.85em;
}
details.code-toggle[open] > summary::before { content: "▾ "; }
details.code-toggle pre.code-snippet {
  background: var(--surface);
  border: 1px solid var(--border);
  margin: 0 0 0.8em;
  padding: 0.7em 0.9em;
  font-size: 0.84em;
}
.code-snippet .ln {
  display: inline-block;
  width: 2.5em;
  color: var(--muted);
  text-align: right;
  user-select: none;
  margin-right: 0.9em;
}

/* Group card — multiple Medium findings sharing id+severity. */
.group-intro {
  background: var(--low-tint);
  border-left: 3px solid var(--accent);
  padding: 0.6em 0.9em;
  border-radius: 0 6px 6px 0;
  margin: 0.4em 0 0.8em;
  font-size: 0.93em;
}
.group-intro strong { color: var(--accent); }
ol.location-list {
  margin: 0.6em 0 1em;
  padding-left: 1.4em;
}
ol.location-list > li { margin: 0.5em 0; }

.footer {
  margin-top: 3em;
  padding-top: 1em;
  border-top: 1px solid var(--border);
  color: var(--muted);
  font-size: 0.85em;
}

/* Print: expand every detail and drop interactive affordances. */
@media print {
  body { background: white; max-width: none; margin: 1em; }
  details.finding-block, details.code-toggle { break-inside: avoid; }
  details, details > * { display: block !important; }
  details > summary::before { content: ""; }
  thead th { position: static; }
}
"""


def build_html_report(
    result: ScanResult,
    *,
    files: dict[str, str] | None = None,
) -> str:
    """Render *result* as a self-contained HTML document.

    When *files* is supplied, each finding card carries a nested "Show
    vulnerable code" toggle revealing the actual lines referenced by
    ``affected_lines``. Without *files*, the toggle is silently omitted.
    """
    sections: list[str] = [_metadata_section(result)]

    if result.findings:
        sections.append(_summary_bar(result.findings))

    warnings = _gather_warnings(result)
    if warnings:
        sections.append(_warnings_section(warnings))

    if result.scan_type == ScanType.deployment_gate:
        sections.append(_gate_decision_section(result.gate_decision))

    if result.findings:
        sections.append(_findings_table(result.findings))
        sections.append(_detailed_findings(result.findings, files))

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
        f"{_BRAND_HEADER}\n"
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
    items = "\n".join(f"<dt>{escape(label)}</dt><dd>{value}</dd>" for label, value in rows)
    return f'<section class="metadata">\n<h2>Scan metadata</h2>\n<dl>\n{items}\n</dl>\n</section>'


def _gather_warnings(result: ScanResult) -> list[str]:
    warnings: list[str] = []

    if result.partial_scan:
        files_html = (
            ", ".join(_code(p) for p in result.unscanned_files)
            if result.unscanned_files
            else "<em>(none listed)</em>"
        )
        warnings.append(
            f"<strong>⚠️ PARTIAL SCAN</strong> — the following files were not analysed: {files_html}"
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

    auto_triaged = [
        f for f in result.findings if f.verification_status == VerificationStatus.advisory_real
    ]
    if auto_triaged:
        warnings.append(
            "<strong>ℹ️ AUTO-TRIAGED</strong> — "
            f"{len(auto_triaged)} findings were auto-triaged as potential issues "
            "with medium confidence. These are not blocking — review at your discretion."
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
    rows = "\n".join(_findings_table_row(f, idx) for idx, f in enumerate(findings, start=1))
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


def _findings_table_row(f: VulnerabilityFinding, idx: int) -> str:
    anchor = f"finding-{idx}"
    return (
        "<tr>"
        f'<td><a class="finding-link" href="#{anchor}">'
        f"{escape(f.vulnerability_id)}</a></td>"
        f"<td>{_severity_span(f.severity)}</td>"
        f"<td>{escape(f.confidence.value)}</td>"
        f"<td>{escape(f.verification_status.value)}</td>"
        f"<td>{_code(f.affected_file)}</td>"
        f"<td>{escape(f.affected_lines or '—')}</td>"
        f"<td>{_owasp_link(f.owasp_reference)}</td>"
        "</tr>"
    )


# --- Detailed findings: bucket, group, render -----------------------------


def _detailed_findings(
    findings: list[VulnerabilityFinding],
    files: dict[str, str] | None,
) -> str:
    """Render findings in severity buckets; Cleanup groups duplicates."""
    urgent, cleanup, advisory = _bucket_findings(findings)
    # Indices map each finding to its 1-based row in the overview table so
    # `#finding-N` anchors continue to resolve correctly.
    indices = {id(f): i for i, f in enumerate(findings, start=1)}

    parts: list[str] = ["<section>\n<h2>Finding details</h2>"]

    if urgent:
        parts.append(
            _render_bucket(
                "Urgent",
                "urgent",
                "fix before you launch",
                urgent,
                indices,
                files,
                group=False,
            )
        )
    if cleanup:
        parts.append(
            _render_bucket(
                "Cleanup",
                "cleanup",
                "fix soon",
                cleanup,
                indices,
                files,
                group=True,
            )
        )
    if advisory:
        parts.append(
            _render_bucket(
                "Advisory",
                "advisory",
                "review when convenient",
                advisory,
                indices,
                files,
                group=True,
            )
        )

    parts.append("</section>")
    return "\n".join(parts)


def _bucket_findings(
    findings: list[VulnerabilityFinding],
) -> tuple[
    list[VulnerabilityFinding],
    list[VulnerabilityFinding],
    list[VulnerabilityFinding],
]:
    urgent = [f for f in findings if f.severity in _URGENT]
    cleanup = [f for f in findings if f.severity in _CLEANUP]
    advisory = [f for f in findings if f.severity in _ADVISORY]
    return urgent, cleanup, advisory


def _render_bucket(
    label: str,
    css_suffix: str,
    hint: str,
    bucket: list[VulnerabilityFinding],
    indices: dict[int, int],
    files: dict[str, str] | None,
    *,
    group: bool,
) -> str:
    header = (
        f'<h3 class="bucket-header bucket-{css_suffix}">'
        f"{escape(label)} ({len(bucket)})"
        f'<span class="bucket-hint">— {escape(hint)}</span>'
        "</h3>"
    )

    if not group:
        cards = "\n".join(_finding_card(f, indices[id(f)], files) for f in bucket)
        return f"{header}\n{cards}"

    # Group consecutive findings sharing (vulnerability_id, severity). Use
    # an OrderedDict to preserve first-occurrence order while merging
    # non-adjacent matches (Pydantic findings can interleave).
    groups: OrderedDict[tuple[str, str], list[VulnerabilityFinding]] = OrderedDict()
    for f in bucket:
        groups.setdefault((f.vulnerability_id, f.severity.value), []).append(f)

    cards: list[str] = []
    for items in groups.values():
        if len(items) == 1:
            cards.append(_finding_card(items[0], indices[id(items[0])], files))
        else:
            cards.append(_group_card(items, indices, files))
    return f"{header}\n" + "\n".join(cards)


def _advisory_real_badge() -> str:
    """HTML badge for auto-triaged advisory_real findings."""
    return (
        '<span class="fix-badge" style="background:#e8f4fd;color:#2980b9;border:1px solid #aed6f1">'
        "Potential issue (auto-triaged, not blocking)"
        "</span>"
    )


# Prefix that identifies an upload context summary (produced by UploadContext.overall_summary).
_UPLOAD_CTX_PREFIX = "Validation:"

# Labels for the upload context panel fields (parsed from overall_summary).
_UPLOAD_FIELD_RE = re.compile(
    r"Validation:\s*([^—]+)"
    r"—\s*Naming:\s*([^—]+)"
    r"—\s*Storage:\s*([^—]+)"
    r"—\s*Limits:\s*([^—]+)"
    r"—\s*Access:\s*([^—]+)"
    r"—\s*Processing:\s*(.+)",
    re.DOTALL,
)


def _upload_context_panel(context_summary: str) -> str:
    """Render a compact upload context panel from context_summary.

    Returns an empty string when context_summary is not an upload summary.

    The panel shows:
      Validation: <value> | Naming: <value> | Storage: <value> |
      Limits: <value> | Access: <value> | Processing: <value>
    """
    if not context_summary or _UPLOAD_CTX_PREFIX not in context_summary:
        return ""

    m = _UPLOAD_FIELD_RE.search(context_summary)
    if m:
        validation = m.group(1).strip()
        naming = m.group(2).strip()
        storage = m.group(3).strip()
        limits = m.group(4).strip()
        access = m.group(5).strip()
        processing = m.group(6).strip()
    else:
        # Can't parse — render as a simple pre block.
        return (
            '<details class="code-toggle">'
            "<summary>Upload context</summary>"
            f'<pre style="white-space:pre-wrap;font-size:0.85em">{escape(context_summary)}</pre>'
            "</details>"
        )

    rows = [
        ("Validation", validation),
        ("Naming", naming),
        ("Storage", storage),
        ("Limits", limits),
        ("Access", access),
        ("Processing", processing),
    ]
    cells = " | ".join(
        f"<strong>{escape(label)}:</strong> {escape(value)}" for label, value in rows
    )
    return (
        '<details class="code-toggle">'
        "<summary>Upload context</summary>"
        f'<div style="padding:0.5em 0;font-size:0.88em">{cells}</div>'
        "</details>"
    )


def _finding_card(
    f: VulnerabilityFinding,
    idx: int,
    files: dict[str, str] | None,
) -> str:
    open_attr = " open" if f.severity in _OPEN_BY_DEFAULT else ""
    sev_class = f"sev-{f.severity.value.lower()}"
    location = (
        f"{_code(f.affected_file)}:{escape(f.affected_lines)}"
        if f.affected_lines
        else _code(f.affected_file)
    )
    badge = _fix_badge_html(f.suggested_fix)
    parts: list[str] = [
        f'<details id="finding-{idx}" class="finding-block {sev_class}"{open_attr}>',
        "<summary>",
        _severity_span(f.severity),
        f"<span>{escape(f.vulnerability_id)} — {location}</span>",
        badge,
    ]
    # Advisory_real findings get the auto-triaged badge.
    if f.verification_status == VerificationStatus.advisory_real:
        parts.append(_advisory_real_badge())
    parts += [
        "</summary>",
        f"<p>{escape(f.description)}</p>",
        f'<div class="risk-callout">{escape(f.exploit_scenario)}</div>',
        _ai_prompt_block(_synthesize_ai_prompt(f), header="Paste this into your AI editor"),
    ]
    # Render upload context panel when present (upload findings).
    upload_panel = _upload_context_panel(f.context_summary)
    if upload_panel:
        parts.append(upload_panel)
    elif f.context_summary:
        # Fallback: generic cross-file context toggle.
        parts.append(
            '<details class="code-toggle">'
            "<summary>Cross-file context</summary>"
            f'<pre style="white-space:pre-wrap;font-size:0.85em">'
            f"{escape(f.context_summary)}</pre>"
            "</details>"
        )
    snippet = _code_snippet_block(files, f.affected_file, f.affected_lines)
    if snippet:
        parts.append(snippet)
    parts.append(_card_meta_row(f))
    parts.append("</details>")
    return "\n".join(parts)


def _group_card(
    items: list[VulnerabilityFinding],
    indices: dict[int, int],
    files: dict[str, str] | None,
) -> str:
    head = items[0]
    first_idx = indices[id(head)]
    sev_class = f"sev-{head.severity.value.lower()}"
    parts: list[str] = [
        f'<details id="finding-{first_idx}" class="finding-block {sev_class}">',
        "<summary>",
        _severity_span(head.severity),
        f"<span>All {len(items)} are one problem — {escape(head.vulnerability_id)}</span>",
        '<span class="fix-badge">fix all at once</span>',
        "</summary>",
        (
            '<div class="group-intro"><strong>All '
            + str(len(items))
            + " are one problem:</strong> "
            + escape(head.description)
            + " You can fix them all at once with the prompt below, then check "
            "each row for the exact files.</div>"
        ),
        _ai_prompt_block(
            _synthesize_group_prompt(items),
            header=f"Fix all {len(items)} at once",
        ),
        "<h4>Affected locations</h4>",
        '<ol class="location-list">',
    ]
    for f in items:
        idx = indices[id(f)]
        loc = (
            f"{_code(f.affected_file)}:{escape(f.affected_lines)}"
            if f.affected_lines
            else _code(f.affected_file)
        )
        snippet = _code_snippet_block(files, f.affected_file, f.affected_lines)
        parts.append(
            f'<li id="finding-{idx}">{loc}' + (f"\n{snippet}" if snippet else "") + "</li>"
        )
    parts.append("</ol>")
    parts.append(_card_meta_row(head))
    parts.append("</details>")
    return "\n".join(parts)


def _card_meta_row(f: VulnerabilityFinding) -> str:
    footnote = _OWASP_2021_TO_2025.get(f.vulnerability_id, "")
    footnote_html = f" <em>— {escape(footnote)}</em>" if footnote else ""
    # "Detected by" row: show when sources are present (even single-voter).
    detected_by_html = ""
    if f.consensus_score >= 1 and f.sources:
        source_list = escape(", ".join(f.sources))
        detected_by_html = (
            f" &middot; <strong>Detected by:</strong> {source_list} "
            f"({f.consensus_score} voter{'s' if f.consensus_score != 1 else ''})"
        )
    return (
        '<div class="meta-row">'
        f"<strong>Confidence:</strong> {escape(f.confidence.value)} &middot; "
        f"<strong>Verification:</strong> {escape(f.verification_status.value)} &middot; "
        f"<strong>OWASP:</strong> {_owasp_link(f.owasp_reference)}{footnote_html} &middot; "
        f"<strong>Patch:</strong> {_code(f.patch_file_path)}"
        f"{detected_by_html}"
        "</div>"
    )


# --- AI-paste prompt synthesis --------------------------------------------


def _synthesize_ai_prompt(f: VulnerabilityFinding) -> str:
    where = f.affected_file + (f" around line {f.affected_lines}" if f.affected_lines else "")
    desc = (f.description or "").rstrip(". ").strip() or "security issue"
    fix = (f.suggested_fix or "").rstrip(". ").strip()
    tail = f" {fix}." if fix else ""
    return f"There is a {desc} in {where}.{tail} Then show me the change."


def _synthesize_group_prompt(group: list[VulnerabilityFinding]) -> str:
    head = group[0]
    desc = (head.description or "").rstrip(". ").strip() or "security issue"
    items: list[str] = []
    for i, f in enumerate(group, start=1):
        loc = f.affected_file + (f" line {f.affected_lines}" if f.affected_lines else "")
        fix = (f.suggested_fix or "").rstrip(". ").strip() or "apply the standard remediation"
        items.append(f"({i}) {loc} — {fix}")
    body = "; ".join(items)
    return (
        f"My project has multiple {desc} issues that a security scan "
        f"flagged. Please fix all of these: {body}. For every credential "
        "that was exposed, remind me to rotate it (change it to a new "
        "value) since it was visible in the code. Show me each change."
    )


def _ai_prompt_block(prompt_text: str, *, header: str) -> str:
    return (
        '<div class="ai-prompt">'
        f'<span class="ai-prompt-header">📋 {escape(header)}</span>'
        f"{escape(prompt_text)}"
        "</div>"
    )


# --- Vulnerable-code snippet (nested toggle) ------------------------------


def _code_snippet_block(
    files: dict[str, str] | None,
    affected_file: str,
    affected_lines: str | None,
) -> str:
    if not files:
        return ""
    content = files.get(affected_file)
    if content is None:
        return ""
    extracted = _extract_code_snippet(content, affected_lines)
    if extracted is None:
        return ""
    snippet, start_line = extracted
    label = (
        f"Show vulnerable code (lines {escape(affected_lines)})"
        if affected_lines
        else "Show vulnerable code"
    )
    numbered = _format_snippet_lines(snippet, start_line)
    return (
        '<details class="code-toggle">'
        f"<summary>{label}</summary>"
        f'<pre class="code-snippet">{numbered}</pre>'
        "</details>"
    )


def _extract_code_snippet(
    content: str,
    affected_lines: str | None,
) -> tuple[str, int] | None:
    """Slice file content for the line range, with ±2 lines of context.

    Returns (snippet_text, true_start_line) where ``true_start_line`` is the
    1-based line number of the first line in the returned snippet.
    """
    parsed = _parse_lines(affected_lines)
    if parsed is None:
        return None
    start, end = parsed
    lines = content.splitlines()
    if not lines:
        return None
    # Clamp into file range; widen by 2 for context.
    lo = max(1, start - 2)
    hi = min(len(lines), end + 2)
    if lo > hi:
        return None
    snippet = "\n".join(lines[lo - 1 : hi])
    return snippet, lo


def _parse_lines(spec: str | None) -> tuple[int, int] | None:
    if not spec:
        return None
    m = _LINES_RE.search(spec)
    if not m:
        return None
    start = int(m.group(1))
    end = int(m.group(2)) if m.group(2) else start
    if end < start:
        start, end = end, start
    return start, end


def _format_snippet_lines(snippet: str, start_line: int) -> str:
    out: list[str] = []
    for offset, raw in enumerate(snippet.splitlines(), start=0):
        ln = start_line + offset
        out.append(f'<span class="ln">{ln}</span>{escape(raw)}')
    return "\n".join(out)


# --- Quick-fix badge heuristic --------------------------------------------


def _fix_badge_html(suggested_fix: str) -> str:
    label = _quick_fix_label(suggested_fix)
    if not label:
        return ""
    return f'<span class="fix-badge">{escape(label)}</span>'


def _quick_fix_label(suggested_fix: str) -> str:
    """Cheap heuristic so the reader can scan for low-effort fixes.

    1 line  -> "1-line fix"
    2-3     -> "quick fix"
    longer  -> no badge (the fix needs proper attention)
    """
    if not suggested_fix:
        return ""
    lines = [ln for ln in suggested_fix.splitlines() if ln.strip()]
    if len(lines) <= 1:
        return "1-line fix"
    if len(lines) <= 3:
        return "quick fix"
    return ""


# --- Summary pills, helpers, footer ---------------------------------------


def _summary_bar(findings: list[VulnerabilityFinding]) -> str:
    counts: dict[Severity, int] = {
        Severity.Critical: 0,
        Severity.High: 0,
        Severity.Medium: 0,
        Severity.Low: 0,
    }
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1
    pills = "\n".join(
        f'<span class="summary-pill {sev.value.lower()}">'
        f"<strong>{counts[sev]}</strong> {escape(sev.value)}</span>"
        for sev in (Severity.Critical, Severity.High, Severity.Medium, Severity.Low)
    )
    return f'<div class="summary-bar" aria-label="Severity summary">\n{pills}\n</div>'


def _footer(findings_count: int) -> str:
    return f'<div class="footer">Findings: {findings_count}</div>'


def _severity_span(severity: Severity) -> str:
    cls = f"severity-{severity.value.lower()}"
    return f'<span class="severity-pill {cls}">{escape(severity.value)}</span>'


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
