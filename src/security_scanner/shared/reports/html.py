"""HTML report generator (spec §2.2 step 6, §6.1, §6.2, BR-008).

Self-contained HTML — all CSS inlined, no JS — so a CI artifact opens
offline. Findings are split into three severity buckets ("Urgent Findings",
"High Priority Findings", "Additional Findings"); medium/low findings sharing
the same (vulnerability_id, severity) collapse into one group card with a
combined paste-prompt covering every location. Each card carries an AI fix
prompt toggle and a "Show vulnerable code" toggle that reveals the actual
lines from the scanned file when the caller supplies the original file
content.

Every user-controlled string is funnelled through ``html.escape`` to
prevent XSS in a rendered report.
"""

from __future__ import annotations

import base64
import re
from collections import Counter, OrderedDict
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
from security_scanner.shared.reports.vuln_names import vuln_display_name

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
    "A03:2021": "Injection is A05:2025 in the latest edition.",
    "A07:2021": "Renamed to A07:2025 Authentication Failures in the latest edition.",
    "A08:2021": "Renamed to A08:2025 Software or Data Integrity Failures in the latest edition.",
    "A09:2021": "Renamed to A09:2025 Security Logging and Alerting Failures in the latest edition.",
    "A10:2021": "SSRF is not a standalone category in OWASP Top 10:2025.",
    "SECRET-001": "Hard-coded credentials map to A04:2025 Cryptographic Failures in the latest edition.",  # noqa: E501
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
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&display=swap');

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
  font-family: "IBM Plex Sans", system-ui, -apple-system, sans-serif;
  max-width: 960px;
  margin: 2.5em auto;
  padding: 0 1.25em 4em;
  background: var(--bg);
  color: var(--text);
  line-height: 1.65;
  font-size: 16px;
}
h1 {
  font-size: 1.9em;
  font-weight: 700;
  margin: 0 0 1em;
  padding-bottom: 0.4em;
  border-bottom: 2px solid var(--brand);
  letter-spacing: -0.02em;
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
  font-size: 1.15em;
  font-weight: 600;
  margin-top: 2.5em;
  margin-bottom: 0.75em;
  padding-bottom: 0.4em;
  border-bottom: 1px solid var(--border);
  letter-spacing: -0.01em;
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

/* Bucket headers */
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

/* Finding cards — left-border accent only, no outer box */
details.finding-block {
  border-left: 3px solid var(--border);
  padding: 0 0 0 1.25em;
  margin: 0.8em 0;
}
details.finding-block.sev-critical { border-left-color: var(--critical); }
details.finding-block.sev-high     { border-left-color: var(--high); }
details.finding-block.sev-medium   { border-left-color: var(--medium); }
details.finding-block.sev-low      { border-left-color: var(--low); }
details.finding-block:target,
details.finding-block:has(:target) {
  background: rgba(74, 125, 163, 0.04);
  border-radius: 0 6px 6px 0;
}
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
  flex-shrink: 0;
}
details.finding-block[open] > summary::before { transform: rotate(90deg); }
details.finding-block > *:last-child { margin-bottom: 1em; }

/* Quick-fix badge */
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

/* Finding card content: impact and fix as plain text */
.finding-impact {
  font-style: italic;
  color: var(--muted);
  margin: 0.2em 0 0.6em;
  font-size: 0.95em;
  line-height: 1.55;
}
.finding-fix {
  margin: 0.4em 0 0.8em;
  font-size: 0.95em;
  line-height: 1.55;
}

/* AI-prompt collapse toggle — subordinate to content */
details.prompt-toggle {
  margin: 0.4em 0 0.9em;
}
details.prompt-toggle > summary {
  cursor: pointer;
  list-style: none;
  padding: 0.35em 0;
  font-size: 0.8em;
  color: var(--muted);
  font-weight: 500;
}
details.prompt-toggle > summary::-webkit-details-marker { display: none; }
details.prompt-toggle > summary::before { content: "▸ "; }
details.prompt-toggle[open] > summary::before { content: "▾ "; }

/* "PASTE THIS" dark surface */
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

/* Technical-details toggle inside a finding card */
details.tech-details {
  margin: 0.4em 0 0.9em;
}
details.tech-details > summary {
  cursor: pointer;
  list-style: none;
  padding: 0.3em 0;
  font-size: 0.8em;
  color: var(--muted);
  font-weight: 500;
}
details.tech-details > summary::-webkit-details-marker { display: none; }
details.tech-details > summary::before { content: "▸ "; }
details.tech-details[open] > summary::before { content: "▾ "; }
.meta-row {
  font-size: 0.85em;
  color: var(--muted);
  margin: 0.5em 0;
}
.meta-row strong { color: var(--text); font-weight: 600; }

/* Nested code-reveal toggle */
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

/* Group card */
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

/* Verdict hero banner */
.gate-hero {
  border-radius: 8px;
  padding: 1.6em 2em 1.4em;
  margin: 0 0 0.75em;
}
.gate-hero.blocked    { background: #fff1f0; border: 1.5px solid #ffa39e; }
.gate-hero.pass       { background: #f0fff4; border: 1.5px solid #95de64; }
.gate-hero.advisory   { background: #fffbeb; border: 1.5px solid #ffd666; }
.gate-hero.bypassed   { background: #f9f0ff; border: 1.5px solid #d3adf7; }
.gate-hero.scan_failed { background: #fff1f0; border: 1.5px solid #ffa39e; }
.gate-hero-verdict {
  font-size: 3em;
  font-weight: 700;
  letter-spacing: -0.03em;
  margin: 0 0 0.2em;
  line-height: 1.0;
}
.gate-hero.blocked .gate-hero-verdict    { color: #b94a4a; }
.gate-hero.pass .gate-hero-verdict       { color: #3f8a5a; }
.gate-hero.advisory .gate-hero-verdict   { color: #7c6b2a; }
.gate-hero.bypassed .gate-hero-verdict   { color: #7c3aed; }
.gate-hero.scan_failed .gate-hero-verdict { color: #b94a4a; }
.gate-hero-score-row {
  display: flex;
  align-items: baseline;
  gap: 0.7em;
  margin: 0 0 0.5em;
}
.gate-hero-score {
  font-size: 1.9em;
  font-weight: 700;
  letter-spacing: -0.02em;
  line-height: 1;
}
.gate-hero-score-label {
  font-size: 0.95em;
  font-weight: 600;
}
.gate-hero-counts {
  font-size: 1em;
  font-weight: 600;
  color: #444;
  margin: 0 0 0.35em;
}
.gate-hero-reason {
  font-size: 0.95em;
  color: #555;
  margin: 0 0 0.35em;
  line-height: 1.55;
}
.gate-hero-cause {
  font-size: 0.9em;
  color: #555;
  margin: 0 0 0.7em;
}
.gate-hero-cause strong { color: var(--text); }
.gate-top-risks { display: flex; flex-wrap: wrap; gap: 0.5em; margin-top: 0.25em; }
.top-risk-chip {
  display: inline-block;
  padding: 0.22em 0.7em;
  border-radius: 4px;
  font-size: 0.82em;
  font-weight: 600;
  background: rgba(185,74,74,0.1);
  color: #b94a4a;
  border: 1px solid rgba(185,74,74,0.25);
}

/* Repo context strip */
.repo-context {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5em;
  margin: 0 0 1.75em;
  font-size: 0.83em;
}
.repo-context-chip {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 0.2em 0.65em;
  color: var(--muted);
  font-weight: 500;
}
.repo-context-chip strong {
  color: var(--text);
  font-weight: 600;
}

/* Executive summary section */
.exec-summary {
  margin: 0 0 2em;
}
.exec-summary p {
  font-size: 1.05em;
  line-height: 1.75;
  max-width: 680px;
  margin: 0 0 0.75em;
  color: #333;
}
.exec-score-line {
  font-size: 1em;
  font-weight: 600;
  margin: 0 0 0.6em;
  color: var(--text);
}

/* Remediation complexity badge */
.remediation-complexity {
  display: inline-flex;
  align-items: center;
  gap: 0.45em;
  font-size: 0.9em;
  color: var(--muted);
  margin-top: 0.25em;
}
.complexity-badge {
  display: inline-block;
  padding: 0.15em 0.65em;
  border-radius: 4px;
  font-size: 0.9em;
  font-weight: 700;
  letter-spacing: 0.02em;
}
.complexity-low      { background: var(--low-tint);      color: var(--low); }
.complexity-medium   { background: var(--medium-tint);   color: var(--medium); }
.complexity-high     { background: var(--high-tint);     color: var(--high); }
.complexity-critical { background: var(--critical-tint); color: var(--critical); }

/* Fix First section */
.fix-first {
  margin: 0 0 2em;
}
.fix-first-list {
  list-style: none;
  margin: 0.75em 0 0;
  padding: 0;
}
.fix-first-list li {
  display: flex;
  align-items: baseline;
  gap: 0.9em;
  padding: 0.55em 0;
  border-bottom: 1px solid var(--border);
  font-size: 0.97em;
  text-decoration: none;
  color: inherit;
}
.fix-first-list li:last-child { border-bottom: none; }
.fix-first-list a {
  display: flex;
  align-items: baseline;
  gap: 0.9em;
  width: 100%;
  text-decoration: none;
  color: inherit;
}
.fix-first-list a:hover .fix-first-name { text-decoration: underline; }
.fix-first-num {
  font-size: 1em;
  font-weight: 700;
  color: var(--muted);
  min-width: 1.4em;
  flex-shrink: 0;
}
.fix-first-name {
  font-weight: 600;
  flex: 1;
}
.fix-first-loc {
  color: var(--muted);
  font-size: 0.88em;
  font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
}

/* Recommended actions section */
.recommended-actions {
  margin: 0 0 2em;
}
.recommended-actions ol {
  margin: 0.75em 0 0;
  padding-left: 1.6em;
}
.recommended-actions li {
  padding: 0.4em 0;
  line-height: 1.55;
  font-size: 0.97em;
}

/* Action callout — green "do this first" band */
.action-callout {
  background: #f0fff4;
  border-left: 3px solid #3f8a5a;
  padding: 0.65em 1em;
  border-radius: 0 6px 6px 0;
  margin: 0 0 1.5em;
  font-size: 0.95em;
  font-weight: 600;
  color: #2d6a4f;
}
.action-callout::before { content: "→ "; font-weight: 700; }

/* Print: expand every detail and drop interactive affordances. */
@media print {
  body { background: white; max-width: none; margin: 1em; }
  details.finding-block, details.code-toggle { break-inside: avoid; }
  details, details > * { display: block !important; }
  details > summary::before { content: ""; }
}
"""


# --- Risk score, executive summary, context strip, actions ----------------

_ACTION_BY_VULN_ID: dict[str, str] = {
    "SECRET-001": "Rotate all exposed credentials and audit secret storage",
    "A01:2021": "Restrict access controls and apply least-privilege principle",
    "A02:2021": "Update cryptographic algorithms to current standards",
    "A03:2021": "Parameterize all database queries and sanitize inputs",
    "A04:2021": "Remove hardcoded configuration and use secrets management",
    "A05:2021": "Patch or upgrade vulnerable dependencies",
    "A06:2021": "Update deprecated or vulnerable components",
    "A07:2021": "Harden authentication configuration and enforce MFA",
    "A08:2021": "Validate all deserialized input before processing",
    "A09:2021": "Enable security logging and set up alerting",
    "A10:2021": "Disable or restrict server-side request forgery entry points",
}


def _risk_score(findings: list[VulnerabilityFinding]) -> int:
    """Compute a 0–100 risk score. High score = high danger."""
    score = 0
    for f in findings:
        verified = f.verification_status == VerificationStatus.verified
        if f.severity == Severity.Critical:
            score += 18 if verified else 12
        elif f.severity == Severity.High:
            score += 8 if verified else 5
        elif f.severity == Severity.Medium:
            score += 3 if verified else 2
        else:
            score += 1
    return min(100, score)


def _risk_score_label(score: int) -> tuple[str, str]:
    """Return (label, css_class) for a risk score."""
    if score >= 81:
        return ("Critical Risk", "var(--critical)")
    if score >= 51:
        return ("High Risk", "var(--high)")
    if score >= 21:
        return ("Medium Risk", "var(--medium)")
    return ("Low Risk", "var(--low)")


def _remediation_complexity(
    findings: list[VulnerabilityFinding],
) -> tuple[str, str]:
    """Return (label, css_suffix) for remediation complexity."""
    crit_verified = sum(
        1
        for f in findings
        if f.severity == Severity.Critical
        and f.verification_status == VerificationStatus.verified
    )
    high_verified = sum(
        1
        for f in findings
        if f.severity == Severity.High
        and f.verification_status == VerificationStatus.verified
    )
    if crit_verified >= 3:
        return ("Critical", "critical")
    if crit_verified >= 1 or high_verified >= 3:
        return ("High", "high")
    if high_verified >= 1:
        return ("Medium", "medium")
    return ("Low", "low")


def _repo_context_row(result: ScanResult) -> str:
    """Compact context strip: repo name, scan type, actor, date."""
    # Extract the last two path segments of the repo URL as the repo name.
    repo_name = result.repo_url.rstrip("/").rsplit("/", 2)
    repo_display = "/".join(repo_name[-2:]) if len(repo_name) >= 2 else repo_name[-1]

    chips = [
        f'<span class="repo-context-chip"><strong>{escape(repo_display)}</strong></span>',
        f'<span class="repo-context-chip">{escape(result.scan_type.value)}</span>',
        f'<span class="repo-context-chip">{escape(result.triggered_by)}</span>',
        f'<span class="repo-context-chip">'
        f'{escape(result.timestamp.strftime("%Y-%m-%d %H:%M UTC"))}'
        f"</span>",
    ]
    return f'<div class="repo-context">{"".join(chips)}</div>'


def _executive_summary_section(result: ScanResult, risk_score: int) -> str:
    """Template-generate a plain-English executive summary from findings data."""
    findings = result.findings
    if not findings:
        score_label, score_colour = _risk_score_label(0)
        return (
            '<section class="exec-summary">'
            '<p class="exec-score-line">'
            f'Risk Score: <span style="color:{score_colour}">0</span>'
            f' — <span style="color:{score_colour}">{escape(score_label)}</span>'
            "</p>"
            "<p>No security findings were identified in this scan. "
            "The repository appears clean and deployment may proceed.</p>"
            "</section>"
        )

    score_label, score_colour = _risk_score_label(risk_score)

    crit_verified = [
        f
        for f in findings
        if f.severity == Severity.Critical
        and f.verification_status == VerificationStatus.verified
    ]
    high_verified = [
        f
        for f in findings
        if f.severity == Severity.High
        and f.verification_status == VerificationStatus.verified
    ]
    total_blocking = len(crit_verified) + len(high_verified)

    type_counts = Counter(
        vuln_display_name(f.vulnerability_id) or f.vulnerability_id
        for f in findings
        if f.severity in (Severity.Critical, Severity.High)
    )
    top_two = [name for name, _ in type_counts.most_common(2)]

    # Sentence 1: what was found
    if total_blocking:
        count_word = str(total_blocking)
        issues_word = "issue" if total_blocking == 1 else "issues"
        sentence1 = (
            f"{count_word} verified critical or high-severity {issues_word} "
            "were identified in this repository."
        )
    else:
        crit_count = sum(1 for f in findings if f.severity == Severity.Critical)
        high_count = sum(1 for f in findings if f.severity == Severity.High)
        if crit_count or high_count:
            sentence1 = (
                f"{crit_count + high_count} critical or high-severity findings "
                "were detected, though none have been verified."
            )
        else:
            sentence1 = (
                f"{len(findings)} finding{'s' if len(findings) != 1 else ''} "
                "were identified, all medium severity or below."
            )

    # Sentence 2: most common types
    if top_two:
        types_str = " and ".join(escape(t) for t in top_two)
        sentence2 = f"Most issues originate from {types_str}."
    else:
        sentence2 = ""

    complexity_label, complexity_css = _remediation_complexity(findings)

    score_html = (
        '<p class="exec-score-line">'
        f'Risk Score: <span style="color:{score_colour};font-weight:700">{risk_score}</span>'
        f' — <span style="color:{score_colour}">{escape(score_label)}</span>'
        "</p>"
    )
    p1 = f"<p>{escape(sentence1)}{(' ' + sentence2) if sentence2 else ''}</p>"
    complexity_html = (
        '<div class="remediation-complexity">'
        "Remediation Complexity: "
        f'<span class="complexity-badge complexity-{complexity_css}">'
        f"{escape(complexity_label)}"
        "</span>"
        "</div>"
    )
    return (
        '<section class="exec-summary">'
        f"{score_html}"
        f"{p1}"
        f"{complexity_html}"
        "</section>"
    )


def _fix_first_section(findings: list[VulnerabilityFinding]) -> str:
    """Top 3 critical/high findings as a prioritised action list."""
    top = [f for f in findings if f.severity in (Severity.Critical, Severity.High)][:3]
    if not top:
        return ""

    items_html = []
    for i, f in enumerate(findings, start=1):
        if f not in top:
            continue
        idx = findings.index(f) + 1
        name = escape(vuln_display_name(f.vulnerability_id) or f.vulnerability_id)
        loc = f.affected_file
        if f.affected_lines:
            loc = f"{loc}:{f.affected_lines}"
        items_html.append(
            f'<li><a href="#finding-{idx}">'
            f'<span class="fix-first-num">{top.index(f) + 1}</span>'
            f'<span class="fix-first-name">{name}</span>'
            f'<span class="fix-first-loc">{escape(loc)}</span>'
            "</a></li>"
        )

    list_html = f'<ol class="fix-first-list">{"".join(items_html)}</ol>'
    return (
        '<section class="fix-first">'
        "<h2>Fix First</h2>"
        f"{list_html}"
        "</section>"
    )


def _recommended_actions_section(findings: list[VulnerabilityFinding]) -> str:
    """Top 3 unique recommended actions derived from vulnerability category."""
    if not findings:
        return ""

    priority_order = [Severity.Critical, Severity.High, Severity.Medium, Severity.Low]
    sorted_findings = sorted(
        findings,
        key=lambda f: (
            priority_order.index(f.severity),
            0 if f.verification_status == VerificationStatus.verified else 1,
        ),
    )

    seen_actions: list[str] = []
    seen_vuln_ids: set[str] = set()
    for f in sorted_findings:
        if len(seen_actions) >= 3:
            break
        # Look up a clean action by vuln_id prefix or exact match.
        action = _ACTION_BY_VULN_ID.get(f.vulnerability_id)
        if action is None:
            # Try prefix match (e.g. "A03" matches "A03:2021")
            for key, val in _ACTION_BY_VULN_ID.items():
                if f.vulnerability_id.startswith(key[:3]):
                    action = val
                    break
        if action is None:
            # Fall back to first sentence of suggested_fix, capitalised
            raw = (f.suggested_fix or "").strip().split(".")[0].strip()
            if raw:
                action = raw[0].upper() + raw[1:]
        if action and action not in seen_actions and f.vulnerability_id not in seen_vuln_ids:
            seen_actions.append(action)
            seen_vuln_ids.add(f.vulnerability_id)

    if not seen_actions:
        return ""

    items_html = "".join(f"<li>{escape(a)}</li>" for a in seen_actions)
    return (
        '<section class="recommended-actions">'
        "<h2>Recommended Actions</h2>"
        f"<ol>{items_html}</ol>"
        "</section>"
    )


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
    report_title = (
        "Deployment Risk Assessment"
        if result.scan_type == ScanType.deployment_gate
        else "Repository Security Assessment"
    )

    risk_score = _risk_score(result.findings) if result.findings else 0

    sections: list[str] = []

    if result.scan_type == ScanType.deployment_gate:
        sections.append(
            _gate_decision_section(result.gate_decision, result.findings, risk_score)
        )

    sections.append(_repo_context_row(result))
    sections.append(_executive_summary_section(result, risk_score))

    if result.findings:
        sections.append(_summary_bar(result.findings))

    fix_first = _fix_first_section(result.findings)
    if fix_first:
        sections.append(fix_first)

    if result.scan_type == ScanType.deployment_gate and result.findings:
        callout = _action_callout(result.gate_decision, result.findings)
        if callout:
            sections.append(callout)

    rec_actions = _recommended_actions_section(result.findings)
    if rec_actions:
        sections.append(rec_actions)

    warnings = _gather_warnings(result)
    if warnings:
        sections.append(_warnings_section(warnings))

    if result.findings:
        sections.append(_detailed_findings(result.findings, files))

    sections.append(_metadata_section(result))
    sections.append(_footer(result.findings_count))

    body = "\n".join(sections)
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        f"<title>{escape(report_title)}</title>\n"
        '<link rel="preconnect" href="https://fonts.googleapis.com">\n'
        '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>\n'
        f"<style>{_STYLE}</style>\n"
        "</head>\n"
        "<body>\n"
        f"{_BRAND_HEADER}\n"
        f"<h1>{escape(report_title)}</h1>\n"
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
    inner = f'<section class="metadata" style="margin-top:0.75em;">\n<dl>\n{items}\n</dl>\n</section>'
    return (
        '<details style="margin:2.5em 0 1em;">'
        '<summary style="cursor:pointer;list-style:none;font-size:0.88em;font-weight:600;'
        'color:var(--muted);padding:0.5em 0;border-top:1px solid var(--border);">'
        "▸ Scan metadata</summary>"
        f"{inner}"
        "</details>"
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


def _gate_decision_section(
    decision: GateDecision,
    findings: list[VulnerabilityFinding],
    risk_score: int,
) -> str:
    c = sum(1 for f in findings if f.severity == Severity.Critical)
    h = sum(1 for f in findings if f.severity == Severity.High)
    m = sum(1 for f in findings if f.severity == Severity.Medium)
    low = sum(1 for f in findings if f.severity == Severity.Low)

    count_parts: list[str] = []
    if c:
        count_parts.append(f"{c} Critical")
    if h:
        count_parts.append(f"{h} High")
    if m:
        count_parts.append(f"{m} Medium")
    if low:
        count_parts.append(f"{low} Low")
    counts_html = " · ".join(escape(p) for p in count_parts) if count_parts else "No findings"

    _REASONS: dict[GateDecision, str] = {
        GateDecision.blocked: (
            "Deployment blocked due to verified critical findings that could expose "
            "sensitive data or allow unauthorized access."
        ),
        GateDecision.pass_: "No blocking issues found. Safe to deploy.",
        GateDecision.advisory: (
            "Deployment can proceed with caution. Non-blocking issues were found — "
            "review and schedule fixes before the next sprint."
        ),
        GateDecision.bypassed: (
            "Gate bypassed. Issues were acknowledged and the override is recorded for audit."
        ),
        GateDecision.scan_failed: "Scan encountered an error and could not reach a gate decision.",
    }
    reason = _REASONS.get(decision, "Gate decision: " + decision.value)

    # Most likely cause: most-frequent vulnerability type among Critical/High findings.
    cause_html = ""
    top_type_counts = Counter(
        vuln_display_name(f.vulnerability_id) or f.vulnerability_id
        for f in findings
        if f.severity in (Severity.Critical, Severity.High)
    )
    if top_type_counts:
        top_type = top_type_counts.most_common(1)[0][0]
        cause_html = (
            f'<div class="gate-hero-cause">'
            f"<strong>Most likely cause:</strong> {escape(top_type)}"
            f"</div>"
        )

    top_findings = [f for f in findings if f.severity in (Severity.Critical, Severity.High)][:3]
    chips_html = ""
    if top_findings:
        chips = "".join(
            f'<span class="top-risk-chip">'
            f"{escape(vuln_display_name(f.vulnerability_id) or f.vulnerability_id)}"
            f"</span>"
            for f in top_findings
        )
        chips_html = f'<div class="gate-top-risks">{chips}</div>'

    score_label, score_colour = _risk_score_label(risk_score)
    score_row_html = (
        f'<div class="gate-hero-score-row">'
        f'<span class="gate-hero-score" style="color:{score_colour}">{risk_score}</span>'
        f'<span class="gate-hero-score-label" style="color:{score_colour}">'
        f"Risk Score — {escape(score_label)}"
        f"</span>"
        f"</div>"
    )

    css_cls = decision.value

    return (
        f'<div class="gate-hero {css_cls}">\n'
        f'<div class="gate-hero-verdict">{escape(decision.value.upper())}</div>\n'
        f"{score_row_html}\n"
        f'<div class="gate-hero-counts">{counts_html}</div>\n'
        f'<div class="gate-hero-reason">{escape(reason)}</div>\n'
        f"{cause_html}\n"
        f"{chips_html}\n"
        f"</div>"
    )


def _action_callout(decision: GateDecision, findings: list[VulnerabilityFinding]) -> str:
    top = next(
        (f for f in findings if f.severity in (Severity.Critical, Severity.High)),
        findings[0] if findings else None,
    )
    if top is None:
        return ""
    top_file = top.affected_file.split("/")[-1]
    name = vuln_display_name(top.vulnerability_id) or top.vulnerability_id
    if decision == GateDecision.blocked:
        text = f"Fix {escape(name)} in {escape(top_file)} before deploying."
    elif decision == GateDecision.advisory:
        text = f"Review {escape(name)} in {escape(top_file)} — advisory findings detected."
    else:
        return ""
    return f'<div class="action-callout">{text}</div>'


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

    parts: list[str] = ["<section>\n<h2>Finding Details</h2>"]

    if urgent:
        parts.append(
            _render_bucket(
                "Urgent Findings",
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
                "High Priority Findings",
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
                "Additional Findings",
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
    name = vuln_display_name(f.vulnerability_id)
    name_suffix = f" · {escape(name)}" if name else ""
    parts: list[str] = [
        f'<details id="finding-{idx}" class="finding-block {sev_class}"{open_attr}>',
        "<summary>",
        _severity_span(f.severity),
        f"<span>{escape(f.vulnerability_id)}{name_suffix} — {location}</span>",
        badge,
    ]
    if f.verification_status == VerificationStatus.advisory_real:
        parts.append(_advisory_real_badge())
    parts += [
        "</summary>",
        # What is wrong?
        f"<p>{escape(f.description)}</p>",
        # Why does it matter? — italic, no box
        f'<p class="finding-impact"><em>{escape(f.exploit_scenario)}</em></p>',
        # What should I do? — plain text, always visible
        f'<p class="finding-fix"><strong>Fix:</strong> {escape(f.suggested_fix)}</p>',
    ]
    # Collapsed: code snippet
    snippet = _code_snippet_block(files, f.affected_file, f.affected_lines)
    if snippet:
        parts.append(snippet)
    # Collapsed: upload or cross-file context
    upload_panel = _upload_context_panel(f.context_summary)
    if upload_panel:
        parts.append(upload_panel)
    elif f.context_summary:
        parts.append(
            '<details class="code-toggle">'
            "<summary>Cross-file context</summary>"
            f'<pre style="white-space:pre-wrap;font-size:0.85em">'
            f"{escape(f.context_summary)}</pre>"
            "</details>"
        )
    # Collapsed: AI fix prompt
    parts.append(
        _ai_prompt_block(_synthesize_ai_prompt(f), header="AI fix prompt")
    )
    # Collapsed: technical metadata
    parts.append(
        '<details class="tech-details">'
        "<summary>Technical details</summary>"
        + _card_meta_row(f)
        + "</details>"
    )
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
    name = vuln_display_name(head.vulnerability_id)
    name_suffix = f" · {escape(name)}" if name else ""
    parts: list[str] = [
        f'<details id="finding-{first_idx}" class="finding-block {sev_class}">',
        "<summary>",
        _severity_span(head.severity),
        f"<span>All {len(items)} are one problem — "
        f"{escape(head.vulnerability_id)}{name_suffix}</span>",
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
        '<details class="prompt-toggle">'
        f'<summary>→ {escape(header)}</summary>'
        '<div class="ai-prompt">'
        f"{escape(prompt_text)}"
        "</div>"
        "</details>"
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
