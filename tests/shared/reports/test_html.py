"""Tests for the HTML report generator (§2.2 step 6, §6.1, §6.2, BR-008)."""

from datetime import UTC, datetime
from uuid import UUID

from security_scanner.shared.models.enums import (
    Confidence,
    GateDecision,
    ScanTarget,
    ScanType,
    Severity,
    VerificationStatus,
)
from security_scanner.shared.models.finding import VulnerabilityFinding
from security_scanner.shared.models.scan_result import ScanResult
from security_scanner.shared.reports.html import build_html_report


def _finding(
    *,
    severity: Severity = Severity.High,
    confidence: Confidence = Confidence.High,
    verification_status: VerificationStatus = VerificationStatus.unverified,
    affected_file: str = "src/app.py",
    vulnerability_id: str = "A03:2021",
) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        vulnerability_id=vulnerability_id,
        severity=severity,
        confidence=confidence,
        cvss_band={
            Severity.Critical: "9.0–10.0",
            Severity.High: "7.0–8.9",
            Severity.Medium: "4.0–6.9",
            Severity.Low: "0.1–3.9",
        }[severity],
        affected_file=affected_file,
        affected_lines="42-55",
        description="SQL injection in login.",
        suggested_fix="Use a parameterised query.",
        owasp_reference="https://owasp.org/Top10/A03_2021-Injection/",
        patch_file_path="patches/A03-2021.patch",
        exploit_scenario=f"Attacker sends a payload to {affected_file}.",
        verification_status=verification_status,
    )


def _result(
    *,
    findings: list[VulnerabilityFinding] | None = None,
    scan_type: ScanType = ScanType.deployment_gate,
    gate_decision: GateDecision = GateDecision.advisory,
    partial_scan: bool = False,
    unscanned_files: list[str] | None = None,
) -> ScanResult:
    fs = findings or []
    return ScanResult(
        scan_id=UUID("12345678-1234-5678-1234-567812345678"),
        repo_url="https://github.com/Phrase-Launchpad/example",
        scan_target=ScanTarget.full_repo,
        scan_type=scan_type,
        triggered_by="alice@phrase.com",
        timestamp=datetime(2026, 5, 18, 12, 0, 0, tzinfo=UTC),
        findings_count=len(fs),
        gate_decision=gate_decision,
        partial_scan=partial_scan,
        unscanned_files=unscanned_files or [],
        findings=fs,
    )


# --- Document structure -----------------------------------------------------


def test_report_is_self_contained_html_document():
    html = build_html_report(_result())
    assert html.startswith("<!DOCTYPE html>")
    # Title is dynamic based on scan type.
    assert "<title>Deployment Risk Assessment</title>" in html
    # CSS is inlined; only font preconnect <link> tags are present (no stylesheets).
    assert "<style>" in html
    assert 'rel="stylesheet"' not in html


def test_report_contains_h1_header():
    assert "<h1>Deployment Risk Assessment</h1>" in build_html_report(_result())


def test_on_demand_report_title():
    html = build_html_report(_result(scan_type=ScanType.on_demand))
    assert "<title>Repository Security Assessment</title>" in html
    assert "<h1>Repository Security Assessment</h1>" in html


def test_metadata_section_includes_all_fields():
    html = build_html_report(_result())
    assert "12345678-1234-5678-1234-567812345678" in html
    assert "https://github.com/Phrase-Launchpad/example" in html
    assert "2026-05-18T12:00:00+00:00" in html
    assert "deployment_gate" in html
    assert "alice@phrase.com" in html


def test_gate_decision_omitted_for_skill_scans():
    html = build_html_report(_result(scan_type=ScanType.on_demand))
    assert "Gate decision" not in html


def test_gate_decision_shown_with_label_for_gate_scans():
    html = build_html_report(_result(gate_decision=GateDecision.blocked))
    # Gate hero banner shows the verdict in uppercase; no longer uses "Gate decision" heading.
    assert "BLOCKED" in html
    assert "gate-hero" in html
    assert "blocked" in html


# --- Severity colour coding (the user's explicit requirement) --------------


def test_critical_severity_uses_severity_class():
    # Colour palette is tunable via CSS variables; the contract we pin is
    # that each severity carries the corresponding ``severity-<level>``
    # class so the styling is reachable from CSS.
    finding = _finding(severity=Severity.Critical)
    html = build_html_report(_result(findings=[finding]))
    assert "severity-critical" in html


def test_high_severity_uses_severity_class():
    finding = _finding(severity=Severity.High)
    html = build_html_report(_result(findings=[finding]))
    assert "severity-high" in html


def test_medium_severity_uses_severity_class():
    finding = _finding(severity=Severity.Medium)
    html = build_html_report(_result(findings=[finding]))
    assert "severity-medium" in html


def test_low_severity_uses_severity_class():
    finding = _finding(severity=Severity.Low)
    html = build_html_report(_result(findings=[finding]))
    assert "severity-low" in html


# --- Warning rendering (the four required cases) ---------------------------


def test_partial_scan_warning_appears_with_file_list():
    result = _result(
        partial_scan=True,
        unscanned_files=["src/a.py", "src/b.py"],
        findings=[_finding()],
    )
    html = build_html_report(result)
    assert "PARTIAL SCAN" in html
    assert "src/a.py" in html
    assert "src/b.py" in html


def test_conflicting_warning_appears_for_critical_conflicting_finding():
    finding = _finding(
        severity=Severity.Critical,
        confidence=Confidence.High,
        verification_status=VerificationStatus.conflicting,
    )
    html = build_html_report(_result(findings=[finding]))
    assert "CONFLICTING FINDINGS" in html
    assert "1 Critical findings were not confirmed" in html


def test_advisory_warning_appears_for_high_critical_with_medium_low_confidence():
    findings = [_finding(severity=Severity.High, confidence=Confidence.Medium)]
    html = build_html_report(_result(findings=findings))
    assert "ADVISORY" in html
    assert "1 findings are High/Critical severity" in html


def test_empty_findings_warning_appears_when_findings_list_is_empty():
    html = build_html_report(_result(findings=[]))
    assert "NO FINDINGS DETECTED" in html
    assert "acknowledgement required" in html


def test_no_warnings_section_when_clean_finding():
    findings = [
        _finding(
            severity=Severity.Critical,
            confidence=Confidence.High,
            verification_status=VerificationStatus.verified,
        ),
    ]
    html = build_html_report(_result(findings=findings))
    assert "<h2>Warnings</h2>" not in html


# --- XSS hygiene -----------------------------------------------------------


def test_html_special_chars_in_user_fields_are_escaped():
    finding = _finding(
        affected_file="src/<script>alert(1)</script>.py",
    )
    html = build_html_report(_result(findings=[finding]))
    # The dangerous tag must not appear unescaped.
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_owasp_reference_url_renders_as_anchor():
    finding = _finding()
    html = build_html_report(_result(findings=[finding]))
    assert 'href="https://owasp.org/Top10/A03_2021-Injection/"' in html


# --- Finding detail rendering ---------------------------------------------


def test_detail_section_contains_description_exploit_and_fix():
    finding = _finding()
    html = build_html_report(_result(findings=[finding]))
    assert "Finding Details" in html
    assert finding.description in html
    assert finding.exploit_scenario in html
    assert finding.suggested_fix in html
    assert finding.patch_file_path in html


def test_findings_cards_present_when_findings_exist():
    html = build_html_report(_result(findings=[_finding()]))
    assert 'class="finding-block' in html
    assert 'id="finding-1"' in html


# --- New visual / structural contracts (UX polish pass) ---------------------


def test_summary_bar_renders_severity_counts():
    findings = [
        _finding(severity=Severity.Critical),
        _finding(severity=Severity.Critical),
        _finding(severity=Severity.High),
        _finding(severity=Severity.Medium),
    ]
    html = build_html_report(_result(findings=findings))
    assert 'class="summary-bar"' in html
    # Each severity pill carries its count + label so a quick scan triages.
    for sev_class in ("critical", "high", "medium", "low"):
        assert f"summary-pill {sev_class}" in html


def test_finding_detail_is_collapsible_details_element():
    findings = [
        _finding(severity=Severity.Critical),
        _finding(severity=Severity.Medium),
    ]
    html = build_html_report(_result(findings=findings))
    # Critical auto-opens; Medium collapses by default.
    assert "<details" in html
    assert 'class="finding-block sev-critical" open' in html
    assert 'class="finding-block sev-medium"' in html
    assert 'class="finding-block sev-medium" open' not in html


def test_findings_table_id_column_links_to_detail_anchor():
    findings = [_finding(vulnerability_id="A03:2021"), _finding(vulnerability_id="A02:2021")]
    html = build_html_report(_result(findings=findings))
    # First row → #finding-1, second → #finding-2.
    assert 'href="#finding-1"' in html
    assert 'href="#finding-2"' in html
    assert 'id="finding-1"' in html
    assert 'id="finding-2"' in html


def test_print_stylesheet_expands_details():
    html = build_html_report(_result(findings=[_finding()]))
    assert "@media print" in html
    # The print rule must force collapsed <details> open.
    assert "details.finding-block" in html


def test_html_report_has_no_finding_id_gaps_vs_markdown():
    """Parity check: every finding ID in the markdown report appears in HTML."""
    from security_scanner.shared.reports.markdown import build_markdown_report

    findings = [
        _finding(vulnerability_id="SECRET-001", severity=Severity.Critical),
        _finding(vulnerability_id="A03:2021", severity=Severity.High),
        _finding(vulnerability_id="A02:2021", severity=Severity.Medium),
    ]
    result = _result(findings=findings)
    md = build_markdown_report(result)
    html = build_html_report(result)
    for f in findings:
        assert f.vulnerability_id in md
        assert f.vulnerability_id in html


# --- Severity buckets, grouping, paste-prompt, edition footnote ------------


def test_findings_split_into_urgent_cleanup_advisory_buckets():
    findings = [
        _finding(severity=Severity.Critical, vulnerability_id="A03:2021"),
        _finding(severity=Severity.High, vulnerability_id="A01:2021"),
        _finding(severity=Severity.Medium, vulnerability_id="A05:2021"),
        _finding(severity=Severity.Low, vulnerability_id="A09:2021"),
    ]
    html = build_html_report(_result(findings=findings))
    assert "bucket-urgent" in html
    assert "bucket-cleanup" in html
    assert "bucket-advisory" in html
    # Each bucket header carries its bucket count.
    assert "Urgent Findings (2)" in html
    assert "High Priority Findings (1)" in html
    assert "Additional Findings (1)" in html


def test_groups_findings_sharing_vulnerability_id_and_severity():
    # Three Medium SECRET-001 findings in different files collapse into one
    # group card with a combined fix-all-at-once prompt.
    findings = [
        _finding(severity=Severity.Medium, vulnerability_id="SECRET-001", affected_file="src/a.py"),
        _finding(severity=Severity.Medium, vulnerability_id="SECRET-001", affected_file="src/b.py"),
        _finding(severity=Severity.Medium, vulnerability_id="SECRET-001", affected_file="src/c.py"),
    ]
    html = build_html_report(_result(findings=findings))
    assert "All 3 are one problem" in html
    assert "Fix all 3 at once" in html
    # Each individual location still anchors to its row index.
    assert 'id="finding-1"' in html
    assert 'id="finding-2"' in html
    assert 'id="finding-3"' in html
    # Combined prompt enumerates every location.
    assert "src/a.py" in html and "src/b.py" in html and "src/c.py" in html


def test_single_medium_finding_renders_as_individual_card_not_group():
    findings = [_finding(severity=Severity.Medium, vulnerability_id="A05:2021")]
    html = build_html_report(_result(findings=findings))
    assert "are one problem" not in html
    assert "Fix all" not in html


def test_ai_prompt_block_appears_in_every_finding_card():
    findings = [
        _finding(severity=Severity.Critical, vulnerability_id="A03:2021"),
        _finding(severity=Severity.Medium, vulnerability_id="A05:2021"),
    ]
    html = build_html_report(_result(findings=findings))
    # The dark "paste this" block is rendered with a class hook so tests
    # (and future polish) can pin it.
    assert html.count('class="ai-prompt"') >= 2
    assert "→ AI fix prompt" in html


def test_ai_prompt_text_includes_file_path_and_suggested_fix_phrase():
    f = _finding(
        severity=Severity.Critical,
        vulnerability_id="A03:2021",
        affected_file="src/login.py",
    )
    html = build_html_report(_result(findings=[f]))
    # The synthesized prompt mentions where to fix and what to do.
    assert "src/login.py" in html
    assert "Use a parameterised query" in html
    assert "Then show me the change." in html


def test_owasp_edition_footnote_rendered_for_known_2021_ids():
    # A03:2021 has a known 2025 cross-reference; the footnote appears.
    f = _finding(vulnerability_id="A03:2021", severity=Severity.Critical)
    html = build_html_report(_result(findings=[f]))
    assert "A05:2025" in html


def test_owasp_edition_footnote_absent_for_ids_without_known_movement():
    f = _finding(vulnerability_id="A04:2021", severity=Severity.Critical)
    html = build_html_report(_result(findings=[f]))
    assert "A05:2025" not in html  # nothing leaks in for unmapped IDs


def test_quick_fix_badge_heuristic_one_line_fix():
    f = _finding(severity=Severity.Critical)
    f = f.model_copy(update={"suggested_fix": "Use parameterised queries."})
    html = build_html_report(_result(findings=[f]))
    assert "1-line fix" in html


def test_quick_fix_badge_heuristic_quick_fix_for_short_multiline():
    f = _finding(severity=Severity.Critical)
    f = f.model_copy(
        update={
            "suggested_fix": "Step one.\nStep two.\nStep three.",
        }
    )
    html = build_html_report(_result(findings=[f]))
    assert "quick fix" in html
    assert "1-line fix" not in html


def test_no_badge_for_long_suggested_fix():
    f = _finding(severity=Severity.Critical)
    f = f.model_copy(
        update={
            "suggested_fix": "\n".join(f"step {i}" for i in range(1, 10)),
        }
    )
    html = build_html_report(_result(findings=[f]))
    # Neither badge label is emitted (the CSS class definition for .fix-badge
    # remains in the inlined stylesheet, so pin the label text instead).
    assert "1-line fix" not in html
    assert "quick fix" not in html


# --- Vulnerable-code snippet toggle ---------------------------------------


def test_code_snippet_toggle_rendered_when_files_provided():
    f = _finding(severity=Severity.Critical, affected_file="src/db.py")
    f = f.model_copy(update={"affected_lines": "3"})
    files = {
        "src/db.py": ("line one\nline two\nVULNERABLE_LINE = 'secret'\nline four\nline five\n"),
    }
    html = build_html_report(_result(findings=[f]), files=files)
    assert "Show vulnerable code (lines 3)" in html
    assert "VULNERABLE_LINE = &#x27;secret&#x27;" in html
    # The snippet sits inside a collapsed <details>, not open by default.
    assert 'class="code-toggle"' in html
    assert 'class="code-toggle" open' not in html


def test_code_snippet_toggle_omitted_when_files_not_provided():
    f = _finding(severity=Severity.Critical, affected_file="src/db.py")
    html = build_html_report(_result(findings=[f]))
    assert "Show vulnerable code" not in html
    # No actual element carries the code-toggle class (CSS def itself does,
    # so pin the element usage instead of the raw substring).
    assert 'class="code-toggle"' not in html


def test_code_snippet_toggle_omitted_when_file_absent_from_dict():
    f = _finding(severity=Severity.Critical, affected_file="src/db.py")
    html = build_html_report(_result(findings=[f]), files={"other.py": "x"})
    assert "Show vulnerable code" not in html
    assert 'class="code-toggle"' not in html


def test_code_snippet_handles_range_lines_with_context_padding():
    f = _finding(severity=Severity.Critical, affected_file="x.py")
    f = f.model_copy(update={"affected_lines": "5-6"})
    files = {"x.py": "\n".join(f"row{i}" for i in range(1, 11))}
    html = build_html_report(_result(findings=[f]), files=files)
    # The snippet widens by 2 lines either side: rows 3..8 inclusive.
    for n in (3, 4, 5, 6, 7, 8):
        assert f">{n}</span>" in html or f">{n} </span>" in html
    # Rows outside the padded window are not included.
    assert "row1" not in html
    assert "row10" not in html


def test_code_snippet_omitted_when_lines_unparseable():
    f = _finding(severity=Severity.Critical, affected_file="x.py")
    f = f.model_copy(update={"affected_lines": "not-a-number"})
    files = {"x.py": "a\nb\nc\n"}
    html = build_html_report(_result(findings=[f]), files=files)
    assert "Show vulnerable code" not in html


# --- v2: advisory_real badge and context_summary --------------------------


def test_advisory_real_badge_in_finding_card():
    """advisory_real findings carry the auto-triaged badge text."""
    f = _finding(verification_status=VerificationStatus.advisory_real)
    html = build_html_report(_result(findings=[f]))
    assert "Potential issue (auto-triaged, not blocking)" in html


def test_advisory_real_warning_in_header():
    """A header warning is emitted when advisory_real findings are present."""
    f = _finding(verification_status=VerificationStatus.advisory_real)
    html = build_html_report(_result(findings=[f]))
    assert "AUTO-TRIAGED" in html


def test_non_advisory_real_has_no_badge():
    """verified findings must NOT carry the auto-triaged badge."""
    f = _finding(verification_status=VerificationStatus.verified)
    html = build_html_report(_result(findings=[f]))
    assert "Potential issue (auto-triaged, not blocking)" not in html


def test_context_summary_renders_in_card_when_present():
    """Finding with context_summary shows a cross-file context detail block."""
    f = _finding()
    f = f.model_copy(update={"context_summary": "ROUTES: GET /docs → get_doc"})
    html = build_html_report(_result(findings=[f]))
    assert "Cross-file context" in html
    assert "ROUTES: GET /docs" in html


def test_context_summary_absent_when_empty():
    """When context_summary is empty, no context block is rendered."""
    f = _finding()
    html = build_html_report(_result(findings=[f]))
    assert "Cross-file context" not in html


# --- v3: upload context panel -------------------------------------------------


def test_upload_context_panel_rendered_for_upload_findings():
    """A finding with an upload context_summary renders the Upload context panel."""
    f = _finding()
    upload_summary = (
        "Validation: none — Naming: preserved-user-filename — "
        "Storage: public-path — Limits: none — Access: none — "
        "Processing: archive-extract"
    )
    f = f.model_copy(update={"context_summary": upload_summary})
    html = build_html_report(_result(findings=[f]))
    assert "Upload context" in html
    assert "Validation:" in html
    assert "archive-extract" in html


def test_upload_context_panel_shows_all_fields():
    """All 6 field labels appear in the upload context panel."""
    f = _finding()
    upload_summary = (
        "Validation: extension-allowlist — Naming: server-generated — "
        "Storage: outside-webroot — Limits: yes — Access: yes — "
        "Processing: none"
    )
    f = f.model_copy(update={"context_summary": upload_summary})
    html = build_html_report(_result(findings=[f]))
    for label in ("Validation:", "Naming:", "Storage:", "Limits:", "Access:", "Processing:"):
        assert label in html, f"Missing label {label!r} in upload context panel"


def test_non_upload_context_summary_renders_cross_file_toggle():
    """Non-upload context_summary still renders as Cross-file context."""
    f = _finding()
    f = f.model_copy(update={"context_summary": "ROUTES: GET /docs → get_doc"})
    html = build_html_report(_result(findings=[f]))
    assert "Cross-file context" in html
    assert "Upload context" not in html


def test_upload_panel_xss_safe():
    """Attacker-controlled strings in context_summary are HTML-escaped."""
    f = _finding()
    upload_summary = (
        "Validation: <script>alert(1)</script> — Naming: server-generated — "
        "Storage: outside-webroot — Limits: yes — Access: yes — Processing: none"
    )
    f = f.model_copy(update={"context_summary": upload_summary})
    html = build_html_report(_result(findings=[f]))
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_detected_by_renders_for_single_voter_claude_finding():
    """Fix #5: a Claude-only finding (sources=['claude']) must show Detected By: claude."""
    f = _finding(verification_status=VerificationStatus.verified)
    f = f.model_copy(update={"sources": ["claude"], "consensus_score": 1})
    html = build_html_report(_result(findings=[f]))
    assert "Detected By" in html
    assert "claude" in html


def test_detected_by_renders_for_multi_voter_finding():
    """Fix #5 regression: multi-voter findings still show Detected By with engine count."""
    f = _finding(verification_status=VerificationStatus.verified)
    f = f.model_copy(update={"sources": ["claude", "bandit"], "consensus_score": 2})
    html = build_html_report(_result(findings=[f]))
    assert "Detected By" in html
    assert "claude" in html
    assert "bandit" in html
    assert "2 engines" in html


def test_detected_by_absent_when_sources_empty():
    """A finding with no sources must NOT emit a Detected by: line."""
    f = _finding(verification_status=VerificationStatus.unverified)
    f = f.model_copy(update={"sources": [], "consensus_score": 0})
    html = build_html_report(_result(findings=[f]))
    assert "Detected by:" not in html


def test_upload_context_panel_rendered_on_non_gate_scan():
    """Upload-context panel must appear in on_demand (non-gate) renders.

    Fix #3 regression guard: the panel is gated only on whether
    context_summary is populated, NOT on the scan type.  Previously the
    pipeline skipped context packaging for on_demand scans so context_summary
    was always empty — now the packager runs on both paths.
    """
    from security_scanner.shared.models.enums import ScanType

    f = _finding()
    upload_summary = (
        "Validation: extension allowlist (weak) — Naming: preserves user filename — "
        "Storage: public path — Limits: none — Access: none — Processing: none"
    )
    f = f.model_copy(update={"context_summary": upload_summary})
    # Use on_demand scan type (the /scan/local path) — not deployment_gate.
    result = _result(
        findings=[f], scan_type=ScanType.on_demand, gate_decision=GateDecision.advisory
    )
    html = build_html_report(result)
    assert "Upload context" in html
    assert "Validation:" in html
    assert "Naming:" in html
    assert "Storage:" in html
