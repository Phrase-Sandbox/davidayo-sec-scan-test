"""Skill response shaping (spec §6.1, BR-005).

The skill API returns a structured JSON dict rather than a raw ``ScanResult``
so Claude.ai can render the report inline and present each patch as a
downloadable attachment. This module owns that shape.
"""

from __future__ import annotations

from security_scanner.shared.models.enums import Severity
from security_scanner.shared.models.scan_result import ScanResult
from security_scanner.shared.reports.markdown import build_markdown_report


def format_skill_response(
    result: ScanResult, patches: dict[str, str]
) -> dict:
    """Render a ``ScanResult`` (+ patch contents) into the skill's response dict.

    Returned shape:

        {
            "report_markdown": str,
            "patches": [{"filename": str, "content": str}],
            "token_limit_warning": str | None,
            "summary": str,
        }

    ``token_limit_warning`` is extracted from ``result.warnings`` when any
    warning mentions BR-005 / the scan-size limit (so callers can surface it
    prominently in the chat). ``patches`` is the dict serialised as a list
    of objects, easier for JavaScript front-ends to iterate.
    """
    return {
        "report_markdown": build_markdown_report(result),
        "patches": [
            {"filename": name, "content": content} for name, content in patches.items()
        ],
        "token_limit_warning": _extract_token_limit_warning(result.warnings),
        "summary": _summary_line(result),
    }


def _extract_token_limit_warning(warnings: list[str]) -> str | None:
    for warning in warnings:
        if "BR-005" in warning or "scan size limit" in warning.lower():
            return warning
    return None


def _summary_line(result: ScanResult) -> str:
    counts = {sev: 0 for sev in Severity}
    for finding in result.findings:
        counts[finding.severity] += 1
    return (
        f"Found {counts[Severity.Critical]} Critical, "
        f"{counts[Severity.High]} High, "
        f"{counts[Severity.Medium]} Medium, "
        f"{counts[Severity.Low]} Low findings."
    )
