"""Bandit adapter (Python security linter).

Invokes ``bandit -f json -r <workspace>`` and maps its check IDs through the
normalisation table.  Only ``.py`` files are scanned.

Binary missing → log warning + return [] (graceful degrade).
"""

from __future__ import annotations

import json
import shutil

from security_scanner.observability.metrics import scanner_runs_total
from security_scanner.shared.logging_util import get_logger
from security_scanner.shared.scanners.models import ScannerCandidate
from security_scanner.shared.scanners.normalize import normalize
from security_scanner.shared.scanners.subprocess_runner import ScannerTimeout, run_scanner
from security_scanner.shared.scanners.workdir import ScannerWorkspace

log = get_logger(__name__)

TOOL = "bandit"


async def scan(workspace: ScannerWorkspace) -> list[ScannerCandidate]:
    """Run Bandit against the workspace and return normalised candidates."""
    if shutil.which("bandit") is None:
        log.warning("bandit adapter: binary not found — skipping")
        return []

    # Check there are any .py files to avoid bandit erroring on empty scan.
    py_files = list(workspace.root.rglob("*.py"))
    if not py_files:
        return []

    cmd = [
        "bandit",
        "-f",
        "json",
        "-r",
        str(workspace.root),
        "--quiet",
    ]

    try:
        _rc, stdout, _stderr = await run_scanner(cmd, cwd=workspace.root)
    except ScannerTimeout:
        log.warning("bandit adapter: timed out")
        scanner_runs_total.labels(tool=TOOL, outcome="timeout").inc()
        return []
    except Exception as exc:  # noqa: BLE001
        log.warning("bandit adapter: subprocess error", error=str(exc))
        scanner_runs_total.labels(tool=TOOL, outcome="error").inc()
        return []

    scanner_runs_total.labels(tool=TOOL, outcome="success").inc()
    return _parse_output(stdout, workspace_root=str(workspace.root))


def _parse_output(stdout: bytes, *, workspace_root: str) -> list[ScannerCandidate]:
    """Parse Bandit JSON output into ScannerCandidate objects."""
    try:
        data = json.loads(stdout.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        log.warning("bandit adapter: JSON parse error", error=str(exc))
        return []

    candidates: list[ScannerCandidate] = []
    for issue in data.get("results", []):
        try:
            raw_rule_id = issue.get("test_id", "")
            filename = issue.get("filename", "")
            # Make path relative to workspace root.
            if filename.startswith(workspace_root):
                filename = filename[len(workspace_root) :].lstrip("/\\")

            line_start = int(issue.get("line_number", 1))
            line_end = int(issue.get("line_range", [line_start])[-1])
            message = issue.get("issue_text", "")
            severity = issue.get("issue_severity", "MEDIUM").lower()

            vuln_class = normalize(TOOL, raw_rule_id)
            candidates.append(
                ScannerCandidate(
                    tool=TOOL,
                    vuln_class=vuln_class,
                    file=filename,
                    line_start=line_start,
                    line_end=line_end,
                    message=message,
                    raw_rule_id=raw_rule_id,
                    severity_hint=severity,
                )
            )
        except Exception as exc:  # noqa: BLE001
            log.debug("bandit adapter: skipping malformed issue", error=str(exc))
            continue

    return candidates
