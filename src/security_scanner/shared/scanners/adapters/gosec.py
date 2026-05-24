"""gosec adapter (Go security checker).

Invokes ``gosec -fmt=json -quiet ./...`` in the workspace root.  Only
workspaces containing ``.go`` files are scanned.

Binary missing → log warning + return [] (graceful degrade).
"""

from __future__ import annotations

import json
import shutil

from security_scanner.shared.logging_util import get_logger
from security_scanner.shared.scanners.models import ScannerCandidate
from security_scanner.shared.scanners.normalize import normalize
from security_scanner.shared.scanners.subprocess_runner import ScannerTimeout, run_scanner
from security_scanner.shared.scanners.workdir import ScannerWorkspace

log = get_logger(__name__)

TOOL = "gosec"


async def scan(workspace: ScannerWorkspace) -> list[ScannerCandidate]:
    """Run gosec against the workspace and return normalised candidates."""
    if shutil.which("gosec") is None:
        log.warning("gosec adapter: binary not found — skipping")
        return []

    go_files = list(workspace.root.rglob("*.go"))
    if not go_files:
        return []

    cmd = [
        "gosec",
        "-fmt=json",
        "-quiet",
        "./...",
    ]

    try:
        _rc, stdout, _stderr = await run_scanner(cmd, cwd=workspace.root)
    except ScannerTimeout:
        log.warning("gosec adapter: timed out")
        return []
    except Exception as exc:  # noqa: BLE001
        log.warning("gosec adapter: subprocess error", error=str(exc))
        return []

    return _parse_output(stdout, workspace_root=str(workspace.root))


def _parse_output(stdout: bytes, *, workspace_root: str) -> list[ScannerCandidate]:
    """Parse gosec JSON output into ScannerCandidate objects."""
    try:
        data = json.loads(stdout.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        log.warning("gosec adapter: JSON parse error", error=str(exc))
        return []

    candidates: list[ScannerCandidate] = []
    for issue in data.get("Issues", []):
        try:
            raw_rule_id = issue.get("rule_id", "")
            filename = issue.get("file", "")
            if filename.startswith(workspace_root):
                filename = filename[len(workspace_root):].lstrip("/\\")

            line_str = issue.get("line", "1")
            # gosec sometimes returns "42-45" for line ranges.
            if "-" in str(line_str):
                parts = str(line_str).split("-", 1)
                line_start = int(parts[0])
                line_end = int(parts[1])
            else:
                line_start = int(line_str)
                line_end = line_start

            message = issue.get("details", "")
            severity = issue.get("severity", "MEDIUM").lower()
            confidence = issue.get("confidence", "MEDIUM").lower()

            if confidence == "low":
                continue

            vuln_class = normalize(TOOL, raw_rule_id)
            candidates.append(ScannerCandidate(
                tool=TOOL,
                vuln_class=vuln_class,
                file=filename,
                line_start=line_start,
                line_end=line_end,
                message=message,
                raw_rule_id=raw_rule_id,
                severity_hint=severity,
            ))
        except Exception as exc:  # noqa: BLE001
            log.debug("gosec adapter: skipping malformed issue", error=str(exc))
            continue

    return candidates
