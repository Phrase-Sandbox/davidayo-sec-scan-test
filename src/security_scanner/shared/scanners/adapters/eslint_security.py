"""ESLint-security adapter (JavaScript / TypeScript).

Invokes ESLint with a vendored security config via ``npx --no-install eslint``
(or directly ``eslint`` if available).  Only JS/TS/JSX/TSX files are targeted.

The ``--no-install`` flag prevents npx from downloading packages at scan time
(network egress defence).  The vendored config at
``eslint_security/.eslintrc.security.json`` extends
``plugin:security/recommended`` which must be installed in the container.

Binary missing → log warning + return [] (graceful degrade).
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from security_scanner.observability.metrics import scanner_runs_total
from security_scanner.shared.logging_util import get_logger
from security_scanner.shared.scanners.models import ScannerCandidate
from security_scanner.shared.scanners.normalize import normalize
from security_scanner.shared.scanners.subprocess_runner import ScannerTimeout, run_scanner
from security_scanner.shared.scanners.workdir import ScannerWorkspace

log = get_logger(__name__)

# Vendored ESLint config lives at repo-root/eslint_security/
# parents[0]=adapters/, [1]=scanners/, [2]=shared/, [3]=security_scanner/, [4]=src/, [5]=repo-root
_ESLINT_CONFIG = Path(__file__).parents[5] / "eslint_security" / ".eslintrc.security.json"

_JS_EXTENSIONS = {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}

TOOL = "eslint"


async def scan(workspace: ScannerWorkspace) -> list[ScannerCandidate]:
    """Run ESLint-security against JS/TS files in the workspace."""
    # Check JS/TS files exist.
    js_files = [f for f in workspace.root.rglob("*") if f.suffix in _JS_EXTENSIONS and f.is_file()]
    if not js_files:
        return []

    if not _ESLINT_CONFIG.exists():
        log.warning("eslint adapter: vendored config missing", config=str(_ESLINT_CONFIG))
        return []

    # Prefer direct eslint binary; fall back to npx --no-install.
    if shutil.which("eslint"):
        eslint_cmd = ["eslint"]
    elif shutil.which("npx"):
        eslint_cmd = ["npx", "--no-install", "eslint"]
    else:
        log.warning("eslint adapter: neither eslint nor npx found — skipping")
        return []

    cmd = [
        *eslint_cmd,
        "-f",
        "json",
        "--no-eslintrc",
        "-c",
        str(_ESLINT_CONFIG),
        "--ext",
        ",".join(_JS_EXTENSIONS),
        ".",
    ]

    try:
        _rc, stdout, _stderr = await run_scanner(cmd, cwd=workspace.root)
    except ScannerTimeout:
        log.warning("eslint adapter: timed out")
        scanner_runs_total.labels(tool=TOOL, outcome="timeout").inc()
        return []
    except Exception as exc:  # noqa: BLE001
        log.warning("eslint adapter: subprocess error", error=str(exc))
        scanner_runs_total.labels(tool=TOOL, outcome="error").inc()
        return []

    scanner_runs_total.labels(tool=TOOL, outcome="success").inc()
    return _parse_output(stdout, workspace_root=str(workspace.root))


def _parse_output(stdout: bytes, *, workspace_root: str) -> list[ScannerCandidate]:
    """Parse ESLint JSON output into ScannerCandidate objects."""
    try:
        data = json.loads(stdout.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        log.warning("eslint adapter: JSON parse error", error=str(exc))
        return []

    if not isinstance(data, list):
        return []

    candidates: list[ScannerCandidate] = []
    for file_result in data:
        filename = file_result.get("filePath", "")
        if filename.startswith(workspace_root):
            filename = filename[len(workspace_root) :].lstrip("/\\")

        for msg in file_result.get("messages", []):
            try:
                raw_rule_id = msg.get("ruleId") or "unknown"
                line_start = int(msg.get("line", 1))
                line_end = int(msg.get("endLine", line_start))
                message = msg.get("message", "")
                severity_int = msg.get("severity", 1)
                severity = "high" if severity_int >= 2 else "medium"

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
                log.debug("eslint adapter: skipping malformed message", error=str(exc))
                continue

    return candidates
