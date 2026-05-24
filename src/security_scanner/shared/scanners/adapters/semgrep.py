"""Semgrep adapter.

Invokes ``semgrep --json --quiet --metrics=off --error`` with vendored local
configs so scans do not depend on the Semgrep Registry being available.

Binary missing → log warning + return [] (graceful degrade).
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from security_scanner.shared.logging_util import get_logger
from security_scanner.shared.scanners.models import ScannerCandidate
from security_scanner.shared.scanners.normalize import normalize
from security_scanner.shared.scanners.subprocess_runner import ScannerTimeout, run_scanner
from security_scanner.shared.scanners.workdir import ScannerWorkspace

log = get_logger(__name__)

# Vendored configs live at repo-root/semgrep_configs/
# parents[0]=adapters/, [1]=scanners/, [2]=shared/, [3]=security_scanner/, [4]=src/, [5]=repo-root
_CONFIGS_DIR = Path(__file__).parents[5] / "semgrep_configs"
_OWASP_CONFIG = _CONFIGS_DIR / "owasp-top-ten.yaml"
_AUDIT_CONFIG = _CONFIGS_DIR / "security-audit.yaml"
_UPLOAD_CONFIG = _CONFIGS_DIR / "upload-security.yaml"

TOOL = "semgrep"


async def scan(workspace: ScannerWorkspace) -> list[ScannerCandidate]:
    """Run Semgrep against the workspace and return normalised candidates."""
    if shutil.which("semgrep") is None:
        log.warning("semgrep adapter: binary not found — skipping")
        return []

    if not _OWASP_CONFIG.exists() or not _AUDIT_CONFIG.exists():
        log.warning(
            "semgrep adapter: vendored configs missing — skipping",
            owasp=str(_OWASP_CONFIG),
            audit=str(_AUDIT_CONFIG),
        )
        return []

    cmd = [
        "semgrep",
        "--json",
        "--quiet",
        "--metrics=off",
        "--error",
        "--config", str(_OWASP_CONFIG),
        "--config", str(_AUDIT_CONFIG),
    ]

    # Add upload config if present (best-effort — not required for scan to proceed).
    if _UPLOAD_CONFIG.exists():
        cmd.extend(["--config", str(_UPLOAD_CONFIG)])

    cmd.append(".")

    try:
        _rc, stdout, stderr = await run_scanner(cmd, cwd=workspace.root)
    except ScannerTimeout:
        log.warning("semgrep adapter: timed out")
        return []
    except Exception as exc:  # noqa: BLE001
        log.warning("semgrep adapter: subprocess error", error=str(exc))
        return []

    return _parse_output(stdout)


def _parse_output(stdout: bytes) -> list[ScannerCandidate]:
    """Parse Semgrep JSON output into ScannerCandidate objects."""
    try:
        data = json.loads(stdout.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        log.warning("semgrep adapter: JSON parse error", error=str(exc))
        return []

    candidates: list[ScannerCandidate] = []
    for result in data.get("results", []):
        try:
            raw_rule_id = result.get("check_id", "unknown")
            path = result.get("path", "")
            start = result.get("start", {})
            end = result.get("end", {})
            line_start = int(start.get("line", 1))
            line_end = int(end.get("line", line_start))
            message = result.get("extra", {}).get("message", "")
            severity = result.get("extra", {}).get("severity", "WARNING").lower()

            vuln_class = normalize(TOOL, raw_rule_id)
            candidates.append(ScannerCandidate(
                tool=TOOL,
                vuln_class=vuln_class,
                file=path,
                line_start=line_start,
                line_end=line_end,
                message=message,
                raw_rule_id=raw_rule_id,
                severity_hint=_map_severity(severity),
            ))
        except Exception as exc:  # noqa: BLE001
            log.debug("semgrep adapter: skipping malformed result", error=str(exc))
            continue

    return candidates


def _map_severity(sev: str) -> str:
    mapping = {"error": "high", "warning": "medium", "info": "low"}
    return mapping.get(sev.lower(), "medium")
