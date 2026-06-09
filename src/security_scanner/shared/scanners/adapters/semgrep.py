"""Semgrep adapter.

Invokes ``semgrep --json --quiet --metrics=off --error`` with vendored local
configs so scans do not depend on the Semgrep Registry being available.

When SEMGREP_USE_REGISTRY=true the adapter also appends the official
``p/owasp-top-ten`` and ``p/default`` registry packs for significantly broader
language and vulnerability-class coverage. Registry packs require internet
access; unavailability falls back gracefully (findings may be fewer).

Binary missing → log warning + return [] (graceful degrade).
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

from security_scanner.observability.metrics import scanner_runs_total
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
_SSRF_CONFIG = _CONFIGS_DIR / "ssrf.yaml"
_PATH_TRAVERSAL_CONFIG = _CONFIGS_DIR / "path-traversal.yaml"
_INJECTION_CONFIG = _CONFIGS_DIR / "injection.yaml"
_AUTH_CONFIG = _CONFIGS_DIR / "auth.yaml"
_PHP_CONFIG = _CONFIGS_DIR / "php.yaml"
_JAVA_CONFIG = _CONFIGS_DIR / "java.yaml"

# Maps rule-pack name → config path.
# "required" packs abort the scan when missing; "best-effort" packs are skipped silently.
_REQUIRED_PACKS = {"owasp", "audit"}
_CONFIG_MAP: dict[str, Path] = {
    # Core packs (required)
    "owasp": _OWASP_CONFIG,
    "audit": _AUDIT_CONFIG,
    # Best-effort packs — skipped silently when file missing
    "upload": _UPLOAD_CONFIG,
    "ssrf": _SSRF_CONFIG,
    "path_traversal": _PATH_TRAVERSAL_CONFIG,
    "injection": _INJECTION_CONFIG,
    "auth": _AUTH_CONFIG,
    "php": _PHP_CONFIG,
    "java": _JAVA_CONFIG,
}

# When SEMGREP_USE_REGISTRY=true, append official registry packs for broad
# multi-language coverage. Requires internet access inside the container.
_USE_REGISTRY = os.environ.get("SEMGREP_USE_REGISTRY", "false").lower() in ("1", "true", "yes")
_REGISTRY_PACKS: list[str] = [
    "p/owasp-top-ten",   # 500+ rules, all languages — maintained by Semgrep
    "p/default",          # curated high-confidence rules per language
    "p/python",           # broad Python security — async, aiohttp, general patterns
    "p/sql-injection",    # SQL injection across Python/JS/Java patterns
]

TOOL = "semgrep"


async def scan(
    workspace: ScannerWorkspace,
    *,
    rules: set[str] | None = None,
) -> list[ScannerCandidate]:
    """Run Semgrep against the workspace and return normalised candidates.

    Parameters
    ----------
    rules:
        Set of rule-pack names to run.  ``None`` (default) runs all packs.
        An empty set skips Semgrep entirely.

        Recognised names: ``owasp``, ``audit``, ``upload``, ``ssrf``,
        ``path_traversal``, ``injection``, ``auth``, ``php``, ``java``.
        Registry packs (``p/owasp-top-ten``, ``p/default``) are added
        automatically when ``SEMGREP_USE_REGISTRY=true`` regardless of this
        parameter.
    """
    if shutil.which("semgrep") is None:
        log.warning("semgrep adapter: binary not found — skipping")
        return []

    selected = {k: v for k, v in _CONFIG_MAP.items() if rules is None or k in rules}
    if not selected and not _USE_REGISTRY:
        log.info("semgrep adapter: no rule sets enabled — skipping")
        return []

    cmd = ["semgrep", "--json", "--quiet", "--metrics=off", "--error"]
    for name, path in selected.items():
        if name in _REQUIRED_PACKS:
            if not path.exists():
                log.warning(
                    "semgrep adapter: required config missing — skipping",
                    config=name,
                    path=str(path),
                )
                return []
            cmd.extend(["--config", str(path)])
        else:
            # Best-effort packs — skip silently when file missing
            if path.exists():
                cmd.extend(["--config", str(path)])
            else:
                log.debug("semgrep adapter: best-effort config absent — skipping", config=name)

    # Optional registry packs (requires network; best-effort)
    if _USE_REGISTRY:
        for pack in _REGISTRY_PACKS:
            cmd.extend(["--config", pack])
        log.info("semgrep adapter: registry packs enabled", packs=_REGISTRY_PACKS)

    if "--config" not in cmd:
        log.info("semgrep adapter: no valid configs to run — skipping")
        return []

    cmd.append(".")

    try:
        _rc, stdout, stderr = await run_scanner(cmd, cwd=workspace.root)
    except ScannerTimeout:
        log.warning("semgrep adapter: timed out")
        scanner_runs_total.labels(tool=TOOL, outcome="timeout").inc()
        return []
    except Exception as exc:  # noqa: BLE001
        log.warning("semgrep adapter: subprocess error", error=str(exc))
        scanner_runs_total.labels(tool=TOOL, outcome="error").inc()
        return []

    scanner_runs_total.labels(tool=TOOL, outcome="success").inc()
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
