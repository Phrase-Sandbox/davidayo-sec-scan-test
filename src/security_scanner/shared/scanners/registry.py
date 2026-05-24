"""Scanner adapter registry.

Maps adapter names to their ``async def scan(workspace) -> list[ScannerCandidate]``
callables.  Adapters that require a binary are only included when that binary
is present on PATH; missing-binary adapters log a one-time warning and are
excluded so the pipeline degrades gracefully.
"""

from __future__ import annotations

import shutil
from collections.abc import Callable
from typing import Any

from security_scanner.shared.logging_util import get_logger

log = get_logger(__name__)

# Set of adapters already warned about (avoid log spam per scan).
_WARNED: set[str] = set()


def _check_binary(name: str, binary: str) -> bool:
    """Return True if ``binary`` is on PATH, else log a one-time warning."""
    if shutil.which(binary) is not None:
        return True
    if name not in _WARNED:
        log.warning(
            "scanner adapter unavailable — binary not found",
            adapter=name,
            binary=binary,
        )
        _WARNED.add(name)
    return False


def get_adapters() -> dict[str, Callable[..., Any]]:
    """Return a dict of ``{adapter_name: scan_fn}`` for available adapters."""
    from security_scanner.shared.scanners.adapters import bandit as _bandit
    from security_scanner.shared.scanners.adapters import eslint_security as _eslint
    from security_scanner.shared.scanners.adapters import gosec as _gosec
    from security_scanner.shared.scanners.adapters import semgrep as _semgrep

    adapters: dict[str, Callable[..., Any]] = {}

    if _check_binary("semgrep", "semgrep"):
        adapters["semgrep"] = _semgrep.scan

    if _check_binary("bandit", "bandit"):
        adapters["bandit"] = _bandit.scan

    if _check_binary("eslint", "eslint") or _check_binary("npx", "npx"):
        adapters["eslint"] = _eslint.scan

    if _check_binary("gosec", "gosec"):
        adapters["gosec"] = _gosec.scan

    return adapters
