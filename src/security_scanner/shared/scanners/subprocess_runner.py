"""Async subprocess runner with concurrency cap, timeout, and bounded output.

Concurrency contract (non-negotiable):
- NEVER use ``subprocess.run``, ``subprocess.Popen``, ``shell=True``, or
  ``os.system``.  All subprocess invocations use ``asyncio.create_subprocess_exec``
  with an explicit ``argv`` list — filenames are always argv items, never
  string-interpolated into a command.
- A module-level ``asyncio.Semaphore(SCANNER_CONCURRENCY)`` caps the total
  number of simultaneous scanner subprocesses across the entire event loop.
  Both the gate path and the /scan/local path share this semaphore because
  it is module-level.
- A per-call timeout (default 60 s, env-configurable) kills the subprocess
  and raises ``ScannerTimeout`` on expiry.
- stdout and stderr are each bounded to ``max_output_bytes`` (default 50 MB)
  via a single ``await proc.stdout.read(MAX)`` call.  Any surplus bytes are
  silently truncated.
- POSIX rlimits (``preexec_fn``) set RLIMIT_AS=2 GB, RLIMIT_CPU=120 s,
  RLIMIT_NOFILE=1024.  On Windows the ``preexec_fn`` parameter is ignored
  and a one-time warning is logged.
"""

from __future__ import annotations

import asyncio
import os
import platform
import sys
from pathlib import Path

from security_scanner.shared.logging_util import get_logger

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Module-level concurrency semaphore — shared across all scan requests.
# ---------------------------------------------------------------------------
_DEFAULT_CONCURRENCY = 4
SCANNER_CONCURRENCY = int(os.environ.get("SCANNER_CONCURRENCY", str(_DEFAULT_CONCURRENCY)))
_SUBPROCESS_SEM = asyncio.Semaphore(SCANNER_CONCURRENCY)

# Per-call output cap.
_DEFAULT_MAX_OUTPUT_BYTES = 50_000_000  # 50 MB

# Warn once about Windows rlimit unavailability.
_WINDOWS_RLIMIT_WARNED = False

# Default per-subprocess timeout in seconds.
_DEFAULT_TIMEOUT = float(os.environ.get("SCANNER_TIMEOUT_SECONDS", "60"))


class ScannerTimeout(Exception):
    """Raised when a scanner subprocess exceeds its time budget."""


def _set_subprocess_rlimits() -> None:  # pragma: no cover — OS-level, not in CI
    """POSIX preexec_fn: set resource limits on the child process."""
    try:
        import resource  # noqa: PLC0415 — only on POSIX

        # Address space: 2 GB.
        resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
        # CPU time: 120 s.
        resource.setrlimit(resource.RLIMIT_CPU, (120, 120))
        # Open file descriptors.
        resource.setrlimit(resource.RLIMIT_NOFILE, (1024, 1024))
    except Exception:  # noqa: BLE001
        pass


def _get_preexec_fn():  # type: ignore[return]
    """Return the preexec_fn to use for subprocess.

    Returns None on Windows (preexec_fn is not supported there) with a
    one-time warning.  On POSIX returns the rlimit setter.
    """
    global _WINDOWS_RLIMIT_WARNED  # noqa: PLW0603
    if platform.system() == "Windows":
        if not _WINDOWS_RLIMIT_WARNED:
            log.warning("subprocess_runner: rlimits not set (Windows)")
            _WINDOWS_RLIMIT_WARNED = True
        return None
    return _set_subprocess_rlimits


async def run_scanner(
    cmd: list[str],
    cwd: Path,
    timeout: float = _DEFAULT_TIMEOUT,
    max_output_bytes: int = _DEFAULT_MAX_OUTPUT_BYTES,
) -> tuple[int, bytes, bytes]:
    """Run a scanner subprocess and return ``(returncode, stdout, stderr)``.

    Parameters
    ----------
    cmd:
        Argv list — NEVER a shell string.  Filenames must appear as discrete
        argv elements so the shell never interpolates them.
    cwd:
        Working directory for the subprocess.
    timeout:
        Wall-clock timeout in seconds.  On expiry the process is killed
        and ``ScannerTimeout`` is raised.
    max_output_bytes:
        Maximum bytes to read from stdout and stderr each.  Excess is
        truncated with a warning.

    Raises
    ------
    ScannerTimeout
        The subprocess did not exit within ``timeout`` seconds.
    """
    preexec_fn = _get_preexec_fn()

    async with _SUBPROCESS_SEM:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(cwd),
            **({"preexec_fn": preexec_fn} if preexec_fn is not None else {}),
        )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                asyncio.gather(
                    proc.stdout.read(max_output_bytes),  # type: ignore[union-attr]
                    proc.stderr.read(max_output_bytes),  # type: ignore[union-attr]
                ),
                timeout=timeout,
            )
            await proc.wait()
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            await proc.wait()
            raise ScannerTimeout(
                f"Scanner command timed out after {timeout}s: {cmd[0]!r}"
            )

    if len(stdout_bytes) >= max_output_bytes:
        log.warning(
            "subprocess_runner: stdout truncated at cap",
            cmd=cmd[0],
            cap_bytes=max_output_bytes,
        )
    if len(stderr_bytes) >= max_output_bytes:
        log.warning(
            "subprocess_runner: stderr truncated at cap",
            cmd=cmd[0],
            cap_bytes=max_output_bytes,
        )

    return proc.returncode or 0, stdout_bytes, stderr_bytes
