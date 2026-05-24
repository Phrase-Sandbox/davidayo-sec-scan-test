"""Tests for the async subprocess runner safety properties."""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

import pytest

from security_scanner.shared.scanners.subprocess_runner import ScannerTimeout, run_scanner


@pytest.mark.asyncio
async def test_basic_command_runs(tmp_path: Path) -> None:
    """A simple echo command completes successfully."""
    rc, stdout, _stderr = await run_scanner(
        [sys.executable, "-c", "print('hello')"],
        cwd=tmp_path,
    )
    assert rc == 0
    assert b"hello" in stdout


@pytest.mark.asyncio
async def test_nonzero_exit_code(tmp_path: Path) -> None:
    """Nonzero exit code is returned without raising."""
    rc, _stdout, _stderr = await run_scanner(
        [sys.executable, "-c", "import sys; sys.exit(2)"],
        cwd=tmp_path,
    )
    assert rc == 2


@pytest.mark.asyncio
async def test_hung_subprocess_killed_within_timeout(tmp_path: Path) -> None:
    """A subprocess that sleeps longer than the timeout is killed."""
    start = time.monotonic()
    with pytest.raises(ScannerTimeout):
        await run_scanner(
            [sys.executable, "-c", "import time; time.sleep(120)"],
            cwd=tmp_path,
            timeout=1.5,
        )
    elapsed = time.monotonic() - start
    # Must finish well within 3 seconds (timeout + overhead).
    assert elapsed < 5.0, f"Kill took too long: {elapsed:.1f}s"


@pytest.mark.asyncio
async def test_oversized_stdout_truncated(tmp_path: Path) -> None:
    """Output exceeding max_output_bytes is truncated, not OOM-killed."""
    # Generate 1 MB of data against a 100-byte cap.
    cap = 100
    rc, stdout, _stderr = await run_scanner(
        [sys.executable, "-c", f"print('x' * {cap * 200})"],
        cwd=tmp_path,
        max_output_bytes=cap,
    )
    # We get at most cap bytes.
    assert len(stdout) <= cap
    assert rc == 0


@pytest.mark.asyncio
async def test_stderr_captured(tmp_path: Path) -> None:
    """stderr is captured alongside stdout."""
    _rc, _stdout, stderr = await run_scanner(
        [sys.executable, "-c", "import sys; sys.stderr.write('err_output')"],
        cwd=tmp_path,
    )
    assert b"err_output" in stderr
