"""Tests for ScannerWorkspace path-traversal and symlink defences."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from security_scanner.shared.scanners.workdir import ScannerWorkspace, WorkspaceError


@pytest.mark.asyncio
async def test_normal_write_succeeds() -> None:
    """A benign relative path is accepted and the file is created."""
    async with ScannerWorkspace(scan_id="test-normal") as ws:
        target = await ws.write_file("src/app.py", "print('hello')")
        assert target.exists()
        assert target.read_text() == "print('hello')"


@pytest.mark.asyncio
async def test_dotdot_traversal_rejected() -> None:
    """A path containing ``..`` is rejected before any write."""
    async with ScannerWorkspace(scan_id="test-dotdot") as ws:
        with pytest.raises(WorkspaceError, match="traversal"):
            await ws.write_file("../../etc/passwd", "evil")


@pytest.mark.asyncio
async def test_absolute_path_rejected() -> None:
    """An absolute path is rejected."""
    async with ScannerWorkspace(scan_id="test-abs") as ws:
        with pytest.raises(WorkspaceError):
            await ws.write_file("/etc/passwd", "evil")


@pytest.mark.asyncio
async def test_nul_byte_rejected() -> None:
    """A path containing a NUL byte is rejected."""
    async with ScannerWorkspace(scan_id="test-nul") as ws:
        with pytest.raises(WorkspaceError, match="NUL"):
            await ws.write_file("foo\x00bar.py", "evil")


@pytest.mark.asyncio
async def test_per_file_byte_cap() -> None:
    """A file exceeding the per-file cap is rejected."""
    async with ScannerWorkspace(scan_id="test-cap") as ws:
        big = "x" * (2 * 1024 * 1024 + 1)  # 1 byte over 2 MB cap
        with pytest.raises(WorkspaceError, match="per-file cap"):
            await ws.write_file("big.txt", big)


@pytest.mark.asyncio
async def test_per_scan_byte_cap() -> None:
    """Cumulative writes exceeding the per-scan cap are rejected."""
    async with ScannerWorkspace(scan_id="test-scan-cap") as ws:
        chunk = "x" * (1024 * 1024)  # 1 MB each
        # Write 200 chunks of 1 MB — should hit the 200 MB cap.
        written = 0
        with pytest.raises(WorkspaceError, match="per-scan cap"):
            for i in range(210):
                await ws.write_file(f"file_{i}.txt", chunk)
                written += 1


@pytest.mark.asyncio
async def test_symlink_refusal(tmp_path: Path) -> None:
    """A pre-existing symlink at the target path is refused after write detection."""
    async with ScannerWorkspace(scan_id="test-symlink") as ws:
        # Create a symlink inside the workspace pointing outside.
        link_dir = ws.root / "src"
        link_dir.mkdir(parents=True, exist_ok=True)
        link_path = link_dir / "evil.py"
        # Point the symlink to /dev/null (safe target for testing).
        try:
            os.symlink("/dev/null", link_path)
        except OSError:
            pytest.skip("Cannot create symlinks on this system")

        # The workspace should detect the symlink after write.
        with pytest.raises(WorkspaceError, match="symlink"):
            await ws.write_file("src/evil.py", "data")


@pytest.mark.asyncio
async def test_cleanup_on_exit() -> None:
    """Workspace temp directory is removed after context exit."""
    root_path: Path | None = None
    async with ScannerWorkspace(scan_id="test-cleanup") as ws:
        root_path = ws.root
        await ws.write_file("dummy.py", "x = 1")
    assert root_path is not None
    assert not root_path.exists()
