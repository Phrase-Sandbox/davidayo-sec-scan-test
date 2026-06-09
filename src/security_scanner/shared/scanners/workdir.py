"""Per-scan temporary workspace with path-traversal and symlink defences.

Safety contract (non-negotiable):
- All written files must resolve inside the tempdir.
- Filenames containing ``..``, NUL bytes, or absolute paths are rejected
  before a single byte is written.
- After writing, ``os.lstat`` confirms the result is a regular file — not a
  symlink that snuck in between the write and the check (TOCTOU defence).
- Per-file cap: 2 MB.
- Per-scan cumulative cap: 200 MB.
- Cleanup in ``__aexit__`` with ``shutil.rmtree(ignore_errors=True)``.
"""

from __future__ import annotations

import os
import shutil
import stat as _stat
import tempfile
from pathlib import Path

from security_scanner.shared.logging_util import get_logger

log = get_logger(__name__)

_PER_FILE_CAP = 2 * 1024 * 1024  # 2 MB
_PER_SCAN_CAP = 200 * 1024 * 1024  # 200 MB


class WorkspaceError(ValueError):
    """Raised when a file cannot be safely written into the workspace."""


class ScannerWorkspace:
    """Async context manager that owns a per-scan temporary directory.

    Usage::

        async with ScannerWorkspace(scan_id="abc123") as ws:
            await ws.write_file("src/app.py", source_content)
            # pass ws.root to adapters
    """

    def __init__(self, *, scan_id: str) -> None:
        self._scan_id = scan_id
        self._root: Path | None = None
        self._bytes_written = 0

    async def __aenter__(self) -> ScannerWorkspace:
        self._root = Path(tempfile.mkdtemp(prefix=f"sec-scan-{self._scan_id}-")).resolve()
        self._bytes_written = 0
        log.debug("workspace created", root=str(self._root), scan_id=self._scan_id)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:  # type: ignore[type-arg]
        if self._root is not None:
            shutil.rmtree(self._root, ignore_errors=True)
            log.debug("workspace cleaned up", root=str(self._root), scan_id=self._scan_id)
        return None  # do not suppress exceptions

    @property
    def root(self) -> Path:
        """The resolved tempdir path.  Only valid inside the ``async with`` block."""
        if self._root is None:
            raise RuntimeError("ScannerWorkspace used outside async context manager")
        return self._root

    async def write_file(self, rel: str, content: str) -> Path:
        """Write ``content`` to ``<tempdir>/<rel>``, enforcing all safety checks.

        Parameters
        ----------
        rel:
            Relative path within the workspace.  Must not contain ``..``,
            NUL bytes, or be an absolute path.
        content:
            UTF-8 source text.

        Returns
        -------
        Path
            The absolute path of the written file.

        Raises
        ------
        WorkspaceError
            If any safety check fails.
        """
        self._validate_rel_path(rel)

        raw_target = self.root / rel
        # Pre-resolve symlink check: a symlink at the target (or any parent)
        # is refused outright before resolve() follows it. This catches the
        # TOCTOU class where an attacker plants a symlink in the workspace.
        for ancestor in [raw_target, *raw_target.parents]:
            try:
                if ancestor.is_symlink():
                    raise WorkspaceError(
                        f"Refusing to write {rel!r}: symlink detected at {ancestor}"
                    )
            except OSError:
                break
            if ancestor == self.root:
                break

        target = raw_target.resolve()

        # Resolve-based traversal check.
        if not self._is_under_root(target):
            raise WorkspaceError(
                f"Path traversal detected: {rel!r} resolves outside workspace"
                " (possible symlink escape)"
            )

        encoded = content.encode("utf-8", errors="replace")

        if len(encoded) > _PER_FILE_CAP:
            raise WorkspaceError(
                f"File {rel!r} exceeds per-file cap ({len(encoded)} > {_PER_FILE_CAP})"
            )

        if self._bytes_written + len(encoded) > _PER_SCAN_CAP:
            raise WorkspaceError(
                f"Writing {rel!r} would exceed per-scan cap of {_PER_SCAN_CAP} bytes"
            )

        # Create parent directories.
        target.parent.mkdir(parents=True, exist_ok=True)

        target.write_bytes(encoded)
        self._bytes_written += len(encoded)

        # TOCTOU: verify the result is a regular file (not a symlink).
        st = os.lstat(target)
        if not _stat.S_ISREG(st.st_mode):
            target.unlink(missing_ok=True)
            raise WorkspaceError(
                f"Post-write lstat detected non-regular file at {rel!r} — possible symlink attack"
            )

        return target

    # --- Helpers ------------------------------------------------------------

    def _validate_rel_path(self, rel: str) -> None:
        if "\x00" in rel:
            raise WorkspaceError(f"Filename contains NUL byte: {rel!r}")
        if os.path.isabs(rel):
            raise WorkspaceError(f"Absolute path not allowed: {rel!r}")
        parts = Path(rel).parts
        if ".." in parts:
            raise WorkspaceError(f"Path traversal component '..': {rel!r}")

    def _is_under_root(self, target: Path) -> bool:
        try:
            target.relative_to(self.root)
            return True
        except ValueError:
            return False
