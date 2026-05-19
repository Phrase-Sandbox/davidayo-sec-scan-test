"""Local working-directory file source for the pre-push skill mode.

Duck-typed to the subset of ``GitHubClient`` the pipeline actually calls
(``get_repo_files`` / ``get_diff_files``) — the same pattern as the
``_MockGitHubClient`` test stub in ``agent/test_endpoint.py``. This lets the
on-demand ``ScanPipeline`` run against a developer's *local* working tree
*before* anything is pushed to GitHub, with zero pipeline changes.

Secret stripping and source-file filtering still happen **inside** the
pipeline (steps 6–7) — this class only does cheap, obvious exclusions
(VCS/build dirs, our own output files, binary/oversized files) so the
pipeline isn't handed noise.

This is a documented deviation from spec §2.2 (which fetches from GitHub via
OAuth). The spec skill path is unchanged and still available.
"""

from __future__ import annotations

import os
from pathlib import Path

# Directories that never contain developer-authored source worth scanning.
_SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        "dist",
        "build",
        ".idea",
        ".vscode",
        "htmlcov",
    }
)

# Our own generated outputs — never scan these (re-run safety).
_REPORT_FILENAME = "security-scan-report.md"
_SKIP_SUFFIXES = (".patch",)

# Skip very large files outright — they are almost never hand-written source
# and bloat the token budget.
_MAX_FILE_BYTES = 1_000_000


class LocalFilesClient:
    """Returns ``{relative_posix_path: utf-8 text}`` for a local directory tree."""

    def __init__(self, root: str | Path) -> None:
        self._root = Path(root).resolve()

    # --- pipeline-facing API (mirrors GitHubClient) -----------------------

    def get_repo_files(
        self,
        owner: str = "",  # noqa: ARG002 — ignored; parity with GitHubClient
        repo: str = "",  # noqa: ARG002
        ref: str = "HEAD",  # noqa: ARG002
        path: str = "",
    ) -> dict[str, str]:
        base = self._root if not path else (self._root / path)
        if not base.is_dir():
            return {}

        files: dict[str, str] = {}
        for dirpath, dirnames, filenames in os.walk(base):
            # Prune skip-dirs in place so os.walk doesn't descend into them.
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for filename in filenames:
                if filename == _REPORT_FILENAME or filename.endswith(_SKIP_SUFFIXES):
                    continue
                full = Path(dirpath) / filename
                try:
                    if full.stat().st_size > _MAX_FILE_BYTES:
                        continue
                    text = full.read_text(encoding="utf-8")
                except (OSError, ValueError, UnicodeDecodeError):
                    # Unreadable, binary, or vanished mid-walk — skip quietly.
                    continue
                rel = full.relative_to(self._root).as_posix()
                files[rel] = text
        return files

    def get_diff_files(
        self,
        owner: str = "",  # noqa: ARG002
        repo: str = "",  # noqa: ARG002
        base: str = "",  # noqa: ARG002
        head: str = "",  # noqa: ARG002
    ) -> dict[str, str]:
        # Local pre-push mode scans the working tree, not a commit range.
        return self.get_repo_files()
