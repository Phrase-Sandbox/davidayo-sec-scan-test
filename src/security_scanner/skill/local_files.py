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

import logging
import os
from pathlib import Path

import pathspec

log = logging.getLogger(__name__)

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
        "vuln-result",  # our own output directory — never scan it
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

    def __init__(self, root: str | Path, *, respect_gitignore: bool = True) -> None:
        self._root = Path(root).resolve()
        self._respect_gitignore = respect_gitignore

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

        # Patterns at ``base/.gitignore`` declare files the developer has
        # explicitly excluded from version control. They are typically build
        # artefacts, machine-local secrets files, vendored caches, etc. —
        # not "the codebase" — so respecting them avoids both wasted work
        # and FP findings on intentionally-uncommitted credentials.
        spec = self._load_gitignore_spec(base) if self._respect_gitignore else None

        files: dict[str, str] = {}
        for dirpath, dirnames, filenames in os.walk(base):
            # Prune skip-dirs in place so os.walk doesn't descend into them.
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            if spec is not None:
                # Additionally prune directories matching .gitignore patterns.
                # Trailing slash signals "directory" to pathspec — required
                # for ``build/`` style patterns to match.
                rel_dir = Path(dirpath).relative_to(base).as_posix()
                prefix = "" if rel_dir == "." else f"{rel_dir}/"
                dirnames[:] = [
                    d for d in dirnames if not spec.match_file(f"{prefix}{d}/")
                ]
            for filename in filenames:
                if filename == _REPORT_FILENAME or filename.endswith(_SKIP_SUFFIXES):
                    continue
                full = Path(dirpath) / filename
                if spec is not None:
                    rel_to_base = full.relative_to(base).as_posix()
                    if spec.match_file(rel_to_base):
                        continue
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

    @staticmethod
    def _load_gitignore_spec(base: Path) -> pathspec.PathSpec | None:
        """Return a parsed PathSpec for ``base/.gitignore``, or ``None``.

        ``None`` covers both "no .gitignore present" and "unreadable
        .gitignore" — a malformed file must not fail the scan. The caller
        treats ``None`` as "apply no extra filtering".
        """
        gi = base / ".gitignore"
        if not gi.is_file():
            return None
        try:
            text = gi.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            log.warning(
                "could not read .gitignore at %s (%s); skipping gitignore filter",
                gi,
                exc,
            )
            return None
        return pathspec.PathSpec.from_lines("gitignore", text.splitlines())

    def get_diff_files(
        self,
        owner: str = "",  # noqa: ARG002
        repo: str = "",  # noqa: ARG002
        base: str = "",  # noqa: ARG002
        head: str = "",  # noqa: ARG002
    ) -> dict[str, str]:
        # Local pre-push mode scans the working tree, not a commit range.
        return self.get_repo_files()
