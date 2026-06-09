"""Source-file filter for the pre-scan pipeline (spec §2.2 step 3).

Discards everything that should not reach the analysis model:
- env files (``.env``, ``.env.*``, ``*.env``)
- lock files
- build output / dependency caches / virtualenvs
- binary assets (images, fonts, PDFs)
- minified bundles
- generated code (protoc, ``*.generated.*``)
- binary content (defence in depth — null bytes within the first 8192 chars)

Keeps only files that match a known source/config extension or are
``Dockerfile``/``Makefile`` (with or without a suffix).
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

_BINARY_CHECK_CHARS = 8192

_EXCLUDED_DIR_NAMES: frozenset[str] = frozenset(
    {
        "dist", "build", ".next", "__pycache__", "node_modules", ".venv", "venv",
        "static", "vendor", "vendored", "assets", "third_party", "third-party",
        # CI / scanner output — never source code worth analysing
        "sec-report", "reports", "coverage", "test-results", "artifacts",
        "vuln-result",
    }
)

_EXCLUDED_FILE_NAMES: frozenset[str] = frozenset(
    {".env", "package-lock.json", "yarn.lock", "Pipfile.lock", "poetry.lock", "Gemfile.lock"}
)

_EXCLUDED_EXTENSIONS: frozenset[str] = frozenset(
    {
        # Image / font / document assets
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
        ".woff", ".woff2", ".ttf", ".eot",
        ".pdf",
        # Any .lock-suffixed file (catches lockfiles beyond the named list)
        ".lock",
    }
)

_EXCLUDED_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^\.env\..+$"),         # .env.local, .env.production
    re.compile(r".+\.env$"),            # production.env, database.env
    re.compile(r".+\.min\.js$"),
    re.compile(r".+\.min\.css$"),
    re.compile(r".+\.pb\.go$"),         # protoc-generated Go
    re.compile(r".+_pb2\.py$"),         # protoc-generated Python
    re.compile(r".+\.generated\..+$"),  # *.generated.*
)

_INCLUDED_EXTENSIONS: frozenset[str] = frozenset(
    {
        # Source
        ".py", ".js", ".ts", ".tsx", ".jsx",
        ".go", ".rb", ".java", ".cs", ".php", ".rs", ".swift", ".kt",
        # Config that can carry logic
        ".yml", ".yaml", ".toml", ".json", ".xml", ".tf", ".hcl",
        # Shell
        ".sh", ".bash", ".zsh",
        # SQL — LLM can reason about inline queries; static scanners cannot
        ".sql",
    }
)

# Scanner layer sees templates too so Semgrep Jinja2/HTML rules can fire.
# LLM filter excludes templates to save tokens — the scanner rules cover them.
_SCANNER_INCLUDED_EXTENSIONS: frozenset[str] = _INCLUDED_EXTENSIONS | frozenset(
    {".jinja2", ".html", ".htm"}
)


def filter(files: dict[str, str]) -> dict[str, str]:
    """Return only source/config files from *files*, dropping everything excluded.

    Used for the LLM analysis pass. The original input dict is not mutated.
    """
    return {path: content for path, content in files.items() if _should_keep(path, content)}


def scanner_filter(files: dict[str, str]) -> dict[str, str]:
    """Wider filter for the Layer-1 scanner pass.

    Identical to :func:`filter` but also includes template files (``.jinja2``,
    ``.html``, ``.htm``) so that Semgrep Jinja2/HTML rules can match them.
    The LLM pass uses the narrower :func:`filter` to keep token costs down.
    The original input dict is not mutated.
    """
    return {
        path: content
        for path, content in files.items()
        if _should_keep(path, content, _SCANNER_INCLUDED_EXTENSIONS)
    }


def _should_keep(
    path: str,
    content: str,
    included_extensions: frozenset[str] = _INCLUDED_EXTENSIONS,
) -> bool:
    posix = PurePosixPath(path)
    basename = posix.name
    suffix = posix.suffix

    # 1. Excluded directory anywhere in the path.
    if any(part in _EXCLUDED_DIR_NAMES for part in posix.parts):
        return False
    # 2. Exact-name exclusions (env / lock files).
    if basename in _EXCLUDED_FILE_NAMES:
        return False
    # 3. Filename pattern exclusions (env variants, minified, generated).
    if any(pattern.match(basename) for pattern in _EXCLUDED_PATTERNS):
        return False
    # 4. Extension exclusions (assets, .lock).
    if suffix in _EXCLUDED_EXTENSIONS:
        return False
    # 5. Binary content — defence in depth for anything that slipped through.
    if _is_binary(content):
        return False
    # 6. Inclusion list.
    if suffix in included_extensions:
        return True
    if _is_dockerfile_or_makefile(basename):
        return True
    return False


def _is_binary(content: str) -> bool:
    return "\x00" in content[:_BINARY_CHECK_CHARS]


def _is_dockerfile_or_makefile(basename: str) -> bool:
    if basename in {"Dockerfile", "Makefile"}:
        return True
    return basename.startswith(("Dockerfile.", "Makefile."))
