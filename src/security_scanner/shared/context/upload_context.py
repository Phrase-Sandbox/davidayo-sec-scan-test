"""Upload-flow context extractor.

Given an ``UploadHandler`` and a files snapshot, produces an ``UploadContext``
describing the security posture of the upload endpoint.

All extraction is heuristic (regex + line-window).  Any exception → empty
``UploadContext`` (best-effort, never crash).
"""

from __future__ import annotations

import re

from security_scanner.shared.context.middleware_extractors import extract_middleware
from security_scanner.shared.context.ownership_checks import scan_ownership_checks
from security_scanner.shared.context.route_extractors import extract_routes
from security_scanner.shared.context.upload_models import UploadContext, UploadHandler
from security_scanner.shared.logging_util import get_logger

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Window around handler (lines)
# ---------------------------------------------------------------------------
_WINDOW_BEFORE = 30
_WINDOW_AFTER = 60


def _window(lines: list[str], line_no: int) -> list[str]:
    lo = max(0, line_no - _WINDOW_BEFORE - 1)
    hi = min(len(lines), line_no + _WINDOW_AFTER)
    return lines[lo:hi]


# ---------------------------------------------------------------------------
# Extension allow/block-list detection
# ---------------------------------------------------------------------------

_EXT_ALLOWLIST_RE = re.compile(
    r"""(?:ALLOWED_EXTENSIONS|allowed_ext|ALLOWED_FILETYPES|whitelist)
        |\.endswith\s*\(['"]\.\w+['"]
        |extension\s+in\s+[\[{(]
        |splitext\s*\(.*\)\s*\[[-12]\]\s*in
        |\.mimetype\s*in\s+
    """.replace("\n", ""),
    re.IGNORECASE | re.VERBOSE,
)

_EXT_BLOCKLIST_RE = re.compile(
    r"""(?:BLOCKED_EXTENSIONS|blacklist|blocklist|DENY_EXT)
        |extension\s+not\s+in\s+[\[{(]
        |\.endswith\s*\(.*\)\s*(?:and|or)\s+(?:raise|return|abort)
    """.replace("\n", ""),
    re.IGNORECASE | re.VERBOSE,
)

_MIME_ONLY_RE = re.compile(
    r"""(?:content.?type|mimetype|mime_type)\s*[=!]=?\s*['"]
        |content.?type\s+in\s+[\[{(]
        |\.mimetype\b
    """.replace("\n", ""),
    re.IGNORECASE | re.VERBOSE,
)

_MAGIC_BYTES_RE = re.compile(
    r"""python.magic|filetype\.guess|imghdr\.|sndhdr\.
        |f\.read\s*\(\s*\d+\s*\)\s*\.startswith
        |file\.read\s*\(\s*\d+\s*\)
        |magic\.from_buffer
        |what\s*\(.*\)
    """.replace("\n", ""),
    re.IGNORECASE | re.VERBOSE,
)

# ---------------------------------------------------------------------------
# Server-generated filename detection
# ---------------------------------------------------------------------------

_SERVER_FILENAME_RE = re.compile(
    r"""uuid\.uuid4\(\)|secrets\.token_hex|secrets\.token_urlsafe
        |hashlib\.\w+\(
        |uuid4\(\)|str\(uuid\b
        |generate_filename|secure_filename\s*\(
    """.replace("\n", ""),
    re.IGNORECASE | re.VERBOSE,
)

_PRESERVED_FILENAME_RE = re.compile(
    r"""\.filename\b|\.originalname\b|\.name\b.*upload
        |file\.name\b|req\.file\.originalname
    """.replace("\n", ""),
    re.IGNORECASE | re.VERBOSE,
)

# ---------------------------------------------------------------------------
# Size limit detection
# ---------------------------------------------------------------------------

_SIZE_LIMIT_RE = re.compile(
    r"""MAX_CONTENT_LENGTH|MAX_FILE_SIZE|max_file_size|maxFileSize
        |limits\s*:\s*\{|fileSize\s*:
        |os\.path\.getsize|content.length\b
        |\.size\s*>\s*\d|\.size\s*<\s*\d
        |MAX_UPLOAD|upload_max_filesize
    """.replace("\n", ""),
    re.IGNORECASE | re.VERBOSE,
)

# ---------------------------------------------------------------------------
# Storage path classification
# ---------------------------------------------------------------------------

_PUBLIC_STORAGE_RE = re.compile(
    r"""['"](/|\./)?(static|public|uploads|media|wwwroot|assets)/
        |os\.path\.join\s*\(.*(?:static|public|uploads|media)
        |multer\s*\(\s*\{[^}]*dest\s*:\s*['"](?:public|uploads|static)
    """.replace("\n", ""),
    re.IGNORECASE | re.VERBOSE,
)

_OUTSIDE_WEBROOT_RE = re.compile(
    r"""UPLOAD_FOLDER|upload_dir|MEDIA_ROOT|DATA_DIR|STORAGE_PATH
        |/var/|/tmp/|/home/|/srv/
        |os\.environ.*(?:upload|media|storage)
    """.replace("\n", ""),
    re.IGNORECASE | re.VERBOSE,
)

# ---------------------------------------------------------------------------
# Retrieval patterns
# ---------------------------------------------------------------------------

_DIRECT_RETRIEVAL_RE = re.compile(
    r"""send_from_directory\s*\(|send_file\s*\(.*filename
        |@.*route.*uploads.*<.*>|@.*route.*files.*<.*>
        |res\.sendFile\s*\(|res\.download\s*\(
        |r\.Static\s*\(|http\.ServeFile
        |ServeContent
    """.replace("\n", ""),
    re.IGNORECASE | re.VERBOSE,
)

# ---------------------------------------------------------------------------
# Post-processing patterns
# ---------------------------------------------------------------------------

_ARCHIVE_EXTRACT_RE = re.compile(
    r"""zipfile\.ZipFile|\.extractall\s*\(|tarfile\.open|\.extractall
        |shutil\.unpack_archive
    """.replace("\n", ""),
    re.IGNORECASE,
)

_RISKY_PARSER_RE = re.compile(
    r"""yaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)
        |yaml\.unsafe_load
        |xml\.etree\.ElementTree\.parse
        |ElementTree\.parse\s*\(
        |template.*\.render\s*\(.*upload
        |jinja.*\.from_string\s*\(.*upload
    """.replace("\n", ""),
    re.IGNORECASE | re.VERBOSE,
)

_COMMONPATH_CHECK_RE = re.compile(
    r"""os\.path\.commonpath|commonprefix|os\.path\.abspath
        |PurePosixPath|Path\(.*\)\.resolve
        |\.resolve\(\)
    """.replace("\n", ""),
    re.IGNORECASE | re.VERBOSE,
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_upload_context(
    handler: UploadHandler,
    files: dict[str, str],
) -> UploadContext:
    """Extract upload-flow context for *handler*.

    Best-effort — never raises.  Returns an empty ``UploadContext`` on error.
    """
    try:
        return _extract(handler, files)
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "upload_context: extractor error",
            file=handler.file,
            line=handler.line,
            error=type(exc).__name__,
            error_message=str(exc),
        )
        return UploadContext()


def _extract(handler: UploadHandler, files: dict[str, str]) -> UploadContext:
    content = files.get(handler.file, "")
    lines = content.splitlines()
    window_lines = _window(lines, handler.line)
    window_text = "\n".join(window_lines)

    # --- Route summary -------------------------------------------------------
    route_summary: list[str] = []
    for r in extract_routes(handler.file, content)[:5]:
        route_summary.append(f"{r.method} {r.path} → {r.handler}")

    # --- Middleware summary ---------------------------------------------------
    middleware_summary: list[str] = []
    for m in extract_middleware(handler.file, content)[:10]:
        middleware_summary.append(m.name)

    # --- Auth/z signals -------------------------------------------------------
    authz_signals: list[str] = []
    for oc in scan_ownership_checks(handler.file, content):
        authz_signals.append(
            f"{oc.pattern} (current_user-derived: {oc.current_user_derived})"
        )

    # --- Filename handling ----------------------------------------------------
    filename_handling: list[str] = []
    if _SERVER_FILENAME_RE.search(window_text):
        filename_handling.append("server-generated")
    if _PRESERVED_FILENAME_RE.search(window_text):
        filename_handling.append("preserved-user-filename")
    if not filename_handling:
        filename_handling.append("unknown")

    # --- Validation signals ---------------------------------------------------
    validation_signals: list[str] = []
    if _MAGIC_BYTES_RE.search(window_text):
        validation_signals.append("magic-bytes")
    if _EXT_ALLOWLIST_RE.search(window_text):
        validation_signals.append("extension-allowlist")
    if _MIME_ONLY_RE.search(window_text) and "magic-bytes" not in validation_signals:
        validation_signals.append("MIME-only")
    if _EXT_BLOCKLIST_RE.search(window_text) and "extension-allowlist" not in validation_signals:
        validation_signals.append("blocklist")
    if not validation_signals:
        validation_signals.append("none")

    # --- Size limits ----------------------------------------------------------
    size_limit_signals: list[str] = []
    if _SIZE_LIMIT_RE.search(window_text):
        size_limit_signals.append("yes")
    else:
        size_limit_signals.append("none")

    # --- Storage signals ------------------------------------------------------
    storage_signals: list[str] = []
    if _PUBLIC_STORAGE_RE.search(window_text):
        storage_signals.append("public-path")
    elif _OUTSIDE_WEBROOT_RE.search(window_text):
        storage_signals.append("outside-webroot")
    else:
        storage_signals.append("unknown")

    # --- Retrieval signals ----------------------------------------------------
    retrieval_signals: list[str] = []
    if _DIRECT_RETRIEVAL_RE.search(content):
        retrieval_signals.append("direct-by-filename")
    if not retrieval_signals:
        retrieval_signals.append("none")

    # --- Post-processing signals ----------------------------------------------
    post_processing_signals: list[str] = []
    has_archive = bool(_ARCHIVE_EXTRACT_RE.search(window_text))
    has_parser = bool(_RISKY_PARSER_RE.search(window_text))
    has_containment = bool(_COMMONPATH_CHECK_RE.search(window_text))

    if has_archive:
        if has_containment:
            post_processing_signals.append("archive-extract-with-containment")
        else:
            post_processing_signals.append("archive-extract")
    if has_parser:
        post_processing_signals.append("risky-parser")
    if not post_processing_signals:
        post_processing_signals.append("none")

    # --- Overall summary ------------------------------------------------------
    validation_str = " | ".join(validation_signals)
    filename_str = " | ".join(filename_handling)
    storage_str = " | ".join(storage_signals)
    size_str = " | ".join(size_limit_signals)
    processing_str = " | ".join(post_processing_signals)
    auth_str = "yes" if authz_signals or middleware_summary else "none"

    overall_summary = (
        f"Validation: {validation_str} — "
        f"Naming: {filename_str} — "
        f"Storage: {storage_str} — "
        f"Limits: {size_str} — "
        f"Access: {auth_str} — "
        f"Processing: {processing_str}"
    )

    return UploadContext(
        route_summary=route_summary,
        middleware_summary=middleware_summary,
        authz_signals=authz_signals,
        filename_handling=filename_handling,
        validation_signals=validation_signals,
        size_limit_signals=size_limit_signals,
        storage_signals=storage_signals,
        retrieval_signals=retrieval_signals,
        post_processing_signals=post_processing_signals,
        overall_summary=overall_summary,
    )
