"""Heuristic upload-handler detector.

Detects upload entry points in Python, JavaScript/TypeScript, and Go source
files without requiring an AST — regex + line-window heuristics only.

Frameworks detected
-------------------
Python:
  Flask     — ``request.files``
  FastAPI   — ``UploadFile``, ``File(...)``
  Django    — ``request.FILES``
  stdlib    — ``multipart.parse_form_data``

JavaScript / TypeScript:
  multer    — ``multer(``, ``upload.single(``, ``upload.array(``
  Express   — ``req.file``, ``req.files``
  busboy    — ``new Busboy``, ``busboy``
  formidable — ``new formidable``, ``Formidable``, ``IncomingForm``

Go:
  net/http  — ``r.FormFile(``, ``r.MultipartForm``, ``multipart.NewReader``
  io        — ``io.Copy(`` near ``multipart``
"""

from __future__ import annotations

import re

from security_scanner.shared.context.upload_models import UploadHandler
from security_scanner.shared.logging_util import get_logger

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Python upload patterns
# ---------------------------------------------------------------------------

_PY_UPLOAD_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Flask uses lowercase `request.files`; Django uses uppercase
    # `request.FILES`. The patterns are case-sensitive on that exact
    # token so the framework label stays correct.
    (re.compile(r"\brequest\.files\b"), "flask"),
    (re.compile(r"\bUploadFile\b"), "fastapi"),
    (re.compile(r"\bFile\s*\(\s*\.\.\.", re.IGNORECASE), "fastapi"),
    (re.compile(r"\brequest\.FILES\b"), "django"),
    (re.compile(r"\bmultipart\.parse_form_data\b", re.IGNORECASE), "multipart"),
    (re.compile(r"\bFlask-Uploads\b|\bsave_file\b.*\bupload\b", re.IGNORECASE), "flask"),
]

# ---------------------------------------------------------------------------
# JavaScript / TypeScript upload patterns
# ---------------------------------------------------------------------------

_JS_UPLOAD_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bmulter\s*\(", re.IGNORECASE), "multer"),
    (re.compile(r"\bupload\.(single|array|fields)\s*\(", re.IGNORECASE), "multer"),
    (re.compile(r"\breq\.file\b", re.IGNORECASE), "express"),
    (re.compile(r"\breq\.files\b", re.IGNORECASE), "express"),
    (re.compile(r"\bnew\s+Busboy\b|\bbusboy\s*\(", re.IGNORECASE), "busboy"),
    (re.compile(r"\bnew\s+(?:formidable\.)?(?:IncomingForm|Formidable)\s*\(", re.IGNORECASE), "formidable"),  # noqa: E501
    (re.compile(r"\bformidable\.parse\b", re.IGNORECASE), "formidable"),
]

# ---------------------------------------------------------------------------
# Go upload patterns
# ---------------------------------------------------------------------------

_GO_UPLOAD_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\br\.FormFile\s*\(", re.IGNORECASE), "gin"),
    (re.compile(r"\br\.MultipartForm\b", re.IGNORECASE), "go_multipart"),
    (re.compile(r"\bmultipart\.NewReader\s*\(", re.IGNORECASE), "go_multipart"),
    (re.compile(r"\bio\.Copy\s*\(.*\bmultipart\b", re.IGNORECASE), "go_multipart"),
    (re.compile(r"\.FormFile\s*\(", re.IGNORECASE), "go_multipart"),
]

# ---------------------------------------------------------------------------
# Function-name extractor (language-specific)
# ---------------------------------------------------------------------------

_PY_FUNC_RE = re.compile(r"(?:async\s+)?def\s+(\w+)\s*\(")
_JS_FUNC_RE = re.compile(
    r"(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\())"
)
_GO_FUNC_RE = re.compile(r"^func\s+(?:\(\s*\w+\s+\*?\w+\s*\)\s+)?(\w+)\s*\(")


def _extract_function_name(lines: list[str], trigger_idx: int, lang: str) -> str:
    """Scan backwards from *trigger_idx* to find the enclosing function name."""
    if lang == "py":
        pattern = _PY_FUNC_RE
    elif lang in ("js", "ts"):
        pattern = _JS_FUNC_RE
    else:  # go
        pattern = _GO_FUNC_RE

    for i in range(trigger_idx, max(-1, trigger_idx - 50), -1):
        if 0 <= i < len(lines):
            m = pattern.search(lines[i])
            if m:
                # Python/Go: group(1); JS: group(1) or group(2)
                name = m.group(1) or (m.group(2) if m.lastindex and m.lastindex >= 2 else "")
                return name or "<unknown>"
    return "<module>"


def _detect_language(filename: str) -> str:
    lower = filename.lower()
    if lower.endswith(".py"):
        return "py"
    if lower.endswith((".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")):
        return "js"
    if lower.endswith(".go"):
        return "go"
    return "unknown"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_MAX_HANDLERS = 200  # global cap across all files in a scan


def find_upload_handlers(files: dict[str, str]) -> list[UploadHandler]:
    """Scan *files* for upload entry points and return a list of handlers.

    Parameters
    ----------
    files:
        Dict mapping relative file path → source content.

    Returns
    -------
    list[UploadHandler]
        At most ``_MAX_HANDLERS`` handlers (early exit on cap).
    """
    results: list[UploadHandler] = []

    for filepath, content in files.items():
        if len(results) >= _MAX_HANDLERS:
            break

        lang = _detect_language(filepath)
        if lang == "unknown":
            continue

        if lang == "py":
            patterns = _PY_UPLOAD_PATTERNS
        elif lang in ("js", "ts"):
            patterns = _JS_UPLOAD_PATTERNS
        else:
            patterns = _GO_UPLOAD_PATTERNS

        try:
            found = _scan_file(filepath, content, patterns, lang)
        except Exception as exc:  # noqa: BLE001
            log.debug(
                "upload_finder: error scanning file",
                file=filepath,
                error=type(exc).__name__,
                error_message=str(exc),
            )
            continue

        results.extend(found[: _MAX_HANDLERS - len(results)])

    log.debug("upload_finder: handlers found", count=len(results))
    return results


def _scan_file(
    filepath: str,
    content: str,
    patterns: list[tuple[re.Pattern[str], str]],
    lang: str,
) -> list[UploadHandler]:
    """Scan a single file and return all upload handlers found."""
    lines = content.splitlines()
    seen: set[int] = set()
    handlers: list[UploadHandler] = []

    for pattern, framework in patterns:
        for i, line in enumerate(lines):
            if pattern.search(line):
                line_no = i + 1
                if line_no in seen:
                    continue
                seen.add(line_no)
                func_name = _extract_function_name(lines, i, lang)
                handlers.append(UploadHandler(
                    file=filepath,
                    line=line_no,
                    function_name=func_name,
                    framework=framework,
                ))

    return handlers
