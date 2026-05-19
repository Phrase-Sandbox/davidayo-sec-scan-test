"""Per-finding patch generator (spec §2.2 step 6, §3.1 ``patch_file_path``).

Generates a unified-diff ``.patch`` file per finding by:

1. Extracting the first fenced code block from ``finding.suggested_fix``.
2. Parsing ``finding.affected_lines`` (e.g. ``"42"`` or ``"42-55"``).
3. Replacing that line range in the supplied ``file_content`` with the code
   block, then running ``difflib.unified_diff`` to produce the patch text.

Findings that cannot be expressed as a patch — architectural changes, fixes
with no code block, an unparseable line range, or a missing file — return
``None`` and have their ``patch_file_path`` cleared to ``""`` so the report
builder can omit the "apply this patch" affordance.

The diff output is a hunk (n=3 context lines) only. The full file is never
written to the patch, and secrets have already been stripped from
``file_content`` upstream (see ``shared/secrets/stripper.py``).
"""

from __future__ import annotations

import difflib
import posixpath
import re
from uuid import UUID

from security_scanner.shared.models.finding import VulnerabilityFinding
from security_scanner.shared.models.scan_result import ScanResult

_CODE_BLOCK_RE = re.compile(
    r"```(?:[A-Za-z0-9_+\-]*)?[\r\n]+(.*?)[\r\n]*```",
    re.DOTALL,
)

_LINE_RANGE_RE = re.compile(
    r"^\s*(\d+)\s*(?:[-–]\s*(\d+))?\s*$",
)

_DIFF_CONTEXT_LINES = 3


def generate_patch(finding: VulnerabilityFinding, file_content: str) -> str | None:
    """Return a unified-diff patch for *finding*, or ``None`` if not representable.

    Side effect: when ``None`` is returned, ``finding.patch_file_path`` is set
    to ``""`` so the report builder can drop the patch reference.
    """
    new_code = _extract_code_block(finding.suggested_fix)
    if new_code is None:
        finding.patch_file_path = ""
        return None

    line_range = _parse_line_range(finding.affected_lines)
    if line_range is None:
        finding.patch_file_path = ""
        return None
    start, end = line_range

    original_lines = file_content.splitlines(keepends=True)
    if start < 1 or end > len(original_lines) or start > end:
        finding.patch_file_path = ""
        return None

    new_lines = new_code.splitlines(keepends=True)
    _ensure_trailing_newline(original_lines)
    _ensure_trailing_newline(new_lines)

    # Build the "after" file by splicing the new code over the affected range.
    # The full "after" content is fed to unified_diff so the hunk gets correct
    # line numbers, but unified_diff only emits the hunk + context — the
    # patch text never contains the full file.
    after_lines = original_lines[: start - 1] + new_lines + original_lines[end:]

    diff_iter = difflib.unified_diff(
        original_lines,
        after_lines,
        fromfile=f"a/{finding.affected_file}",
        tofile=f"b/{finding.affected_file}",
        n=_DIFF_CONTEXT_LINES,
    )
    return "".join(diff_iter)


def generate_all_patches(
    result: ScanResult, files: dict[str, str]
) -> dict[str, str]:
    """Return ``{patch_filename: patch_text}`` for every findable patch in *result*.

    Filename format: ``{scan_id}_{finding_index}_{affected_file_basename}.patch``.
    Findings without a fetched file or without a representable patch are
    silently skipped (their ``patch_file_path`` is cleared to ``""``).
    """
    patches: dict[str, str] = {}
    for index, finding in enumerate(result.findings):
        file_content = files.get(finding.affected_file)
        if file_content is None:
            finding.patch_file_path = ""
            continue
        patch_text = generate_patch(finding, file_content)
        if patch_text is None:
            # patch_file_path already cleared by generate_patch.
            continue
        filename = _patch_filename(result.scan_id, index, finding.affected_file)
        patches[filename] = patch_text
        finding.patch_file_path = filename
    return patches


# --- Helpers ---------------------------------------------------------------


def _extract_code_block(text: str) -> str | None:
    if not text:
        return None
    match = _CODE_BLOCK_RE.search(text)
    if match is None:
        return None
    return match.group(1)


def _parse_line_range(value: str | None) -> tuple[int, int] | None:
    if value is None:
        return None
    match = _LINE_RANGE_RE.match(value)
    if match is None:
        return None
    start = int(match.group(1))
    end = int(match.group(2)) if match.group(2) is not None else start
    return start, end


def _ensure_trailing_newline(lines: list[str]) -> None:
    if lines and not lines[-1].endswith(("\n", "\r")):
        lines[-1] = lines[-1] + "\n"


def _patch_filename(scan_id: UUID, finding_index: int, affected_file: str) -> str:
    basename = posixpath.basename(affected_file) or "file"
    return f"{scan_id}_{finding_index}_{basename}.patch"
