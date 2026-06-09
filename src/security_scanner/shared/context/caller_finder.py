"""Repo-wide caller finder — heuristic text/import scan.

Finds up to MAX_CALLERS call sites for a given function name.
Skips test paths.  Returns up to 5 lines of context per call.
"""

from __future__ import annotations

import re
from typing import NamedTuple

MAX_CALLERS = 20
CONTEXT_LINES = 5

# Test path fragments to skip.
_TEST_PATH_FRAGMENTS = frozenset(
    {
        "/test/",
        "/tests/",
        "__tests__",
        ".test.",
        ".spec.",
        "\\test\\",
        "\\tests\\",
    }
)


def _is_test_file(path: str) -> bool:
    lower = path.lower()
    # Top-level "tests/" or "test/" prefix isn't preceded by a separator,
    # so the fragment check needs explicit prefix handling.
    if lower.startswith(("tests/", "test/", "__tests__/")):
        return True
    return any(frag in lower for frag in _TEST_PATH_FRAGMENTS)


class _CallerMatch(NamedTuple):
    file: str
    line: int  # 1-based
    function_name: str
    snippet: str


_CALLING_FUNC_RE = re.compile(r"""def\s+(\w+)\s*\(""")


def _enclosing_function(lines: list[str], call_line_idx: int) -> str:
    """Walk backwards from call_line_idx to find the enclosing def."""
    for i in range(call_line_idx, -1, -1):
        m = _CALLING_FUNC_RE.search(lines[i])
        if m:
            return m.group(1)
    return "<module>"


def find_callers(
    function_name: str,
    files: dict[str, str],
    *,
    max_callers: int = MAX_CALLERS,
) -> list[_CallerMatch]:
    """Search *files* for call sites of *function_name*.

    Parameters
    ----------
    function_name:
        The function whose callers we are looking for.
    files:
        Mapping of filepath → content (in-memory repo snapshot).
    max_callers:
        Hard cap on the number of call sites returned.

    Returns
    -------
    list[_CallerMatch]
        Up to *max_callers* matches, test files excluded.
    """
    if not function_name or function_name == "<unknown>":
        return []

    # Build a pattern that matches the function being called (not defined).
    # We want  foo(  or  foo (  but NOT  def foo(  or  class foo(
    # Use a simple word-boundary match + post-filter for def/class declarations.
    call_re = re.compile(r"""\b""" + re.escape(function_name) + r"""\s*\(""")
    # Detect definition lines to exclude.
    def_re = re.compile(
        r"""^\s*(?:async\s+)?(?:def|class)\s+""" + re.escape(function_name) + r"""\s*[\(:]"""
    )

    results: list[_CallerMatch] = []
    for filepath, content in files.items():
        if _is_test_file(filepath):
            continue
        if len(results) >= max_callers:
            break
        lines = content.splitlines()
        for i, line in enumerate(lines):
            # Skip definition lines (def foo( or class foo()
            if def_re.search(line):
                continue
            if call_re.search(line):
                lo = max(0, i - 2)
                hi = min(len(lines), i + CONTEXT_LINES - 2)
                snippet = "\n".join(lines[lo:hi])
                enc = _enclosing_function(lines, i)
                results.append(
                    _CallerMatch(
                        file=filepath,
                        line=i + 1,
                        function_name=enc,
                        snippet=snippet,
                    )
                )
                if len(results) >= max_callers:
                    break
    return results
