"""Token-count estimation for the pre-scan token-limit gate.

Implements the formula from spec §4.2:

    estimated_tokens ≈ total_characters_in_filtered_files / 4

and the 150 000-token ceiling from BR-005. When ``exceeds_limit`` returns
``True`` the caller must warn the developer and prompt for a directory-scoped
re-scan before proceeding to the Claude API (EC-010).
"""

from __future__ import annotations

THRESHOLD = 150_000


def count(files: dict[str, str]) -> int:
    """Return the estimated token count for *files* using the §4.2 formula."""
    return _total_chars(files) // 4


def exceeds_limit(files: dict[str, str]) -> bool:
    """Return True iff the estimated token count strictly exceeds ``THRESHOLD``.

    The comparison is done in character-space (``total_chars > THRESHOLD * 4``)
    so the boundary case of 600 000 chars maps to *exactly* 150 000 tokens —
    at the threshold but not over it.
    """
    return _total_chars(files) > THRESHOLD * 4


def _total_chars(files: dict[str, str]) -> int:
    return sum(len(content) for content in files.values())
