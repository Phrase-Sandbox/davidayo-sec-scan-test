"""Token-count estimation for the pre-scan token-limit gate.

Implements the formula from spec §4.2:

    estimated_tokens ≈ total_characters_in_filtered_files / 4

and the 150 000-token ceiling from BR-005. When ``exceeds_limit`` returns
``True`` the caller must warn the developer and prompt for a directory-scoped
re-scan before proceeding to the Claude API (EC-010).
"""

from __future__ import annotations

THRESHOLD = 150_000

# High-risk path prefixes: files under these directories are prioritised when
# trimming a repo to fit the token budget.  Mirrors the built-in list in
# shared/context/packager.py so the most security-sensitive files are always
# included in a partial scan.
_HIGH_RISK_PREFIXES: tuple[str, ...] = (
    "auth/", "authentication/", "authorisation/", "authorization/",
    "login/", "session/", "oauth/", "sso/",
    "payments/", "billing/", "checkout/", "stripe/",
    "admin/", "management/", "internal/",
    "api/", "endpoints/", "routes/",
    "crypto/", "security/", "secrets/",
    "upload/", "uploads/", "files/",
    "db/", "database/", "models/", "migrations/",
)


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


def trim_to_budget(
    files: dict[str, str],
    budget: int = THRESHOLD,
) -> tuple[dict[str, str], list[str]]:
    """Return *(kept, skipped)* where *kept* fits within *budget* tokens.

    Files are prioritised in two passes:
    1. Files whose path starts with a high-risk prefix (auth, payments, admin, …).
    2. Remaining files in alphabetical order (deterministic, reproducible).

    Within each pass files are added greedily until the budget would be exceeded.
    The first file that would push the total over budget and all subsequent files
    are collected in *skipped*.
    """
    budget_chars = budget * 4

    def _is_high_risk(path: str) -> bool:
        lower = path.lower().replace("\\", "/")
        return any(
            lower.startswith(p) or ("/" + p) in lower
            for p in _HIGH_RISK_PREFIXES
        )

    high_risk = sorted(p for p in files if _is_high_risk(p))
    normal = sorted(p for p in files if not _is_high_risk(p))

    kept: dict[str, str] = {}
    skipped: list[str] = []
    total_chars = 0

    for path in high_risk + normal:
        content = files[path]
        if total_chars + len(content) <= budget_chars:
            kept[path] = content
            total_chars += len(content)
        else:
            skipped.append(path)

    return kept, skipped


def _total_chars(files: dict[str, str]) -> int:
    return sum(len(content) for content in files.values())
