"""Callee finder — resolves helpers called from within a snippet window.

Identifies functions called from the candidate's surrounding context window and
classifies them into categories relevant to authz/IDOR analysis.
"""

from __future__ import annotations

import re
from typing import NamedTuple

# Patterns for interesting callees.
_DB_QUERY_RE = re.compile(
    r"""\b(execute|query|fetchone|fetchall|cursor|find_by|get_or_404|get_object_or_404|
        filter_by|select|insert|update|delete|raw|execute_query)\s*\(""".replace("\n", "").replace(" ", ""),
    re.IGNORECASE,
)
_OWNERSHIP_HELPER_RE = re.compile(
    r"""\b(get_user|find_\w+_by_id|get_\w+_by_id|current_user|get_current_user|
        get_owner|get_resource_owner|get_tenant)\s*\(""".replace("\n", "").replace(" ", ""),
    re.IGNORECASE,
)
_AUTH_CHECK_RE = re.compile(
    r"""\b(has_permission|can_\w+|require_\w+|check_permission|is_authorized|
        is_owner|verify_\w+|assert_permission|authorize)\s*\(""".replace("\n", "").replace(" ", ""),
    re.IGNORECASE,
)
_GENERIC_CALL_RE = re.compile(r"""\b(\w{3,})\s*\(""")


class _CalleeMatch(NamedTuple):
    name: str
    kind: str  # db_query | ownership_helper | auth_check | other


def find_callees(snippet: str) -> list[_CalleeMatch]:
    """Extract callee names from *snippet*.

    Returns deduplicated list ordered by category priority
    (auth_check > ownership_helper > db_query > other).
    """
    seen: dict[str, str] = {}  # name → kind

    for m in _AUTH_CHECK_RE.finditer(snippet):
        name = m.group(1)
        seen.setdefault(name, "auth_check")

    for m in _OWNERSHIP_HELPER_RE.finditer(snippet):
        name = m.group(1)
        seen.setdefault(name, "ownership_helper")

    for m in _DB_QUERY_RE.finditer(snippet):
        name = m.group(1)
        seen.setdefault(name, "db_query")

    for m in _GENERIC_CALL_RE.finditer(snippet):
        name = m.group(1)
        # Skip Python keywords and very short names.
        if name not in {
            "if", "for", "while", "def", "class", "return", "import",
            "from", "with", "not", "and", "or", "in", "is", "str", "int",
            "len", "print", "True", "False", "None",
        }:
            seen.setdefault(name, "other")

    # Priority order for output.
    priority = {"auth_check": 0, "ownership_helper": 1, "db_query": 2, "other": 3}
    return sorted(
        [_CalleeMatch(name=n, kind=k) for n, k in seen.items()],
        key=lambda x: (priority[x.kind], x.name),
    )
