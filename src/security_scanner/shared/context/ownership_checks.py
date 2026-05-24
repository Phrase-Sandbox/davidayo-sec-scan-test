"""Ownership / permission check pattern detector.

Scans a file's content for patterns that indicate access-control enforcement:
- SQL ``WHERE user_id = ?``  style clauses
- Decorator / function-call permission gates
- current_user comparison patterns

For each match, classifies whether the RHS is ``current_user``-derived (safe)
or potentially attacker-controllable.
"""

from __future__ import annotations

import re
from typing import NamedTuple


class _OwnershipMatch(NamedTuple):
    line: int               # 1-based
    pattern: str            # label of the matched pattern
    identifier: str         # the ownership column / parameter name
    current_user_derived: bool   # True = safe comparison


# --- Pattern registry ---------------------------------------------------

# SQL ownership clause: WHERE user_id = ... / WHERE tenant_id = ...
_SQL_OWNERSHIP_RE = re.compile(
    r"""WHERE\s+(user_id|tenant_id|org_id|owner_id|account_id|created_by)\s*=\s*(.+?)(?:\s*AND|\s*OR|\s*$|;)""",
    re.IGNORECASE,
)

# require_admin / require_permission / require_role
# Matches both decorator form (@require_admin) and call form (require_admin(...)).
_REQUIRE_RE = re.compile(
    r"""\b(require_(?:admin|permission|role|staff|authenticated|login))\b""",
    re.IGNORECASE,
)

# has_permission / can_read / can_write / can_access
_HAS_PERM_RE = re.compile(
    r"""\b(has_permission|can_(?:read|write|access|delete|edit|update|view))\s*\(""",
    re.IGNORECASE,
)

# current_user.id  or  request.user.id  comparisons
_CURRENT_USER_CMP_RE = re.compile(
    r"""(?:current_user|request\.user)\.(?:id|pk|user_id|uuid|uid)\b""",
    re.IGNORECASE,
)

# FastAPI: Depends(get_current_user)
_DEPENDS_CURRENT_USER_RE = re.compile(
    r"""Depends\s*\(\s*get_current_user\s*\)""",
    re.IGNORECASE,
)

# Attacker-controllable RHS heuristics (request params, path vars)
_ATTACKER_RHS_RE = re.compile(
    r"""(?:request\.(?:GET|POST|args|json|data|form)|
         (?:params|body|query)\[|
         (?:\?|\$\{)|
         request\.params\.|
         req\.(?:params|query|body)\.|
         ctx\.params\.)""".replace("\n", "").replace(" ", ""),
    re.IGNORECASE,
)


def _is_current_user_rhs(rhs: str) -> bool:
    return bool(_CURRENT_USER_CMP_RE.search(rhs))


def _is_attacker_rhs(rhs: str) -> bool:
    return bool(_ATTACKER_RHS_RE.search(rhs))


def scan_ownership_checks(filename: str, content: str) -> list[_OwnershipMatch]:
    """Return all ownership / permission checks found in *content*.

    Parameters
    ----------
    filename:
        File path (used for context; not read from disk).
    content:
        Full text of the file.

    Returns
    -------
    list[_OwnershipMatch]
    """
    lines = content.splitlines()
    results: list[_OwnershipMatch] = []

    for i, line in enumerate(lines):
        line_no = i + 1

        # SQL ownership clause
        for m in _SQL_OWNERSHIP_RE.finditer(line):
            identifier = m.group(1)
            rhs = m.group(2).strip()
            safe = _is_current_user_rhs(rhs) and not _is_attacker_rhs(rhs)
            results.append(_OwnershipMatch(
                line=line_no,
                pattern=f"WHERE {identifier} =",
                identifier=identifier,
                current_user_derived=safe,
            ))

        # require_*
        for m in _REQUIRE_RE.finditer(line):
            results.append(_OwnershipMatch(
                line=line_no,
                pattern=m.group(1),
                identifier=m.group(1),
                current_user_derived=True,  # decorator gates are safe by design
            ))

        # has_permission / can_*
        for m in _HAS_PERM_RE.finditer(line):
            # Determine if the check uses current_user
            safe = _is_current_user_rhs(line)
            results.append(_OwnershipMatch(
                line=line_no,
                pattern=m.group(1),
                identifier=m.group(1),
                current_user_derived=safe,
            ))

        # current_user.id comparison
        if _CURRENT_USER_CMP_RE.search(line):
            results.append(_OwnershipMatch(
                line=line_no,
                pattern="current_user.id",
                identifier="current_user.id",
                current_user_derived=True,
            ))

        # FastAPI Depends(get_current_user)
        if _DEPENDS_CURRENT_USER_RE.search(line):
            results.append(_OwnershipMatch(
                line=line_no,
                pattern="Depends(get_current_user)",
                identifier="get_current_user",
                current_user_derived=True,
            ))

    return results
