"""Heuristic middleware / decorator extractors.

Detects:
- Python stacked decorators above route handlers (@login_required, @require_admin, etc.)
- FastAPI Depends(...) in function signatures
- Express app.use(...)
- Django MIDDLEWARE list
"""

from __future__ import annotations

import re
from typing import NamedTuple


class _MiddlewareMatch(NamedTuple):
    line: int   # 1-based
    name: str
    kind: str   # decorator | app.use | Depends | django_middleware


# ---------------------------------------------------------------------------
# Python: stacked decorators
# Matches any @decorator_name above a def line.
# ---------------------------------------------------------------------------
_DECORATOR_RE = re.compile(r"""^(\s*)@([\w.]+(?:\([^)]*\))?)\s*$""")
_DEF_RE = re.compile(r"""^(\s*)(?:async\s+)?def\s+\w+""", re.MULTILINE)
_AUTH_DECORATOR_NAMES = re.compile(
    r"""login_required|require_admin|require_staff|permission_required|
        admin_required|auth_required|authenticated|requires_auth|
        jwt_required|token_required|verify_jwt|check_permission|
        authorize|secured|protected""".replace("\n", "").replace(" ", ""),
    re.IGNORECASE,
)


def extract_python_decorators(filename: str, content: str) -> list[_MiddlewareMatch]:
    """Return all auth-related decorators stacked above def statements."""
    lines = content.splitlines()
    results: list[_MiddlewareMatch] = []
    i = 0
    while i < len(lines):
        dm = _DEF_RE.match(lines[i])
        if dm:
            # Scan backwards to collect decorators.
            j = i - 1
            while j >= 0:
                dec_m = _DECORATOR_RE.match(lines[j])
                if dec_m:
                    name = dec_m.group(2)
                    if _AUTH_DECORATOR_NAMES.search(name):
                        results.append(_MiddlewareMatch(
                            line=j + 1, name=name, kind="decorator",
                        ))
                    j -= 1
                else:
                    break
        i += 1
    return results


# ---------------------------------------------------------------------------
# FastAPI: Depends(...) in function signature — any dependency injection.
# ---------------------------------------------------------------------------
_FASTAPI_DEPENDS_RE = re.compile(
    r"""Depends\s*\(\s*([\w.]+(?:\([^)]*\))?)\s*\)""",
    re.IGNORECASE,
)


def extract_fastapi_depends(filename: str, content: str) -> list[_MiddlewareMatch]:
    lines = content.splitlines()
    results: list[_MiddlewareMatch] = []
    for i, line in enumerate(lines):
        for m in _FASTAPI_DEPENDS_RE.finditer(line):
            results.append(_MiddlewareMatch(
                line=i + 1, name=f"Depends({m.group(1)})", kind="Depends",
            ))
    return results


# ---------------------------------------------------------------------------
# Express: app.use(...)  or  router.use(...)
# ---------------------------------------------------------------------------
_EXPRESS_USE_RE = re.compile(
    r"""(?:app|router)\.use\s*\(\s*(?:['"` ][^)]*)?(\w+)\s*\)""",
    re.IGNORECASE,
)


def extract_express_middleware(filename: str, content: str) -> list[_MiddlewareMatch]:
    lines = content.splitlines()
    results: list[_MiddlewareMatch] = []
    for i, line in enumerate(lines):
        m = _EXPRESS_USE_RE.search(line)
        if m:
            results.append(_MiddlewareMatch(
                line=i + 1, name=m.group(1), kind="app.use",
            ))
    return results


# ---------------------------------------------------------------------------
# Django: MIDDLEWARE = [...] list
# ---------------------------------------------------------------------------
_DJANGO_MW_LIST_START_RE = re.compile(r"""MIDDLEWARE\s*=\s*\[""")
_DJANGO_MW_ENTRY_RE = re.compile(r"""['"]([\w.]+)['"]""")


def extract_django_middleware(filename: str, content: str) -> list[_MiddlewareMatch]:
    lines = content.splitlines()
    results: list[_MiddlewareMatch] = []
    in_list = False
    for i, line in enumerate(lines):
        if not in_list:
            if _DJANGO_MW_LIST_START_RE.search(line):
                in_list = True
        else:
            if "]" in line:
                break
            for m in _DJANGO_MW_ENTRY_RE.finditer(line):
                results.append(_MiddlewareMatch(
                    line=i + 1, name=m.group(1), kind="django_middleware",
                ))
    return results


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def extract_middleware(filename: str, content: str) -> list[_MiddlewareMatch]:
    """Auto-detect framework and extract middleware from *content*."""
    lower = filename.lower()
    results: list[_MiddlewareMatch] = []

    if lower.endswith(".py"):
        results.extend(extract_python_decorators(filename, content))
        results.extend(extract_fastapi_depends(filename, content))
        if "settings" in lower or "config" in lower:
            results.extend(extract_django_middleware(filename, content))
    elif lower.endswith((".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")):
        results.extend(extract_express_middleware(filename, content))

    return results
