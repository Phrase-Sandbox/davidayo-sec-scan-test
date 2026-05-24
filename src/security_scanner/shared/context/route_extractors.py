"""Heuristic regex-based route extractors for multiple frameworks.

Supports:
- Python: Flask, FastAPI, aiohttp, Django
- JavaScript/TypeScript: Express
- Go: Gin

All extractors are pure CPU, in-memory only — no I/O, no subprocesses.
"""

from __future__ import annotations

import re
from typing import NamedTuple


class _Match(NamedTuple):
    line: int       # 1-based
    method: str
    path: str
    handler: str


# ---------------------------------------------------------------------------
# Flask: @app.route('/path', methods=['GET','POST'])
#        @blueprint.route('/path')
# ---------------------------------------------------------------------------
_FLASK_ROUTE_RE = re.compile(
    r"""@(?:\w+\.)?route\s*\(\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)
_FLASK_METHODS_RE = re.compile(
    r"""methods\s*=\s*\[([^\]]+)\]""",
    re.IGNORECASE,
)
_PY_FUNC_RE = re.compile(r"""(?:async\s+)?def\s+(\w+)\s*\(""")


def _next_function_name(lines: list[str], after_line: int) -> str:
    """Return the name of the first ``def`` found on or after ``after_line`` (0-based)."""
    for i in range(after_line, min(after_line + 6, len(lines))):
        m = _PY_FUNC_RE.search(lines[i])
        if m:
            return m.group(1)
    return "<unknown>"


def extract_flask_routes(filename: str, content: str) -> list[_Match]:
    lines = content.splitlines()
    results: list[_Match] = []
    for i, line in enumerate(lines):
        m = _FLASK_ROUTE_RE.search(line)
        if not m:
            continue
        path = m.group(1)
        methods_m = _FLASK_METHODS_RE.search(line)
        if methods_m:
            raw = methods_m.group(1)
            methods = [s.strip().strip("'\"") for s in raw.split(",") if s.strip()]
        else:
            methods = ["GET"]
        handler = _next_function_name(lines, i + 1)
        for method in methods:
            results.append(_Match(line=i + 1, method=method.upper(), path=path, handler=handler))
    return results


# ---------------------------------------------------------------------------
# FastAPI: @router.get('/path')  @app.post('/path')  etc.
# ---------------------------------------------------------------------------
_FASTAPI_ROUTE_RE = re.compile(
    r"""@(?:\w+\.)?(get|post|put|delete|patch|head|options|trace)\s*\(\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)


def extract_fastapi_routes(filename: str, content: str) -> list[_Match]:
    lines = content.splitlines()
    results: list[_Match] = []
    for i, line in enumerate(lines):
        m = _FASTAPI_ROUTE_RE.search(line)
        if not m:
            continue
        method = m.group(1).upper()
        path = m.group(2)
        handler = _next_function_name(lines, i + 1)
        results.append(_Match(line=i + 1, method=method, path=path, handler=handler))
    return results


# ---------------------------------------------------------------------------
# aiohttp: app.router.add_route('GET', '/path', handler)
#          app.router.add_get('/path', handler)
#          routes.get('/path')  (RouteTableDef)
# ---------------------------------------------------------------------------
_AIOHTTP_ADD_ROUTE_RE = re.compile(
    r"""\.add_route\s*\(\s*['"](\w+)['"]\s*,\s*['"]([^'"]+)['"]\s*,\s*(\w+)""",
    re.IGNORECASE,
)
_AIOHTTP_METHOD_RE = re.compile(
    r"""\.add_(get|post|put|delete|patch|head)\s*\(\s*['"]([^'"]+)['"]\s*,\s*(\w+)""",
    re.IGNORECASE,
)
_AIOHTTP_TABLE_RE = re.compile(
    r"""@routes\.(get|post|put|delete|patch|head)\s*\(\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)


def extract_aiohttp_routes(filename: str, content: str) -> list[_Match]:
    lines = content.splitlines()
    results: list[_Match] = []
    for i, line in enumerate(lines):
        m = _AIOHTTP_ADD_ROUTE_RE.search(line)
        if m:
            results.append(_Match(
                line=i + 1, method=m.group(1).upper(),
                path=m.group(2), handler=m.group(3),
            ))
            continue
        m = _AIOHTTP_METHOD_RE.search(line)
        if m:
            results.append(_Match(
                line=i + 1, method=m.group(1).upper(),
                path=m.group(2), handler=m.group(3),
            ))
            continue
        m = _AIOHTTP_TABLE_RE.search(line)
        if m:
            handler = _next_function_name(lines, i + 1)
            results.append(_Match(
                line=i + 1, method=m.group(1).upper(),
                path=m.group(2), handler=handler,
            ))
    return results


# ---------------------------------------------------------------------------
# Django: urlpatterns = [path('/path', view_func, name='x')]
#         re_path(r'^/path$', view_func)
# ---------------------------------------------------------------------------
_DJANGO_PATH_RE = re.compile(
    r"""(?:re_)?path\s*\(\s*[r]?['"]([^'"]+)['"]\s*,\s*(\w[\w.]*)\s*""",
    re.IGNORECASE,
)


def extract_django_routes(filename: str, content: str) -> list[_Match]:
    lines = content.splitlines()
    results: list[_Match] = []
    for i, line in enumerate(lines):
        m = _DJANGO_PATH_RE.search(line)
        if not m:
            continue
        path = m.group(1)
        handler = m.group(2)
        results.append(_Match(line=i + 1, method="ANY", path=path, handler=handler))
    return results


# ---------------------------------------------------------------------------
# Express (JS/TS): app.get('/path', handler)  router.post('/path', handler)
# ---------------------------------------------------------------------------
_EXPRESS_ROUTE_RE = re.compile(
    r"""(?:app|router)\.(get|post|put|delete|patch|head|options|all)\s*\(\s*['"`]([^'"`]+)['"`]""",
    re.IGNORECASE,
)
_JS_FUNC_ARG_RE = re.compile(r""",\s*(?:async\s+)?(?:function\s+)?(\w+)\s*[,)\n{]""")


def extract_express_routes(filename: str, content: str) -> list[_Match]:
    lines = content.splitlines()
    results: list[_Match] = []
    for i, line in enumerate(lines):
        m = _EXPRESS_ROUTE_RE.search(line)
        if not m:
            continue
        method = m.group(1).upper()
        path = m.group(2)
        # Try to grab handler name from same line
        fn_m = _JS_FUNC_ARG_RE.search(line[m.end():])
        handler = fn_m.group(1) if fn_m else "<anonymous>"
        results.append(_Match(line=i + 1, method=method, path=path, handler=handler))
    return results


# ---------------------------------------------------------------------------
# Gin (Go): r.GET("/path", HandlerFunc)
# ---------------------------------------------------------------------------
_GIN_ROUTE_RE = re.compile(
    r"""(?:\w+)\.(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|Any)\s*\(\s*"([^"]+)"\s*,\s*(\w+)""",
    re.IGNORECASE,
)


def extract_gin_routes(filename: str, content: str) -> list[_Match]:
    lines = content.splitlines()
    results: list[_Match] = []
    for i, line in enumerate(lines):
        m = _GIN_ROUTE_RE.search(line)
        if not m:
            continue
        results.append(_Match(
            line=i + 1, method=m.group(1).upper(),
            path=m.group(2), handler=m.group(3),
        ))
    return results


# ---------------------------------------------------------------------------
# Dispatcher: pick extractors by filename extension.
# ---------------------------------------------------------------------------

def extract_routes(filename: str, content: str) -> list[_Match]:
    """Auto-detect framework and extract routes from *content*.

    Returns a list of ``_Match`` named-tuples.
    """
    lower = filename.lower()
    results: list[_Match] = []

    if lower.endswith(".go"):
        results.extend(extract_gin_routes(filename, content))
    elif lower.endswith((".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")):
        results.extend(extract_express_routes(filename, content))
    elif lower.endswith(".py"):
        # Try all Python frameworks; any may match.
        results.extend(extract_flask_routes(filename, content))
        results.extend(extract_fastapi_routes(filename, content))
        results.extend(extract_aiohttp_routes(filename, content))
        results.extend(extract_django_routes(filename, content))

    return results
