"""ContextPackager — assembles cross-file context bundles for vulnerability candidates.

Pure CPU, in-memory only.  Runs in ``asyncio.to_thread`` to avoid blocking the
event loop.  Any extractor exception → empty bundle for that candidate (degrade,
never crash).

Token budget: ≤80 lines total across categories per bundle.
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml

from security_scanner.shared.context.callee_finder import find_callees
from security_scanner.shared.context.caller_finder import find_callers
from security_scanner.shared.context.middleware_extractors import extract_middleware
from security_scanner.shared.context.models import (
    CalleeInfo,
    CallerInfo,
    ContextBundle,
    MiddlewareInfo,
    OwnershipCheckInfo,
    RouteInfo,
)
from security_scanner.shared.context.ownership_checks import scan_ownership_checks
from security_scanner.shared.context.route_extractors import extract_routes
from security_scanner.shared.context.upload_context import extract_upload_context
from security_scanner.shared.context.upload_finder import find_upload_handlers
from security_scanner.shared.context.upload_models import UploadContext
from security_scanner.shared.logging_util import get_logger
from security_scanner.shared.scanners.types import CandidateForVerification

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# High-risk path prefixes — loaded once at module import (read-only constant).
# Env override HIGH_RISK_PATHS_FILE for tests.
# ---------------------------------------------------------------------------
_DEFAULT_YAML = Path(__file__).parent / "high_risk_paths.yaml"


def _load_high_risk_paths() -> list[str]:
    yaml_path = Path(os.environ.get("HIGH_RISK_PATHS_FILE", str(_DEFAULT_YAML)))
    try:
        with yaml_path.open() as fh:
            data = yaml.safe_load(fh)
        return [str(p) for p in (data or {}).get("high_risk_paths", [])]
    except Exception as exc:  # noqa: BLE001
        log.warning("context: failed to load high_risk_paths.yaml", error=str(exc))
        return []


HIGH_RISK_PATHS: list[str] = _load_high_risk_paths()

# ---------------------------------------------------------------------------
# Budget
# ---------------------------------------------------------------------------
_MAX_BUNDLE_LINES = 80
_MAX_SNIPPET_LINES = 30
_MAX_CALLERS = 5
_MAX_CALLEES = 10
_MAX_ROUTES = 5
_MAX_MIDDLEWARE = 10
_MAX_OWNERSHIP = 10


def is_high_risk_path(filepath: str, prefixes: list[str] | None = None) -> bool:
    """Return True if *filepath* matches any high-risk path prefix."""
    effective = prefixes if prefixes is not None else HIGH_RISK_PATHS
    lower = filepath.lower().replace("\\", "/")
    return any(lower.startswith(p.lower()) or ("/" + p.lower()) in lower
               for p in effective)


class ContextPackager:
    """Assembles ContextBundle objects for a list of candidates.

    Usage (in pipeline)::

        bundles = await asyncio.to_thread(
            ContextPackager().attach, candidates, files
        )

    The returned dict maps ``id(candidate)`` → ``ContextBundle``.
    """

    def attach(
        self,
        candidates: list[CandidateForVerification],
        files: dict[str, str],
    ) -> dict[int, ContextBundle]:
        """Build a context bundle for each candidate.

        Parameters
        ----------
        candidates:
            Merged list of LLM + scanner candidates.
        files:
            In-memory snapshot of repo files (path → content).

        Returns
        -------
        dict[int, ContextBundle]
            Keys are ``id(candidate)`` for fast O(1) lookup.
        """
        result: dict[int, ContextBundle] = {}
        for candidate in candidates:
            try:
                bundle = self._build_bundle(candidate, files)
            except Exception as exc:  # noqa: BLE001
                log.warning(
                    "context packager: extractor error — empty bundle",
                    file=candidate.file,
                    vuln_class=candidate.vuln_class,
                    error=type(exc).__name__,
                    error_message=str(exc),
                )
                bundle = ContextBundle(
                    file=candidate.file,
                    vuln_class=candidate.vuln_class,
                    snippet="",
                )
            result[id(candidate)] = bundle
        return result

    # --- internals ---

    def _build_bundle(
        self,
        candidate: CandidateForVerification,
        files: dict[str, str],
    ) -> ContextBundle:
        file_content = files.get(candidate.file, "")
        snippet = self._extract_snippet(file_content, candidate.line_start, candidate.line_end)

        routes = self._extract_routes(candidate.file, file_content, files)
        middleware = self._extract_middleware(candidate.file, file_content, files)
        callers = self._find_callers(candidate, files)
        callees = self._find_callees(snippet)
        ownership = self._find_ownership(candidate.file, files)

        # Attach upload context when candidate is an upload class OR the file
        # contains an upload handler detected by upload_finder.
        upload_ctx: UploadContext | None = None
        try:
            is_upload_class = candidate.vuln_class.lower() == "unsafe_file_upload"
            if is_upload_class:
                # Use the first upload handler found in the candidate file.
                file_handlers = find_upload_handlers({candidate.file: file_content})
                if file_handlers:
                    upload_ctx = extract_upload_context(file_handlers[0], files)
                else:
                    # No handler found — still build an empty UploadContext so
                    # the verifier knows this is an upload class.
                    upload_ctx = UploadContext()
            else:
                # Check whether this file happens to contain an upload handler.
                file_handlers = find_upload_handlers({candidate.file: file_content})
                if file_handlers:
                    upload_ctx = extract_upload_context(file_handlers[0], files)
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "context packager: upload context extraction failed",
                file=candidate.file,
                error=type(exc).__name__,
                error_message=str(exc),
            )
            upload_ctx = None

        return ContextBundle(
            file=candidate.file,
            vuln_class=candidate.vuln_class,
            snippet=snippet,
            route_definitions=tuple(routes),
            middleware_chain=tuple(middleware),
            callers=tuple(callers),
            callees=tuple(callees),
            ownership_checks=tuple(ownership),
            upload_context=upload_ctx,
        )

    def _extract_snippet(self, content: str, line_start: int, line_end: int | None) -> str:
        if not content:
            return ""
        lines = content.splitlines()
        if line_start:
            # ±8 lines: wide enough to absorb small line-number errors from the
            # first-pass LLM (off-by-one to off-by-5 is common when multiple
            # files are in the same chunk), yet still ≤ _MAX_SNIPPET_LINES (30).
            lo = max(0, line_start - 8)
            hi = min(len(lines), (line_end or line_start) + 8)
        else:
            lo, hi = 0, min(len(lines), _MAX_SNIPPET_LINES)
        snippet_lines = lines[lo:hi]
        # Truncate to budget.
        return "\n".join(snippet_lines[:_MAX_SNIPPET_LINES])

    def _extract_routes(
        self,
        filepath: str,
        content: str,
        files: dict[str, str],
    ) -> list[RouteInfo]:
        results: list[RouteInfo] = []
        # Scan the candidate file first.
        for m in extract_routes(filepath, content)[:_MAX_ROUTES]:
            results.append(RouteInfo(
                file=filepath, line=m.line, method=m.method,
                path=m.path, handler=m.handler,
            ))
        # Also scan other files if the candidate file had no routes.
        if not results:
            for fpath, fcontent in files.items():
                if fpath == filepath:
                    continue
                for m in extract_routes(fpath, fcontent):
                    results.append(RouteInfo(
                        file=fpath, line=m.line, method=m.method,
                        path=m.path, handler=m.handler,
                    ))
                    if len(results) >= _MAX_ROUTES:
                        return results
        return results[:_MAX_ROUTES]

    def _extract_middleware(
        self,
        filepath: str,
        content: str,
        files: dict[str, str],
    ) -> list[MiddlewareInfo]:
        results: list[MiddlewareInfo] = []
        for m in extract_middleware(filepath, content)[:_MAX_MIDDLEWARE]:
            results.append(MiddlewareInfo(
                file=filepath, line=m.line, name=m.name, kind=m.kind,
            ))
        return results

    def _find_callers(
        self,
        candidate: CandidateForVerification,
        files: dict[str, str],
    ) -> list[CallerInfo]:
        # Derive function name from snippet or candidate.
        file_content = files.get(candidate.file, "")
        func_name = self._extract_handler_name(file_content, candidate.line_start)
        if not func_name:
            return []
        matches = find_callers(func_name, files, max_callers=_MAX_CALLERS)
        return [
            CallerInfo(
                file=m.file, line=m.line,
                function_name=m.function_name,
                snippet=m.snippet,
            )
            for m in matches
        ]

    def _find_callees(self, snippet: str) -> list[CalleeInfo]:
        matches = find_callees(snippet)
        return [
            CalleeInfo(name=m.name, kind=m.kind)
            for m in matches[:_MAX_CALLEES]
        ]

    def _find_ownership(
        self,
        filepath: str,
        files: dict[str, str],
    ) -> list[OwnershipCheckInfo]:
        results: list[OwnershipCheckInfo] = []
        # Scan the candidate file.
        content = files.get(filepath, "")
        if content:
            for m in scan_ownership_checks(filepath, content)[:_MAX_OWNERSHIP]:
                results.append(OwnershipCheckInfo(
                    file=filepath, line=m.line, pattern=m.pattern,
                    identifier=m.identifier,
                    current_user_derived=m.current_user_derived,
                ))
        return results

    @staticmethod
    def _extract_handler_name(content: str, line_start: int) -> str:
        """Extract the function name that contains line_start."""
        if not content:
            return ""
        import re
        # Use search (not match) so we handle indented functions too.
        func_re = re.compile(r"""(?:async\s+)?def\s+(\w+)\s*\(""")
        lines = content.splitlines()
        # Scan backwards from line_start.
        target = max(0, (line_start or 1) - 1)
        for i in range(target, -1, -1):
            if i < len(lines):
                m = func_re.search(lines[i])
                if m:
                    return m.group(1)
        return ""
