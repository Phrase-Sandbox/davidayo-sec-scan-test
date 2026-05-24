"""Provider-agnostic parsing of an LLM reply into a findings list.

Moved verbatim out of ``shared/claude/client.py`` (behaviour-preserving) so
every provider parses findings identically. ``ClaudeClient`` delegates here
and injects its own ``ClaudeResponseError`` as ``error_cls`` so its public
exception type is unchanged — the existing client tests are the regression
guard.

The spec's prompt forbids markdown fences and asks for a
``{"findings": [...]}`` object; both a fenced reply and a bare top-level
array are accepted defensively.
"""

from __future__ import annotations

import json
import re

_FENCE_PREFIX_RE = re.compile(r"^```(?:json)?\s*", re.IGNORECASE)


class LLMResponseError(Exception):
    """Reply was not parseable as the expected JSON structure.

    ``ClaudeResponseError`` injects itself as ``error_cls`` so the proven
    Claude path keeps raising its own type; non-Claude providers raise this.
    """


def _extract_first_json_object(text: str) -> str:
    """Return the first balanced ``{...}`` substring in *text*.

    Claude Haiku occasionally appends trailing prose after the closing ``}``
    of its JSON response (e.g. a "Note: …" sentence).  ``json.loads`` rejects
    such input with "Extra data".  This function extracts just the first
    top-level JSON object via a brace-balance scan so the parser can tolerate
    the trailing text.

    Returns an empty string when no ``{`` is found (caller falls back to
    re-raising the original error).
    """
    start = text.find("{")
    if start == -1:
        return ""
    depth = 0
    in_string = False
    escape_next = False
    for i, ch in enumerate(text[start:], start):
        if escape_next:
            escape_next = False
            continue
        if ch == "\\" and in_string:
            escape_next = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    # Unbalanced — return empty so the caller re-raises the original error.
    return ""


def parse_findings(
    text: str,
    *,
    error_cls: type[Exception] = LLMResponseError,
) -> list[dict]:
    """Parse an LLM response into a list of finding dicts.

    Strips a defensive markdown fence, then accepts either a top-level array
    or a ``{"findings": [...]}`` object (an object with an
    ``empty_findings_note`` and no list = no findings). Any other shape, a
    JSON error, or an empty body raises ``error_cls``.

    Trailing prose after the closing ``}`` is tolerated: if ``json.loads``
    raises "Extra data", the parser retries after extracting the first
    balanced ``{...}`` substring via a brace-balance scan.  This lets models
    like Claude Haiku that append explanatory text still produce valid output.
    """
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = _FENCE_PREFIX_RE.sub("", stripped, count=1)
        if stripped.endswith("```"):
            stripped = stripped[:-3].rstrip()
    if not stripped:
        raise error_cls("Empty response body from the model")

    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError as exc:
        # If the error is "Extra data", retry after stripping the trailing prose.
        if "Extra data" in exc.msg:
            candidate = _extract_first_json_object(stripped)
            if candidate:
                try:
                    parsed = json.loads(candidate)
                except json.JSONDecodeError as inner_exc:
                    raise error_cls(
                        f"Could not parse model response as JSON: {inner_exc.msg}"
                    ) from inner_exc
            else:
                raise error_cls(
                    f"Could not parse model response as JSON: {exc.msg}"
                ) from exc
        else:
            raise error_cls(
                f"Could not parse model response as JSON: {exc.msg}"
            ) from exc

    if isinstance(parsed, dict):
        findings = parsed.get("findings")
        if isinstance(findings, list):
            return findings
        if findings is None and "empty_findings_note" in parsed:
            return []
        raise error_cls(
            f"Response object missing 'findings' list (keys: {sorted(parsed)})"
        )
    if isinstance(parsed, list):
        return parsed
    raise error_cls(f"Unexpected response shape: {type(parsed).__name__}")
