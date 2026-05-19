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
