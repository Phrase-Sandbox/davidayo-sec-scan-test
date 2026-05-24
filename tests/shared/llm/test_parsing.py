"""The shared provider-agnostic findings parser (D-15).

These mirror the behaviour the old in-`client.py` parser had — the existing
`tests/shared/claude/test_client.py` parse tests are the regression guard
that `ClaudeClient` still raises `ClaudeResponseError` through this.
"""

import pytest

from security_scanner.shared.llm.parsing import LLMResponseError, parse_findings


def test_top_level_array():
    assert parse_findings('[{"a": 1}]') == [{"a": 1}]


def test_findings_object():
    assert parse_findings('{"findings": [{"x": 1}]}') == [{"x": 1}]


def test_empty_findings_note_means_no_findings():
    assert parse_findings('{"empty_findings_note": "nothing found"}') == []


def test_fenced_json_block_is_stripped():
    assert parse_findings('```json\n{"findings": []}\n```') == []


def test_empty_body_raises():
    with pytest.raises(LLMResponseError):
        parse_findings("   ")


def test_bad_json_raises():
    with pytest.raises(LLMResponseError):
        parse_findings("not json at all")


def test_missing_findings_key_raises():
    with pytest.raises(LLMResponseError):
        parse_findings('{"other_key": 1}')


def test_unexpected_shape_raises():
    with pytest.raises(LLMResponseError):
        parse_findings("123")


def test_injected_error_cls_is_used():
    class Boom(Exception):
        pass

    with pytest.raises(Boom):
        parse_findings("", error_cls=Boom)


# ---------------------------------------------------------------------------
# Trailing-prose tolerance (Fix #2 — Claude Haiku extra-data regression).
# ---------------------------------------------------------------------------


def test_trailing_prose_after_findings_object_is_tolerated():
    """A valid JSON object followed by trailing prose must parse successfully.

    Claude Haiku sometimes appends explanatory text after the closing ``}``
    which previously caused ``json.JSONDecodeError: Extra data``.
    """
    payload = (
        '{"findings": [{"type": "auth_bypass", "file": "routes.py"}]}'
        "\n\nNote: this is a clear case of IDOR — the route does not check ownership."
    )
    result = parse_findings(payload)
    assert len(result) == 1
    assert result[0]["type"] == "auth_bypass"


def test_trailing_prose_after_empty_findings_note_is_tolerated():
    """Empty-findings response with trailing prose must return empty list."""
    payload = (
        '{"empty_findings_note": "no issues found"}'
        "\n\nThe code looks clean."
    )
    result = parse_findings(payload)
    assert result == []


def test_top_level_array_still_parses_without_trailing_prose():
    """Bare array responses (no top-level object) continue to work."""
    assert parse_findings('[{"vuln": "sqli"}]') == [{"vuln": "sqli"}]
