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
