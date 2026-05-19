"""Tests for the stdout-only structured logger and its redaction guarantee."""

from __future__ import annotations

import json
import logging

import pytest

from security_scanner.shared.logging_util import (
    REDACT_FIELDS,
    REDACTED_VALUE,
    JSONFormatter,
    StructuredLogger,
    get_logger,
)


@pytest.fixture(autouse=True)
def _reset_logger_handlers():
    """Clear handlers between tests so each test gets a clean logger state."""
    yield
    for name in list(logging.root.manager.loggerDict):
        logging.getLogger(name).handlers.clear()


def _emit_and_capture(logger_name: str, capsys, level: str = "INFO") -> dict:
    """Emit one info() call and return the parsed JSON line from stdout."""
    logger = get_logger(logger_name, level=level)
    logger.info("hello", scan_id="abc-123")
    captured = capsys.readouterr().out.strip()
    return json.loads(captured.splitlines()[-1])


def test_emits_valid_json_to_stdout(capsys):
    line = _emit_and_capture("test.emit_json", capsys)
    assert line["level"] == "INFO"
    assert line["message"] == "hello"
    assert line["scan_id"] == "abc-123"


def test_timestamp_is_iso8601_utc(capsys):
    line = _emit_and_capture("test.timestamp", capsys)
    assert line["timestamp"].endswith("+00:00")


def test_structured_logger_levels_all_route_through_handler(capsys):
    logger = get_logger("test.levels", level="DEBUG")
    logger.debug("d")
    logger.info("i")
    logger.warning("w")
    logger.error("e")
    lines = [json.loads(line) for line in capsys.readouterr().out.strip().splitlines()]
    assert [line["level"] for line in lines] == ["DEBUG", "INFO", "WARNING", "ERROR"]


@pytest.mark.parametrize("field_name", sorted(REDACT_FIELDS))
def test_redacted_fields_are_replaced_regardless_of_value_type(field_name, capsys):
    logger = get_logger(f"test.redact.{field_name}")
    logger.info("with secret", **{field_name: "this is the secret payload"})
    line = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert line[field_name] == REDACTED_VALUE


def test_non_redacted_fields_pass_through_unchanged(capsys):
    logger = get_logger("test.passthrough")
    logger.info(
        "scan started",
        scan_id="s-1",
        repo_url="https://github.com/Phrase-Launchpad/x",
        finding_count=3,
    )
    line = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert line["scan_id"] == "s-1"
    assert line["repo_url"] == "https://github.com/Phrase-Launchpad/x"
    assert line["finding_count"] == 3


def test_repeated_get_logger_does_not_duplicate_handlers(capsys):
    """Calling get_logger twice for the same name must not double the output."""
    get_logger("test.no_dupes")
    get_logger("test.no_dupes")
    logger = get_logger("test.no_dupes")
    logger.info("once")
    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 1


def test_logger_does_not_propagate_to_root(capsys):
    """Records must not bubble up to the root logger (which writes plain text to stderr)."""
    logger = StructuredLogger("test.no_propagate")
    assert logger._logger.propagate is False  # noqa: SLF001 — direct check of contract


def test_formatter_handles_log_record_directly():
    """JSONFormatter.format() must work on a hand-built LogRecord."""
    record = logging.LogRecord(
        name="x",
        level=logging.INFO,
        pathname="x.py",
        lineno=1,
        msg="hi",
        args=(),
        exc_info=None,
    )
    record.scan_id = "abc"
    record.content = "should be redacted"
    output = json.loads(JSONFormatter().format(record))
    assert output["message"] == "hi"
    assert output["scan_id"] == "abc"
    assert output["content"] == REDACTED_VALUE
