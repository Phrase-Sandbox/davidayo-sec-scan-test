"""Structured JSON logging to stdout with mandatory redaction of source-code fields.

Per spec §11 and CLAUDE.md: never log raw source code, prompt payloads, or file
contents. Field names listed in ``REDACT_FIELDS`` are always replaced with the
sentinel ``"[REDACTED]"`` before the log line is emitted, regardless of caller
intent.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

REDACT_FIELDS: frozenset[str] = frozenset(
    {"content", "source_code", "code", "file_content", "prompt", "payload"}
)
REDACTED_VALUE = "[REDACTED]"

# LogRecord attributes that are NOT structured fields supplied by the caller.
# Anything not in this set is treated as caller-supplied context.
_STANDARD_RECORD_ATTRS: frozenset[str] = frozenset(
    {
        "args", "asctime", "created", "exc_info", "exc_text", "filename",
        "funcName", "levelname", "levelno", "lineno", "message", "module",
        "msecs", "msg", "name", "pathname", "process", "processName",
        "relativeCreated", "stack_info", "thread", "threadName", "taskName",
    }
)

# Names that already exist on LogRecord — passing any of these via ``extra=``
# raises ``KeyError`` from Python's logging library. We transparently rename
# them with a ``ctx_`` prefix so callers can use natural field names without
# having to memorise the LogRecord attribute list.
_RESERVED_RECORD_KEYS: frozenset[str] = _STANDARD_RECORD_ATTRS


def _safe_extra(fields: dict[str, Any]) -> dict[str, Any]:
    return {(f"ctx_{k}" if k in _RESERVED_RECORD_KEYS else k): v for k, v in fields.items()}


class JSONFormatter(logging.Formatter):
    """Emit one JSON object per record on stdout; redact sensitive fields."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key in _STANDARD_RECORD_ATTRS or key.startswith("_"):
                continue
            payload[key] = REDACTED_VALUE if key in REDACT_FIELDS else value
        return json.dumps(payload, default=str)


class StructuredLogger:
    """Thin wrapper over ``logging.Logger`` exposing ``info(msg, **fields)`` semantics."""

    def __init__(self, name: str, level: str = "INFO") -> None:
        self._logger = logging.getLogger(name)
        if not any(isinstance(h, _StdoutHandler) for h in self._logger.handlers):
            handler = _StdoutHandler()
            handler.setFormatter(JSONFormatter())
            self._logger.addHandler(handler)
        self._logger.setLevel(level)
        # Stop propagation so the root logger's default StreamHandler (which
        # writes to stderr in plain text) never re-emits our records.
        self._logger.propagate = False

    def debug(self, message: str, **fields: Any) -> None:
        self._logger.debug(message, extra=_safe_extra(fields))

    def info(self, message: str, **fields: Any) -> None:
        self._logger.info(message, extra=_safe_extra(fields))

    def warning(self, message: str, **fields: Any) -> None:
        self._logger.warning(message, extra=_safe_extra(fields))

    def error(self, message: str, **fields: Any) -> None:
        self._logger.error(message, extra=_safe_extra(fields))


class _StdoutHandler(logging.Handler):
    """Handler that writes one line per record to the *current* ``sys.stdout``.

    The stream is looked up at emit time rather than construction time so that
    callers (and tests using ``capsys``) can redirect stdout after the logger
    has been created. A traditional ``logging.StreamHandler(sys.stdout)`` binds
    the stream at construction and would bypass pytest's stdout patching.
    """

    def emit(self, record: logging.LogRecord) -> None:
        try:
            sys.stdout.write(self.format(record) + "\n")
            sys.stdout.flush()
        except Exception:  # pragma: no cover — handler error path
            self.handleError(record)


def get_logger(name: str = "security_scanner", level: str = "INFO") -> StructuredLogger:
    """Return a configured ``StructuredLogger`` for the given module name."""
    return StructuredLogger(name, level)
