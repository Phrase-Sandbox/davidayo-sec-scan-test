"""Tests for the Bandit adapter."""

from __future__ import annotations

import json
import shutil

import pytest


def test_parse_output_basic() -> None:
    """Parse a minimal Bandit JSON result."""
    from security_scanner.shared.scanners.adapters.bandit import _parse_output

    data = {
        "results": [
            {
                "filename": "/tmp/workspace/app.py",
                "test_id": "B608",
                "test_name": "hardcoded_sql_expressions",
                "issue_text": "Possible SQL injection via string-based query construction.",
                "issue_severity": "HIGH",
                "issue_confidence": "MEDIUM",
                "line_number": 42,
                "line_range": [42, 43],
                "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b608_hardcoded_sql_expressions.html",
            }
        ],
        "errors": [],
    }
    candidates = _parse_output(json.dumps(data).encode(), workspace_root="/tmp/workspace")
    assert len(candidates) == 1
    c = candidates[0]
    assert c.tool == "bandit"
    assert c.vuln_class == "sqli"
    assert c.file == "app.py"
    assert c.line_start == 42
    assert c.line_end == 43


def test_parse_output_low_confidence_skipped() -> None:
    """Low-confidence findings are filtered out."""
    from security_scanner.shared.scanners.adapters.bandit import _parse_output

    data = {
        "results": [
            {
                "filename": "/tmp/ws/x.py",
                "test_id": "B608",
                "test_name": "sql",
                "issue_text": "SQL injection",
                "issue_severity": "HIGH",
                "issue_confidence": "LOW",
                "line_number": 1,
                "line_range": [1],
            }
        ],
        "errors": [],
    }
    candidates = _parse_output(json.dumps(data).encode(), workspace_root="/tmp/ws")
    assert candidates == []


def test_parse_output_malformed_json() -> None:
    """Malformed JSON produces no candidates."""
    from security_scanner.shared.scanners.adapters.bandit import _parse_output
    candidates = _parse_output(b"{broken", workspace_root="/tmp")
    assert candidates == []


@pytest.mark.asyncio
async def test_scan_skips_if_binary_missing(monkeypatch) -> None:
    """scan() returns [] when bandit binary is not on PATH."""
    import shutil as _shutil
    monkeypatch.setattr(_shutil, "which", lambda _: None)
    from security_scanner.shared.scanners.adapters.bandit import scan
    from security_scanner.shared.scanners.workdir import ScannerWorkspace

    async with ScannerWorkspace(scan_id="test-bandit-missing") as ws:
        result = await scan(ws)
    assert result == []
