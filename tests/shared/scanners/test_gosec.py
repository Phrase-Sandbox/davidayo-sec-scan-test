"""Tests for the gosec adapter."""

from __future__ import annotations

import json

import pytest


def test_parse_output_basic() -> None:
    """Parse a minimal gosec JSON result."""
    from security_scanner.shared.scanners.adapters.gosec import _parse_output

    data = {
        "Issues": [
            {
                "file": "/tmp/ws/main.go",
                "rule_id": "G201",
                "details": "SQL query construction using format string",
                "severity": "HIGH",
                "confidence": "HIGH",
                "line": "25",
            }
        ],
        "Stats": {},
    }
    candidates = _parse_output(json.dumps(data).encode(), workspace_root="/tmp/ws")
    assert len(candidates) == 1
    c = candidates[0]
    assert c.tool == "gosec"
    assert c.vuln_class == "sqli"
    assert c.file == "main.go"
    assert c.line_start == 25


def test_parse_output_line_range() -> None:
    """gosec line ranges (e.g. '25-26') are parsed correctly."""
    from security_scanner.shared.scanners.adapters.gosec import _parse_output

    data = {
        "Issues": [
            {
                "file": "/tmp/ws/handler.go",
                "rule_id": "G304",
                "details": "File path provided as taint input",
                "severity": "MEDIUM",
                "confidence": "HIGH",
                "line": "10-12",
            }
        ]
    }
    candidates = _parse_output(json.dumps(data).encode(), workspace_root="/tmp/ws")
    assert len(candidates) == 1
    assert candidates[0].line_start == 10
    assert candidates[0].line_end == 12


def test_parse_output_low_confidence_skipped() -> None:
    """Low-confidence findings are filtered."""
    from security_scanner.shared.scanners.adapters.gosec import _parse_output

    data = {
        "Issues": [
            {
                "file": "/tmp/ws/main.go",
                "rule_id": "G201",
                "details": "SQL query",
                "severity": "HIGH",
                "confidence": "LOW",
                "line": "1",
            }
        ]
    }
    candidates = _parse_output(json.dumps(data).encode(), workspace_root="/tmp/ws")
    assert candidates == []


@pytest.mark.asyncio
async def test_scan_skips_if_binary_missing(monkeypatch) -> None:
    """scan() returns [] when gosec binary is not on PATH."""
    import shutil as _shutil
    monkeypatch.setattr(_shutil, "which", lambda _: None)
    from security_scanner.shared.scanners.adapters.gosec import scan
    from security_scanner.shared.scanners.workdir import ScannerWorkspace

    async with ScannerWorkspace(scan_id="test-gosec-missing") as ws:
        result = await scan(ws)
    assert result == []
