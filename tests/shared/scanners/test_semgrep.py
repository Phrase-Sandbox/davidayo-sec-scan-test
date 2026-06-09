"""Tests for the Semgrep adapter."""

from __future__ import annotations

import json

import pytest

from security_scanner.shared.scanners.adapters.semgrep import _parse_output


def test_parse_output_basic() -> None:
    """Parse a minimal Semgrep JSON result."""
    data = {
        "results": [
            {
                "check_id": "python-sqli-string-format",
                "path": "app/db.py",
                "start": {"line": 15, "col": 5},
                "end": {"line": 15, "col": 40},
                "extra": {
                    "message": "SQL string format injection",
                    "severity": "ERROR",
                },
            }
        ],
        "errors": [],
    }
    stdout = json.dumps(data).encode()
    candidates = _parse_output(stdout)
    assert len(candidates) == 1
    c = candidates[0]
    assert c.tool == "semgrep"
    assert c.vuln_class == "sqli"
    assert c.file == "app/db.py"
    assert c.line_start == 15
    assert c.severity_hint == "high"


def test_parse_output_empty_results() -> None:
    """Empty results list produces no candidates."""
    data = {"results": [], "errors": []}
    candidates = _parse_output(json.dumps(data).encode())
    assert candidates == []


def test_parse_output_malformed_json() -> None:
    """Malformed JSON produces no candidates (graceful degrade)."""
    candidates = _parse_output(b"not json at all")
    assert candidates == []


def test_parse_output_missing_optional_fields() -> None:
    """Result missing optional fields is still parsed without raising."""
    data = {
        "results": [
            {
                "check_id": "python-eval-input",
                "path": "script.py",
                "start": {"line": 1},
                "end": {"line": 1},
                "extra": {},
            }
        ]
    }
    candidates = _parse_output(json.dumps(data).encode())
    assert len(candidates) == 1
    assert candidates[0].vuln_class == "code_injection"


@pytest.mark.asyncio
async def test_scan_skips_if_binary_missing(monkeypatch) -> None:
    """scan() returns [] when semgrep binary is not on PATH."""
    import shutil as _shutil

    monkeypatch.setattr(_shutil, "which", lambda _: None)
    from security_scanner.shared.scanners.adapters.semgrep import scan
    from security_scanner.shared.scanners.workdir import ScannerWorkspace

    async with ScannerWorkspace(scan_id="test-semgrep-missing") as ws:
        result = await scan(ws)
    assert result == []


@pytest.mark.asyncio
async def test_scan_empty_rules_returns_empty(monkeypatch) -> None:
    """scan(rules=set()) skips subprocess and returns [] immediately."""
    import shutil as _shutil

    monkeypatch.setattr(_shutil, "which", lambda _: "/usr/bin/semgrep")
    from security_scanner.shared.scanners.adapters.semgrep import scan
    from security_scanner.shared.scanners.workdir import ScannerWorkspace

    async with ScannerWorkspace(scan_id="test-semgrep-empty-rules") as ws:
        result = await scan(ws, rules=set())
    assert result == []


@pytest.mark.asyncio
async def test_scan_none_rules_identical_to_default(monkeypatch) -> None:
    """scan(rules=None) and scan() must use the same config-selection path."""
    import shutil as _shutil

    monkeypatch.setattr(_shutil, "which", lambda _: None)
    from security_scanner.shared.scanners.adapters.semgrep import scan
    from security_scanner.shared.scanners.workdir import ScannerWorkspace

    async with ScannerWorkspace(scan_id="test-semgrep-none-rules") as ws:
        r_default = await scan(ws)
        r_none = await scan(ws, rules=None)
    assert r_default == r_none == []
