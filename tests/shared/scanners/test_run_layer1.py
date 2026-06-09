"""Tests for run_layer1 — enabled_adapters and semgrep_rules kwargs."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest


@pytest.mark.asyncio
async def test_run_layer1_empty_files_returns_empty() -> None:
    """No files → returns [] without touching adapters."""
    from security_scanner.shared.scanners import run_layer1

    result = await run_layer1({}, scan_id="test-empty")
    assert result == []


@pytest.mark.asyncio
async def test_run_layer1_no_adapters_enabled_returns_empty(monkeypatch) -> None:
    """enabled_adapters=set() means all tools disabled → returns []."""
    import shutil as _shutil
    monkeypatch.setattr(_shutil, "which", lambda _: "/usr/bin/tool")

    from security_scanner.shared.scanners import run_layer1

    result = await run_layer1(
        {"app.py": "x = 1"},
        scan_id="test-no-adapters",
        enabled_adapters=set(),
    )
    assert result == []


@pytest.mark.asyncio
async def test_run_layer1_enabled_adapters_filters_to_subset(monkeypatch) -> None:
    """Only the named adapter runs; others are excluded."""
    import shutil as _shutil
    monkeypatch.setattr(_shutil, "which", lambda _: "/usr/bin/tool")

    mock_bandit = AsyncMock(return_value=[])

    with patch("security_scanner.shared.scanners.get_adapters", return_value={"bandit": mock_bandit}) as mock_ga:
        from security_scanner.shared.scanners import run_layer1

        await run_layer1(
            {"app.py": "import os"},
            scan_id="test-subset",
            enabled_adapters={"bandit"},
        )
        mock_ga.assert_called_once_with(enabled={"bandit"})
        mock_bandit.assert_awaited_once()


@pytest.mark.asyncio
async def test_run_layer1_semgrep_rules_wraps_with_partial(monkeypatch) -> None:
    """semgrep_rules kwarg is forwarded to the semgrep adapter via functools.partial."""
    captured_rules: list = []

    async def mock_semgrep(workspace, *, rules=None):
        captured_rules.append(rules)
        return []

    with patch(
        "security_scanner.shared.scanners.get_adapters",
        return_value={"semgrep": mock_semgrep},
    ):
        from security_scanner.shared.scanners import run_layer1

        await run_layer1(
            {"app.py": "x = 1"},
            scan_id="test-semgrep-rules",
            semgrep_rules={"owasp"},
        )

    assert captured_rules == [{"owasp"}]


@pytest.mark.asyncio
async def test_run_layer1_semgrep_rules_none_does_not_wrap(monkeypatch) -> None:
    """When semgrep_rules=None the adapter is called without the rules kwarg."""
    captured_rules: list = []

    async def mock_semgrep(workspace, *, rules=None):
        captured_rules.append(rules)
        return []

    with patch(
        "security_scanner.shared.scanners.get_adapters",
        return_value={"semgrep": mock_semgrep},
    ):
        from security_scanner.shared.scanners import run_layer1

        await run_layer1(
            {"app.py": "x = 1"},
            scan_id="test-semgrep-no-rules",
            semgrep_rules=None,
        )

    # None is the default — adapter is called with rules=None (un-wrapped)
    assert captured_rules == [None]
