"""Tests for the scanner adapter registry — enabled filter."""

from __future__ import annotations


def test_get_adapters_enabled_none_returns_all_available(monkeypatch) -> None:
    """enabled=None (default) returns all binary-available adapters."""
    import shutil as _shutil
    monkeypatch.setattr(_shutil, "which", lambda _: "/usr/bin/tool")
    from security_scanner.shared.scanners.registry import get_adapters
    adapters = get_adapters(enabled=None)
    assert "semgrep" in adapters
    assert "bandit" in adapters
    assert "gosec" in adapters
    assert "eslint" in adapters


def test_get_adapters_enabled_subset_filters_correctly(monkeypatch) -> None:
    """enabled={"bandit"} returns only bandit when binary is present."""
    import shutil as _shutil
    monkeypatch.setattr(_shutil, "which", lambda _: "/usr/bin/tool")
    from security_scanner.shared.scanners.registry import get_adapters
    adapters = get_adapters(enabled={"bandit"})
    assert list(adapters.keys()) == ["bandit"]


def test_get_adapters_enabled_empty_set_returns_empty(monkeypatch) -> None:
    """enabled=set() returns {} — all tools disabled."""
    import shutil as _shutil
    monkeypatch.setattr(_shutil, "which", lambda _: "/usr/bin/tool")
    from security_scanner.shared.scanners.registry import get_adapters
    adapters = get_adapters(enabled=set())
    assert adapters == {}


def test_get_adapters_enabled_filters_unavailable(monkeypatch) -> None:
    """Requesting an adapter whose binary is missing still returns empty."""
    import shutil as _shutil
    monkeypatch.setattr(_shutil, "which", lambda _: None)
    from security_scanner.shared.scanners.registry import get_adapters
    adapters = get_adapters(enabled={"bandit"})
    assert adapters == {}
