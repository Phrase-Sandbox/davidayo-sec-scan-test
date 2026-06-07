"""Unit tests for scanner_runs_total metric emission (Fix #4).

Each scanner adapter must call
``scanner_runs_total.labels(tool=TOOL, outcome=...).inc()`` after every
subprocess invocation — success, timeout, or error.  These tests mock
``run_scanner`` so no real subprocess is started, then read the Prometheus
registry directly to assert the counter incremented.

The REGISTRY helper ``get_sample_value`` is flagged as "intended only for
use in unittests" — that is exactly this use-case.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from prometheus_client import REGISTRY

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _counter_value(tool: str, outcome: str) -> float:
    """Read the current value of scanner_runs_total{tool, outcome}.

    prometheus_client adds a ``_total`` suffix for Counters in some versions.
    Try both names so tests run on any compatible version.
    """
    for metric_name in ("scanner_runs_total_total", "scanner_runs_total"):
        val = REGISTRY.get_sample_value(
            metric_name,
            labels={"tool": tool, "outcome": outcome},
        )
        if val is not None:
            return float(val)
    return 0.0


def _fake_workspace(root) -> MagicMock:
    """Return a mock ScannerWorkspace whose .root points at *root*."""
    ws = MagicMock()
    ws.root = root
    return ws


# ---------------------------------------------------------------------------
# Semgrep adapter
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_semgrep_success_increments_counter(tmp_path):
    """semgrep adapter emits outcome=success after a clean subprocess run."""
    from security_scanner.shared.scanners.adapters.semgrep import TOOL, scan

    # Stub out binary + config existence checks.
    with (
        patch("shutil.which", return_value="/usr/bin/semgrep"),
        patch(
            "security_scanner.shared.scanners.adapters.semgrep._OWASP_CONFIG"
        ) as mock_owasp,
        patch(
            "security_scanner.shared.scanners.adapters.semgrep._AUDIT_CONFIG"
        ) as mock_audit,
        patch(
            "security_scanner.shared.scanners.adapters.semgrep._UPLOAD_CONFIG"
        ) as mock_upload,
        patch(
            "security_scanner.shared.scanners.adapters.semgrep.run_scanner",
            new=AsyncMock(return_value=(0, b'{"results": []}', b"")),
        ),
    ):
        mock_owasp.exists.return_value = True
        mock_audit.exists.return_value = True
        mock_upload.exists.return_value = False

        before = _counter_value(TOOL, "success")
        ws = _fake_workspace(tmp_path)
        await scan(ws)
        after = _counter_value(TOOL, "success")

    assert after == before + 1.0


@pytest.mark.asyncio
async def test_semgrep_timeout_increments_counter(tmp_path):
    """semgrep adapter emits outcome=timeout when subprocess times out."""
    from security_scanner.shared.scanners.adapters.semgrep import TOOL, scan
    from security_scanner.shared.scanners.subprocess_runner import ScannerTimeout

    with (
        patch("shutil.which", return_value="/usr/bin/semgrep"),
        patch(
            "security_scanner.shared.scanners.adapters.semgrep._OWASP_CONFIG"
        ) as mock_owasp,
        patch(
            "security_scanner.shared.scanners.adapters.semgrep._AUDIT_CONFIG"
        ) as mock_audit,
        patch(
            "security_scanner.shared.scanners.adapters.semgrep._UPLOAD_CONFIG"
        ) as mock_upload,
        patch(
            "security_scanner.shared.scanners.adapters.semgrep.run_scanner",
            new=AsyncMock(side_effect=ScannerTimeout("too slow")),
        ),
    ):
        mock_owasp.exists.return_value = True
        mock_audit.exists.return_value = True
        mock_upload.exists.return_value = False

        before = _counter_value(TOOL, "timeout")
        ws = _fake_workspace(tmp_path)
        await scan(ws)
        after = _counter_value(TOOL, "timeout")

    assert after == before + 1.0


# ---------------------------------------------------------------------------
# Bandit adapter
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bandit_success_increments_counter(tmp_path):
    """bandit adapter emits outcome=success after a clean subprocess run."""
    from security_scanner.shared.scanners.adapters.bandit import TOOL, scan

    # Create a .py file so bandit doesn't skip early.
    (tmp_path / "dummy.py").write_text("x = 1\n")

    with (
        patch("shutil.which", return_value="/usr/bin/bandit"),
        patch(
            "security_scanner.shared.scanners.adapters.bandit.run_scanner",
            new=AsyncMock(return_value=(0, b'{"results": []}', b"")),
        ),
    ):
        before = _counter_value(TOOL, "success")
        ws = _fake_workspace(tmp_path)
        await scan(ws)
        after = _counter_value(TOOL, "success")

    assert after == before + 1.0


# ---------------------------------------------------------------------------
# ESLint adapter
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_eslint_success_increments_counter(tmp_path):
    """eslint adapter emits outcome=success after a clean subprocess run."""
    from security_scanner.shared.scanners.adapters.eslint_security import TOOL, scan

    # Create a .js file so eslint doesn't skip early.
    (tmp_path / "app.js").write_text("var x = 1;\n")

    with (
        patch(
            "security_scanner.shared.scanners.adapters.eslint_security._ESLINT_CONFIG"
        ) as mock_cfg,
        patch("shutil.which", return_value="/usr/bin/eslint"),
        patch(
            "security_scanner.shared.scanners.adapters.eslint_security.run_scanner",
            new=AsyncMock(return_value=(0, b"[]", b"")),
        ),
    ):
        mock_cfg.exists.return_value = True

        before = _counter_value(TOOL, "success")
        ws = _fake_workspace(tmp_path)
        await scan(ws)
        after = _counter_value(TOOL, "success")

    assert after == before + 1.0


# ---------------------------------------------------------------------------
# gosec adapter
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gosec_success_increments_counter(tmp_path):
    """gosec adapter emits outcome=success after a clean subprocess run."""
    from security_scanner.shared.scanners.adapters.gosec import TOOL, scan

    # Create a .go file so gosec doesn't skip early.
    (tmp_path / "main.go").write_text("package main\n")

    with (
        patch("shutil.which", return_value="/usr/bin/gosec"),
        patch(
            "security_scanner.shared.scanners.adapters.gosec.run_scanner",
            new=AsyncMock(return_value=(0, b'{"Issues": []}', b"")),
        ),
    ):
        before = _counter_value(TOOL, "success")
        ws = _fake_workspace(tmp_path)
        await scan(ws)
        after = _counter_value(TOOL, "success")

    assert after == before + 1.0
