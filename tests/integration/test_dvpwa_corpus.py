"""End-to-end corpus test against the dvpwa (Damn Vulnerable Python Web App).

The dvpwa application at ``asdfg/dvpwa/`` contains known SQLi and weak-crypto
(MD5 passwords) vulnerabilities.  This test:
1. Loads the dvpwa Python source files.
2. Runs the Layer-1 scanner pass directly (no pipeline, no real LLM).
3. For the mock LLM path, asserts that if bandit is available it finds at
   least the MD5 usage (weak_crypto) and that the merge/consensus logic works.

The test skips if bandit is not installed (mirrors the graceful-degrade approach).
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

_DVPWA_DIR = Path(__file__).parents[2] / "asdfg" / "dvpwa"

_REQUIRED_BANDIT = pytest.mark.skipif(
    shutil.which("bandit") is None,
    reason="bandit binary not installed",
)


@pytest.mark.asyncio
@_REQUIRED_BANDIT
async def test_bandit_finds_weak_crypto_in_dvpwa() -> None:
    """Bandit finds the MD5 usage in dvpwa/sqli/dao/user.py."""
    from security_scanner.shared.scanners.adapters.bandit import scan
    from security_scanner.shared.scanners.workdir import ScannerWorkspace

    # Collect all .py files from dvpwa.
    files: dict[str, str] = {}
    for py_file in _DVPWA_DIR.rglob("*.py"):
        rel = py_file.relative_to(_DVPWA_DIR)
        try:
            files[str(rel)] = py_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

    if not files:
        pytest.skip("No .py files found in dvpwa directory")

    async with ScannerWorkspace(scan_id="dvpwa-corpus-test") as ws:
        for rel_path, content in files.items():
            try:
                await ws.write_file(rel_path, content)
            except Exception:  # noqa: BLE001
                pass  # skip files that fail safety checks

        candidates = await scan(ws)

    # Find weak_crypto findings (MD5 usage).
    weak_crypto = [c for c in candidates if c.vuln_class == "weak_crypto"]

    # There should be at least one (the md5 in user.py).
    assert len(weak_crypto) >= 1, (
        f"Expected at least 1 weak_crypto finding from dvpwa; "
        f"got {len(weak_crypto)}. All candidates: {[c.raw_rule_id for c in candidates]}"
    )


@pytest.mark.asyncio
async def test_run_layer1_returns_list_with_no_binaries(monkeypatch) -> None:
    """run_layer1 returns an empty list gracefully when no scanner binaries exist."""
    import shutil as _shutil

    monkeypatch.setattr(_shutil, "which", lambda _: None)

    from security_scanner.shared.scanners import run_layer1

    files = {"dummy.py": "x = 1"}
    result = await run_layer1(files, scan_id="test-no-binaries")
    assert result == []


@pytest.mark.asyncio
async def test_consensus_score_set_when_multiple_tools_agree() -> None:
    """When two tools flag the same location the consensus_score >= 2."""
    from security_scanner.shared.scanners.consensus import aggregate
    from security_scanner.shared.scanners.models import ScannerCandidate

    cands = [
        ScannerCandidate(
            tool="bandit",
            vuln_class="sqli",
            file="app.py",
            line_start=42,
            line_end=42,
            message="SQL injection",
            raw_rule_id="B608",
        ),
        ScannerCandidate(
            tool="semgrep",
            vuln_class="sqli",
            file="app.py",
            line_start=42,
            line_end=43,
            message="SQL injection via format string",
            raw_rule_id="python-sqli-string-format",
        ),
    ]
    aggregated = aggregate(cands)
    assert len(aggregated) == 1
    assert aggregated[0].consensus_score == 2
    assert set(aggregated[0].sources) == {"bandit", "semgrep"}
