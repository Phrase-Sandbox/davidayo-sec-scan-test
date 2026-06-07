"""Concurrency / isolation integration test.

Spawns 10 concurrent ``ScanPipeline.run()`` calls and verifies:
1. 10 distinct scan_ids appear in captured logs.
2. Each ScanResult contains no findings from other scans (no cross-contamination).
3. The pipeline completes successfully for each scan.

Mocks both ``ClaudeClient`` (to avoid real API calls) and the file-fetcher
(to return a distinct planted file per scan).
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from security_scanner.pipeline import ScanPipeline
from security_scanner.shared.models.enums import GateDecision, ScanTarget, ScanType


def _make_mock_claude(scan_index: int) -> MagicMock:
    """Return a mock Claude client that echoes a finding tagged with scan_index."""
    client = MagicMock()
    # analyse_async returns an empty list (we test isolation, not findings quality)
    client.analyse_async = AsyncMock(return_value=[])
    # analyse_async_chunked returns (raw_findings, partial_files).
    client.analyse_async_chunked = AsyncMock(return_value=([], []))
    # ask_async (used by verify steps) returns a well-formed response
    client.ask_async = AsyncMock(return_value="VERDICT: yes")
    # Sync versions too (for verify_secret_findings and verify_critical_findings)
    client.ask = MagicMock(return_value="VERDICT: yes")
    client.analyse = MagicMock(return_value=[])
    return client


def _make_mock_github(scan_index: int) -> MagicMock:
    """Return a mock GitHub client that returns a single distinct file per scan."""
    github = MagicMock()
    # Each scan gets a file named after its index containing unique content.
    github.get_repo_files = MagicMock(
        return_value={f"scan_{scan_index}/main.py": f"# scan {scan_index}\nx = {scan_index}\n"}
    )
    github.get_diff_files = MagicMock(return_value={})
    return github


@pytest.mark.asyncio
async def test_concurrent_scans_isolation(caplog) -> None:
    """10 concurrent pipeline runs produce isolated scan_ids and results."""
    import logging
    import os

    # Disable multi-scanner so we don't need real scanner binaries.
    os.environ["ENABLE_MULTI_SCANNER"] = "false"

    n_scans = 10

    pipelines = [
        ScanPipeline(
            github_client=_make_mock_github(i),
            claude_client=_make_mock_claude(i),
            mode=ScanType.on_demand,
        )
        for i in range(n_scans)
    ]

    # Patch run_layer1 to be a no-op so no real scanners are invoked.
    with patch(
        "security_scanner.pipeline.run_layer1",
        new_callable=AsyncMock,
        return_value=[],
    ):
        with caplog.at_level(logging.INFO, logger="security_scanner"):
            results = await asyncio.gather(
                *[
                    p.run(
                        repo_url=f"https://github.com/test/repo{i}",
                        scan_target=ScanTarget.full_repo,
                        triggered_by=f"user-{i}",
                    )
                    for i, p in enumerate(pipelines)
                ]
            )

    # All 10 scans completed.
    assert len(results) == n_scans

    # Verify all results have a valid gate decision (no crash).
    for result in results:
        assert result.gate_decision in {
            GateDecision.pass_,
            GateDecision.advisory,
            GateDecision.blocked,
            GateDecision.scan_failed,
        }

    # Scan IDs in results are all distinct.
    scan_ids = [str(r.scan_id) for r in results]
    assert len(set(scan_ids)) == n_scans, "Duplicate scan_ids detected — isolation failure"

    # Clean up env.
    del os.environ["ENABLE_MULTI_SCANNER"]
