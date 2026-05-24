"""Multi-scanner Layer-1 runner.

Public entry point: ``run_layer1(files, scan_id)`` spawns all available
adapters concurrently inside a per-request ``ScannerWorkspace`` and returns
a deduplicated, consensus-scored list of ``AggregatedCandidate`` objects
ready for merging with the Claude first-pass findings.

Fail-safe direction: if an adapter fails (binary missing, subprocess error,
timeout) its contribution is silently dropped — the pipeline continues with
the results from other adapters and Claude.  This matches the detect-secrets
philosophy: scanner failure → degrade gracefully, never abort.

TODO (egress policy): add a container-level NetworkPolicy that blocks egress
from scanner subprocesses at the infra level.  This module uses
``semgrep --metrics=off`` and ``npm --no-install`` as application-level
defences, but an infra NetworkPolicy is the defence-in-depth follow-up.
"""

from __future__ import annotations

import asyncio

from security_scanner.shared.logging_util import get_logger
from security_scanner.shared.scanners.consensus import aggregate
from security_scanner.shared.scanners.models import AggregatedCandidate, ScannerCandidate
from security_scanner.shared.scanners.registry import get_adapters
from security_scanner.shared.scanners.workdir import ScannerWorkspace

log = get_logger(__name__)

__all__ = ["run_layer1"]


async def run_layer1(
    files: dict[str, str],
    scan_id: str,
) -> list[AggregatedCandidate]:
    """Run all available scanner adapters concurrently and return aggregated candidates.

    Parameters
    ----------
    files:
        Dict mapping relative file path → source content (already stripped of secrets).
    scan_id:
        The current scan's UUID hex string — used as a tempdir prefix so two
        concurrent scans never share a workspace.

    Returns
    -------
    list[AggregatedCandidate]
        Consensus-scored candidates grouped by ``(file, vuln_class, line_range)``.
        Returns an empty list if no adapters are available or all fail.
    """
    if not files:
        return []

    adapters = get_adapters()
    if not adapters:
        log.warning("run_layer1: no scanner adapters available")
        return []

    all_candidates: list[ScannerCandidate] = []

    async with ScannerWorkspace(scan_id=scan_id) as workspace:
        # Write all files into the workspace.
        write_errors = 0
        for rel_path, content in files.items():
            try:
                await workspace.write_file(rel_path, content)
            except Exception as exc:  # noqa: BLE001
                write_errors += 1
                log.warning(
                    "run_layer1: skipping file (write error)",
                    file=rel_path,
                    error=type(exc).__name__,
                    error_message=str(exc),
                )
        if write_errors:
            log.warning("run_layer1: %d file(s) skipped due to write errors", write_errors)

        # Run all adapters concurrently.
        async def _run_one(adapter_name: str, adapter_fn) -> list[ScannerCandidate]:  # type: ignore[type-arg]
            try:
                return await adapter_fn(workspace)
            except Exception as exc:  # noqa: BLE001
                log.warning(
                    "run_layer1: adapter failed — skipping",
                    adapter=adapter_name,
                    error=type(exc).__name__,
                    error_message=str(exc),
                )
                return []

        tasks = [_run_one(name, fn) for name, fn in adapters.items()]
        results = await asyncio.gather(*tasks)
        for batch in results:
            all_candidates.extend(batch)

    log.info(
        "run_layer1: scanner pass complete",
        raw_candidates=len(all_candidates),
    )

    return aggregate(all_candidates)
