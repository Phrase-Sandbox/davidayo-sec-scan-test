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
import functools

from security_scanner.shared.context.upload_finder import find_upload_handlers
from security_scanner.shared.context.upload_models import UploadHandler
from security_scanner.shared.logging_util import get_logger
from security_scanner.shared.scanners.consensus import aggregate
from security_scanner.shared.scanners.models import AggregatedCandidate, ScannerCandidate
from security_scanner.shared.scanners.registry import get_adapters
from security_scanner.shared.scanners.workdir import ScannerWorkspace

log = get_logger(__name__)

__all__ = ["run_layer1"]

# ---------------------------------------------------------------------------
# Synthetic candidate generation helpers
# ---------------------------------------------------------------------------

import re as _re  # noqa: E402

_SYNTH_TOOL = "upload_synth"

# Patterns for "weak signals" used to decide whether to synthesise a candidate.
# A handler with ≥2 of these weak signals and no scanner rule fired gets a
# synthetic ScannerCandidate.

_WEAK_EXT_ALLOWLIST = _re.compile(
    r"ALLOWED_EXTENSIONS|allowed_ext|extension\s+in\s+[\[{(]|splitext.*\[[-12]\]\s+in",
    _re.IGNORECASE,
)
_WEAK_SIZE_LIMIT = _re.compile(
    r"MAX_CONTENT_LENGTH|MAX_FILE_SIZE|maxFileSize|limits\s*:\s*\{|fileSize\s*:",
    _re.IGNORECASE,
)
_WEAK_SERVER_FILENAME = _re.compile(
    r"uuid\.uuid4\(\)|secrets\.token_hex|secure_filename|token_urlsafe",
    _re.IGNORECASE,
)
_WEAK_PUBLIC_STORAGE = _re.compile(
    r"['\"/](static|public|uploads|media|wwwroot)/",
    _re.IGNORECASE,
)
_WEAK_ARCHIVE_EXTRACT = _re.compile(
    r"\.extractall\s*\(",
    _re.IGNORECASE,
)
_WEAK_MAGIC_BYTES = _re.compile(
    r"python.magic|filetype\.guess|magic\.from_buffer|imghdr\.",
    _re.IGNORECASE,
)


def _count_weak_signals(handler: UploadHandler, files: dict[str, str]) -> int:
    """Return the number of *absent* defences (weak signals indicating risk).

    Each absent defence counts as one weak signal.  The caller synthesises a
    candidate when the count is ≥ 2.
    """
    content = files.get(handler.file, "")
    # Take a window around the handler line.
    lines = content.splitlines()
    lo = max(0, handler.line - 30 - 1)
    hi = min(len(lines), handler.line + 60)
    window = "\n".join(lines[lo:hi])

    weak_count = 0
    # Absent extension allowlist → weak signal.
    if not _WEAK_EXT_ALLOWLIST.search(window):
        weak_count += 1
    # Absent size limit → weak signal.
    if not _WEAK_SIZE_LIMIT.search(window):
        weak_count += 1
    # Preserved (attacker) filename + public storage → weak signal.
    has_preserved = bool(_re.search(r"\.filename\b|\.originalname\b", window, _re.IGNORECASE))
    has_public = bool(_WEAK_PUBLIC_STORAGE.search(window))
    if has_preserved and has_public:
        weak_count += 1
    # Archive extraction without magic-byte check → weak signal.
    if _WEAK_ARCHIVE_EXTRACT.search(window) and not _WEAK_MAGIC_BYTES.search(window):
        weak_count += 1

    return weak_count


def _synthesise_candidates(
    handlers: list[UploadHandler],
    files: dict[str, str],
    fired_files: set[str],
) -> list[ScannerCandidate]:
    """Return synthetic ScannerCandidates for handlers with ≥2 weak signals.

    Only handlers in files where no scanner rule already fired for
    ``unsafe_file_upload`` are synthesised (to avoid double-counting).
    """
    synth: list[ScannerCandidate] = []
    for handler in handlers:
        # Skip if a scanner rule already covered this file.
        if handler.file in fired_files:
            continue
        weak = _count_weak_signals(handler, files)
        if weak >= 2:
            synth.append(
                ScannerCandidate(
                    tool=_SYNTH_TOOL,
                    vuln_class="unsafe_file_upload",
                    file=handler.file,
                    line_start=handler.line,
                    line_end=handler.line,
                    message=(
                        f"Synthetic upload candidate: upload handler at "
                        f"{handler.file}:{handler.line} ({handler.framework}) "
                        f"has {weak} weak security signal(s). No scanner rule fired."
                    ),
                    raw_rule_id="upload_synth",
                    severity_hint="medium",
                )
            )
    return synth


async def run_layer1(
    files: dict[str, str],
    scan_id: str,
    *,
    enabled_adapters: set[str] | None = None,
    semgrep_rules: set[str] | None = None,
) -> list[AggregatedCandidate]:
    """Run all available scanner adapters concurrently and return aggregated candidates.

    Parameters
    ----------
    files:
        Dict mapping relative file path → source content (already stripped of secrets).
    scan_id:
        The current scan's UUID hex string — used as a tempdir prefix so two
        concurrent scans never share a workspace.
    enabled_adapters:
        When ``None`` (default), all binary-available adapters run. Pass a set of
        adapter names (``"semgrep"``, ``"bandit"``, ``"gosec"``, ``"eslint"``) to
        restrict which adapters execute for this scan.
    semgrep_rules:
        When ``None`` (default), Semgrep runs all rule packs. Pass a set of
        rule-pack names (``"owasp"``, ``"audit"``, ``"upload"``) to restrict which
        Semgrep configs are used.

    Returns
    -------
    list[AggregatedCandidate]
        Consensus-scored candidates grouped by ``(file, vuln_class, line_range)``.
        Returns an empty list if no adapters are available or all fail.
    """
    if not files:
        return []

    adapters = get_adapters(enabled=enabled_adapters)
    if not adapters:
        log.warning("run_layer1: no scanner adapters available")
        return []

    # Bind semgrep rule-pack selection for this scan only.
    # functools.partial of an async fn returns a coroutine when called — works
    # transparently with `await adapter_fn(workspace)` in _run_one below.
    if "semgrep" in adapters and semgrep_rules is not None:
        adapters["semgrep"] = functools.partial(adapters["semgrep"], rules=semgrep_rules)

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
            log.warning("run_layer1: files skipped due to write errors", count=write_errors)

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

    # Synthetic-candidate path: run upload_finder and synthesise candidates
    # for handlers with ≥2 weak signals where no scanner rule already fired.
    try:
        handlers = find_upload_handlers(files)
        if handlers:
            # Collect files where a scanner rule already fired for unsafe_file_upload.
            fired_upload_files: set[str] = {
                c.file for c in all_candidates if c.vuln_class == "unsafe_file_upload"
            }
            synth = _synthesise_candidates(handlers, files, fired_upload_files)
            if synth:
                log.info(
                    "run_layer1: synthetic upload candidates added",
                    count=len(synth),
                )
                all_candidates.extend(synth)
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "run_layer1: synthetic candidate generation failed — skipping",
            error=type(exc).__name__,
            error_message=str(exc),
        )

    return aggregate(all_candidates)
