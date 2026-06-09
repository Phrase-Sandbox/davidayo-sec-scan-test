"""End-to-end scan orchestrator (spec §2.2, both paths).

Wires every step of the §2.2 sequence into one ``ScanPipeline`` class that
both the agent (gate) and skill (on-demand) entry points call. The pipeline:

1. Parses ``owner``/``repo`` from the repo URL.
2. Honours BR-004 (empty diff is skipped) and EC-007 (no source files found).
3. Strips secrets *before* anything else, per "What NOT to Do" #2.
4. Filters to source files only.
5. Enforces the BR-005 token limit by raising ``TokenLimitError``.
6. Calls Claude (analyse — first pass).
7. Validates the schema (rule 1–6 + Pydantic backstop).
8. Applies the cso-derived mechanical post-filter.
9. On the gate path only: runs BR-009 blind verification across Critical findings.
10. Computes the gate decision via ``severity/mapping.should_block``.
11. Updates each finding's ``patch_file_path`` by calling
    ``generate_all_patches`` (the patch *content* dict is discarded — the
    caller regenerates it from the returned ``ScanResult``).

Error isolation: only auth errors and the explicit ``TokenLimitError``
propagate. Everything else degrades gracefully to a ScanResult with the
appropriate ``gate_decision`` (``scan_failed`` / ``advisory``).
"""

from __future__ import annotations

import asyncio
import os
import re
from datetime import UTC, datetime
from urllib.parse import urlparse
from uuid import uuid4

from security_scanner.shared.claude.client import (
    ClaudeClient,
    ClaudeResponseError,
    ClaudeTimeoutError,
    ClaudeUnavailableError,
)
from security_scanner.shared.context import ContextPackager
from security_scanner.shared.filters.file_filter import filter as filter_files
from security_scanner.shared.filters.file_filter import scanner_filter as scanner_filter_files
from security_scanner.shared.filters.post_filter import filter_findings
from security_scanner.shared.github.client import GitHubAuthError, GitHubClient, GitHubError
from security_scanner.shared.logging_util import get_logger, set_scan_id
from security_scanner.shared.models.enums import (
    Confidence,
    GateDecision,
    ScanTarget,
    ScanType,
    Severity,
    VerificationStatus,
)
from security_scanner.shared.models.finding import VulnerabilityFinding
from security_scanner.shared.models.scan_result import ScanResult
from security_scanner.shared.reports.patch import generate_all_patches
from security_scanner.shared.scanners import run_layer1
from security_scanner.shared.scanners.merge import merge_with_llm_findings
from security_scanner.shared.secrets.stripper import SecretStripResult, strip
from security_scanner.shared.severity.mapping import (
    severity_to_cvss_band,
    should_block,
)
from security_scanner.shared.tokens.counter import THRESHOLD as TOKEN_THRESHOLD
from security_scanner.shared.tokens.counter import (
    count as token_count,
)
from security_scanner.shared.tokens.counter import (
    exceeds_limit,
    trim_to_budget,
)
from security_scanner.shared.validation.schema import validate
from security_scanner.shared.verification.consolidation import consolidate_findings
from security_scanner.shared.verification.parallel import (
    verify_critical_findings,
)
from security_scanner.shared.verification.quality_gate import strengthen_fix_quality
from security_scanner.shared.verification.secrets import verify_secret_findings
from security_scanner.shared.verification.vulns import (
    verify_vuln_candidates,
)

log = get_logger(__name__)

SECRET_OWASP_REFERENCE = (
    # A02:2021 Cryptographic Failures is the 2021-edition entry that explicitly
    # calls out "hard-coded passwords" as an example. A05:2025 Security
    # Misconfiguration is the 2025-edition counterpart — surfaced by the HTML
    # report's edition footnote.
    "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"  # noqa: S105 — OWASP URL, not a credential
)


class TokenLimitError(Exception):
    """Filtered file set exceeds the §4.2 / BR-005 token threshold."""

    def __init__(self, estimated_tokens: int, threshold: int) -> None:
        super().__init__(
            f"Estimated token count {estimated_tokens} exceeds limit {threshold}. "
            "Recommend scanning by directory."
        )
        self.estimated_tokens = estimated_tokens
        self.threshold = threshold


async def _load_active_scanner_settings():
    """Return latest ScannerSettings row, or None if none exist.

    None means no admin has saved settings yet, DATABASE_URL is not configured,
    or the DB is unreachable — callers fall back to env-var / module-level defaults,
    preserving behaviour identical to the pre-feature state.
    """
    try:
        from sqlalchemy import select  # noqa: PLC0415

        from security_scanner.tokens.db import get_session_factory  # noqa: PLC0415
        from security_scanner.tokens.models import ScannerSettings  # noqa: PLC0415

        factory = get_session_factory()
        async with factory() as session:
            stmt = select(ScannerSettings).order_by(ScannerSettings.id.desc()).limit(1)
            return (await session.execute(stmt)).scalar_one_or_none()
    except Exception:  # noqa: BLE001
        # DB not configured (test env), unreachable, or no table yet.
        return None


class ScanPipeline:
    """Composable pipeline used by both the agent (gate) and skill (on-demand) paths."""

    def __init__(
        self,
        github_client: GitHubClient,
        claude_client: ClaudeClient,
        mode: ScanType,
    ) -> None:
        self._github = github_client
        self._claude = claude_client
        self._mode = mode

    # --- Public API ---------------------------------------------------------

    async def run(
        self,
        repo_url: str,
        scan_target: ScanTarget,
        triggered_by: str,
        ref: str = "HEAD",
        base: str | None = None,
        head: str | None = None,
        directory: str = "",
        prefetched_files: dict[str, str] | None = None,
    ) -> ScanResult:
        # Set scan_id in the context variable so all log lines for this
        # request carry it, and concurrent scans don't interleave.
        scan_id = uuid4().hex
        set_scan_id(scan_id)

        is_gate = self._mode == ScanType.deployment_gate

        # Load scanner settings from DB. Returns None when no admin has saved
        # settings yet — all per-call vars below default to None in that case,
        # which tells each subsystem to use its own env-var / module-level default.
        sc = await _load_active_scanner_settings()

        # Feature-flag for multi-scanner layer.  DB row wins; falls back to env.
        if sc is not None:
            _enable_scanner = (
                sc.enable_semgrep or sc.enable_bandit or sc.enable_gosec or sc.enable_eslint
            )
        else:
            _default_scanner = "true" if is_gate else "false"
            _enable_scanner = (
                os.environ.get("ENABLE_MULTI_SCANNER", _default_scanner).lower() == "true"
            )

        # Per-scan tuning derived from DB settings (None = subsystem env defaults).
        if sc is not None:
            enabled_adapters: set[str] | None = {
                name for name, flag in [
                    ("semgrep", sc.enable_semgrep),
                    ("bandit", sc.enable_bandit),
                    ("gosec", sc.enable_gosec),
                    ("eslint", sc.enable_eslint),
                ] if flag
            }
            semgrep_rules: set[str] | None = (
                {
                    name for name, flag in [
                        ("owasp", sc.semgrep_owasp),
                        ("audit", sc.semgrep_audit),
                        ("upload", sc.semgrep_upload),
                    ] if flag
                }
                if sc.enable_semgrep else None
            )
            _keep_conf = frozenset(
                v.strip() for v in sc.keep_confidences.split(",") if v.strip()
            )
            _advisory_conf = frozenset(
                v.strip() for v in sc.advisory_confidences.split(",") if v.strip()
            )
            _parallelism: int | None = sc.vuln_verifier_parallelism
            _high_risk_paths: list[str] | None = (
                [p.strip() for p in sc.high_risk_paths.splitlines() if p.strip()] or None
            )
            _enable_consolidation_verifier: bool = sc.enable_consolidation_verifier
            _enable_partial_scan: bool = sc.enable_partial_scan
            _enable_zero_findings_retry: bool = sc.enable_zero_findings_retry
            _enable_quality_gate: bool = sc.enable_quality_gate
        else:
            enabled_adapters = None      # all adapters (binary-available)
            semgrep_rules = None         # all rule packs
            _keep_conf = None            # module-level env default
            _advisory_conf = None        # module-level env default
            _parallelism = None          # module-level env default
            _high_risk_paths = None      # YAML file default
            _enable_consolidation_verifier = False
            _enable_partial_scan = True   # default: partial scan preferred over 0 findings
            _enable_zero_findings_retry = True  # default: retry on empty first pass
            _enable_quality_gate = False  # default: off (zero latency for existing deployments)

        # Step 1: parse owner/repo.
        parsed = _parse_repo_url(repo_url)
        if parsed is None:
            return _scan_failed(
                repo_url, scan_target, self._mode, triggered_by,
                reason=f"Could not parse owner/repo from URL: {repo_url!r}",
            )
        owner, repo = parsed

        # Step 2: diff target needs base + head.
        if scan_target == ScanTarget.diff and not (base and head):
            return _scan_failed(
                repo_url, scan_target, self._mode, triggered_by,
                reason="Diff scan requested but base/head not provided",
            )

        # Step 3: fetch files — or use pre-fetched files from the CI runner.
        # When prefetched_files are provided (e.g. from build-payload action)
        # we skip the GitHub API call entirely. No GitHub App credentials needed.
        if prefetched_files is not None:
            files = prefetched_files
            log.info(
                "pipeline.run: using pre-fetched files from caller",
                file_count=len(files),
            )
        else:
            try:
                files = self._fetch_files(owner, repo, scan_target, ref, base, head, directory)
            except GitHubAuthError:
                # Auth failures are unrecoverable — propagate so the caller surfaces
                # EC-005 / EC-006 to the developer.
                raise
            except GitHubError as exc:
                log.warning("github fetch failed", reason=str(exc))
                return _scan_failed(
                    repo_url, scan_target, self._mode, triggered_by,
                    reason=f"GitHub fetch failed: {exc}",
                )

        # Steps 4–5: empty input handling (EC-007, BR-004 / EC-008).
        if not files:
            return _build_result(
                repo_url=repo_url, scan_target=scan_target, scan_type=self._mode,
                triggered_by=triggered_by,
                findings=[],
                gate_decision=GateDecision.advisory,
                partial_scan=False,
                unscanned_files=[],
            )

        # Step 6: strip secrets (runs on ALL files so secrets in .min.js etc are caught).
        strip_result = strip(files)
        secret_findings = _build_secret_findings(strip_result)
        # LLM verification of Layer-2/3 hits runs against the ORIGINAL files.
        # Wrapped in asyncio.to_thread so the blocking ThreadPoolExecutor inside
        # verify_secret_findings does not block the event loop.
        original_files = files  # pre-redaction copy for secret verifier
        secret_findings = await asyncio.to_thread(
            verify_secret_findings,
            secret_findings, strip_result.hits, original_files, self._claude
        )

        # Step 7: filter AFTER strip so the LLM only receives source files
        # (not minified JS/CSS/vendor bundles).  The stripper above already saw
        # every file, so secrets in filtered-out files are still reported.
        # LLM filter: source/config/SQL only (token-efficient).
        files = filter_files(strip_result.cleaned_files)
        # Scanner filter: same rules + template files (.jinja2/.html/.htm) so
        # Semgrep Jinja2/HTML rules can fire on templates.
        scanner_files = scanner_filter_files(strip_result.cleaned_files)

        # If filtering removed everything, treat as no scannable source.
        if not files:
            return _build_result(
                repo_url=repo_url, scan_target=scan_target, scan_type=self._mode,
                triggered_by=triggered_by,
                findings=secret_findings,
                gate_decision=_decide_gate(secret_findings, partial=False, is_gate=is_gate),
                partial_scan=False,
                unscanned_files=[],
            )

        # Step 9 state — initialised here so the token-trim branch below can set them.
        partial_scan = False
        unscanned: list[str] = []
        raw_findings: list[dict] = []

        # Step 8: token-limit gate (BR-005).
        # When partial scan is enabled: trim to budget and continue with a subset
        # of files (highest-risk paths first).  When disabled: raise so the caller
        # returns an advisory result with zero findings (legacy behaviour, EC-010).
        if exceeds_limit(files):
            if _enable_partial_scan:
                files, trimmed_unscanned = trim_to_budget(files, TOKEN_THRESHOLD)
                scanner_files = {k: v for k, v in scanner_files.items() if k in files}
                partial_scan = True
                unscanned.extend(trimmed_unscanned)
                log.info(
                    "token limit exceeded — partial scan",
                    kept_files=len(files),
                    skipped_files=len(trimmed_unscanned),
                )
                # If every file exceeded the budget (e.g. a single file larger
                # than 150k tokens), nothing can be scanned — return advisory.
                if not files:
                    return _build_result(
                        repo_url=repo_url, scan_target=scan_target, scan_type=self._mode,
                        triggered_by=triggered_by,
                        findings=secret_findings,
                        gate_decision=GateDecision.advisory,
                        partial_scan=True,
                        unscanned_files=unscanned,
                        warnings=["All files exceed the token budget; no files could be scanned."],
                    )
            else:
                raise TokenLimitError(token_count(files), TOKEN_THRESHOLD)

        if _enable_scanner:
            # Run chunked Claude first-pass and Layer-1 scanners concurrently.
            llm_task = asyncio.create_task(self._claude.analyse_async_chunked(files))
            scanner_task = asyncio.create_task(
                run_layer1(
                    scanner_files, scan_id,
                    enabled_adapters=enabled_adapters,
                    semgrep_rules=semgrep_rules,
                )
            )
            try:
                (raw_findings, partial_files), aggregated_candidates = await asyncio.gather(
                    llm_task, scanner_task, return_exceptions=False
                )
                if partial_files:
                    partial_scan = True
                    unscanned.extend(partial_files)
            except ClaudeTimeoutError as exc:
                # All chunks timed out — entire first-pass is partial.
                log.warning("claude timeout — marking partial_scan", reason=str(exc))
                partial_scan = True
                unscanned = list(files.keys())
                raw_findings = []
                aggregated_candidates = []
            except ClaudeUnavailableError as exc:
                reason = str(exc)
                log.warning(
                    "llm upstream unavailable — degraded scan with advisory result",
                    mode=self._mode.value,
                    provider=type(self._claude).__name__,
                    reason=reason,
                )
                # Tag the result with a structured warning so the API layer
                # can detect "every file unscanned because the LLM was
                # totally unavailable" and route accordingly (BYO-key →
                # surface as 502; default mode → keep advisory + Slack alert).
                return _build_result(
                    repo_url=repo_url, scan_target=scan_target, scan_type=self._mode,
                    triggered_by=triggered_by,
                    findings=secret_findings,
                    gate_decision=GateDecision.advisory,
                    partial_scan=True,
                    unscanned_files=list(files.keys()),
                    warnings=[f"LLM upstream unavailable: {reason}"],
                )
            except ClaudeResponseError as exc:
                log.warning(
                    "llm response malformed",
                    provider=type(self._claude).__name__,
                    reason=str(exc),
                )
                return _scan_failed(
                    repo_url, scan_target, self._mode, triggered_by,
                    reason=f"Claude response could not be parsed: {exc}",
                )
        else:
            # Scanner disabled — fall back to Claude-only chunked (original behaviour).
            aggregated_candidates = []
            try:
                raw_findings, partial_files = await self._claude.analyse_async_chunked(files)
                if partial_files:
                    partial_scan = True
                    unscanned.extend(partial_files)
            except ClaudeTimeoutError as exc:
                # All chunks timed out.
                log.warning("claude timeout — marking partial_scan", reason=str(exc))
                partial_scan = True
                unscanned = list(files.keys())
                raw_findings = []
            except ClaudeUnavailableError as exc:
                reason = str(exc)
                log.warning(
                    "llm upstream unavailable — degraded scan with advisory result",
                    mode=self._mode.value,
                    provider=type(self._claude).__name__,
                    reason=reason,
                )
                # Tag the result with a structured warning so the API layer
                # can detect "every file unscanned because the LLM was
                # totally unavailable" and route accordingly (BYO-key →
                # surface as 502; default mode → keep advisory + Slack alert).
                return _build_result(
                    repo_url=repo_url, scan_target=scan_target, scan_type=self._mode,
                    triggered_by=triggered_by,
                    findings=secret_findings,
                    gate_decision=GateDecision.advisory,
                    partial_scan=True,
                    unscanned_files=list(files.keys()),
                    warnings=[f"LLM upstream unavailable: {reason}"],
                )
            except ClaudeResponseError as exc:
                log.warning(
                    "llm response malformed",
                    provider=type(self._claude).__name__,
                    reason=str(exc),
                )
                return _scan_failed(
                    repo_url, scan_target, self._mode, triggered_by,
                    reason=f"Claude response could not be parsed: {exc}",
                )

        # Step 9b: zero-findings retry.
        # When Claude returns nothing on a non-trivial codebase and the retry flag
        # is enabled, fire one more analysis pass with an explicit re-examine
        # instruction.  Fires at most once — if the retry also returns nothing,
        # processing continues normally (scanner candidates still flow through).
        _ZERO_FINDINGS_LINE_THRESHOLD = 500
        total_lines = sum(content.count("\n") + 1 for content in files.values())
        if (
            not raw_findings
            and not partial_scan
            and _enable_zero_findings_retry
            and total_lines > _ZERO_FINDINGS_LINE_THRESHOLD
        ):
            log.info(
                "zero_findings_retry",
                source_lines=total_lines,
                file_count=len(files),
            )
            try:
                retry_findings, _ = await self._claude.analyse_async_chunked(
                    files,
                    extra_instruction=(
                        "IMPORTANT: Re-examine the codebase carefully — the initial analysis "
                        "found no security issues in a non-trivial codebase. Look especially "
                        "for injection vulnerabilities, authentication bypasses, insecure "
                        "cryptography, and access-control flaws. If the code is genuinely "
                        "secure, explain briefly why in a single advisory-level finding."
                    ),
                )
                if retry_findings:
                    raw_findings = retry_findings
                    log.info("zero_findings_retry succeeded", found=len(retry_findings))
            except (ClaudeTimeoutError, ClaudeUnavailableError, ClaudeResponseError) as exc:
                log.warning("zero_findings_retry failed", reason=str(exc))

        # Step 10: schema validation.
        validation = validate(raw_findings, total_lines, is_gate_path=is_gate)
        valid_findings = validation.valid_findings

        # Step 11: post-filter.
        post_filtered = filter_findings(valid_findings)

        # Step 12: merge LLM findings with scanner candidates.
        candidates = merge_with_llm_findings(post_filtered, aggregated_candidates)

        # Step 12b: cross-file context packaging — runs on both gate and
        # on-demand paths.  Pure CPU, no LLM calls.  Upload context is cheap
        # and needed on /scan/local so the upload-context panel renders in
        # local-mode reports.
        if candidates:
            bundles = await asyncio.to_thread(
                ContextPackager().attach, candidates, scanner_files
            )
        else:
            bundles = {}

        # Step 13: production-mode vuln verifier — runs on both gate and
        # on-demand paths so CLI scans don't show unverified findings.
        # Use scanner_files so the verifier can read template content for any
        # scanner finding that lands in a .jinja2 / .html file.
        kept = await asyncio.to_thread(
            verify_vuln_candidates, candidates, scanner_files, self._claude,
            bundles=bundles,
            keep_confidences=_keep_conf,
            advisory_confidences=_advisory_conf,
            parallelism=_parallelism,
            high_risk_paths=_high_risk_paths,
        )

        # Step 14: BR-009 defense-in-depth — only for Claude-only Critical findings.
        # Scanner-sourced findings have already been verified by the new verifier
        # in step 13.  Skipping BR-009 for them avoids a duplicate LLM call.
        if is_gate:
            claude_only = [f for f in kept if f.sources == ["claude"]]
            scanner_sourced = [f for f in kept if f.sources != ["claude"]]
            verified_claude = await asyncio.to_thread(
                verify_critical_findings, claude_only, scanner_files, self._claude
            )
            kept = [*verified_claude, *scanner_sourced]

        # Step 14b: consolidation verifier — optional single LLM pass reviewing
        # the complete set of confirmed findings together for combined risks.
        if _enable_consolidation_verifier and kept:
            kept = await asyncio.to_thread(consolidate_findings, kept, self._claude)

        # Step 14c: quality gate — optional pass regenerating suggested_fix /
        # exploit_scenario for verified findings whose fix lacks a code block.
        if _enable_quality_gate and kept:
            kept = await asyncio.to_thread(
                strengthen_fix_quality, kept, scanner_files, self._claude
            )

        all_findings = [*secret_findings, *kept]

        # Step 15: gate decision.
        gate_decision = _decide_gate(all_findings, partial=partial_scan, is_gate=is_gate)

        # Step 16: patches.
        result = _build_result(
            repo_url=repo_url, scan_target=scan_target, scan_type=self._mode,
            triggered_by=triggered_by,
            findings=all_findings,
            gate_decision=gate_decision,
            partial_scan=partial_scan,
            unscanned_files=unscanned,
        )
        result.patches = generate_all_patches(result, files)
        # Attach the accumulated LLM usage from the client so the handler can
        # persist it to the DB without needing a second reference to the client.
        result.llm_usage = getattr(self._claude, "usage", None)
        return result

    # --- Internals ---------------------------------------------------------

    def _fetch_files(
        self,
        owner: str,
        repo: str,
        scan_target: ScanTarget,
        ref: str,
        base: str | None,
        head: str | None,
        directory: str,
    ) -> dict[str, str]:
        if scan_target == ScanTarget.diff:
            assert base and head  # noqa: S101 — guarded in run()
            return self._github.get_diff_files(owner, repo, base, head)
        if scan_target == ScanTarget.directory:
            return self._github.get_repo_files(owner, repo, ref=ref, path=directory)
        return self._github.get_repo_files(owner, repo, ref=ref)


# --- Helpers ---------------------------------------------------------------


_HTTPS_URL_RE = re.compile(r"^([^/]+)/([^/]+?)(?:\.git)?/?$")
_SSH_URL_RE = re.compile(r"^git@github\.com:([^/]+)/([^/]+?)(?:\.git)?$")


def _parse_repo_url(repo_url: str) -> tuple[str, str] | None:
    ssh = _SSH_URL_RE.match(repo_url)
    if ssh:
        return ssh.group(1), ssh.group(2)
    parsed = urlparse(repo_url)
    if not parsed.netloc.endswith("github.com"):
        return None
    parts = parsed.path.strip("/").split("/")
    if len(parts) < 2 or not parts[0] or not parts[1]:
        return None
    repo = parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    return parts[0], repo


def _build_secret_findings(strip_result: SecretStripResult) -> list[VulnerabilityFinding]:
    """One SECRET-001 Critical finding per (file, line) where the stripper hit.

    Each finding carries the source line (or range, for multi-line PEM blocks)
    and a non-sensitive textual anchor (``hint``) — e.g. ``"API_KEY = "`` —
    so a reviewer can trace the credential back to its origin without the
    report ever containing the secret value itself.
    """
    findings: list[VulnerabilityFinding] = []
    for hit in strip_result.hits:
        affected_lines = (
            str(hit.line)
            if hit.line == hit.end_line
            else f"{hit.line}-{hit.end_line}"
        )
        hint_clause = (
            f" Line begins with: `{hit.hint}` (no secret value shown)."
            if hit.hint
            else ""
        )
        findings.append(
            VulnerabilityFinding(
                vulnerability_id="SECRET-001",
                severity=Severity.Critical,
                confidence=Confidence.High,
                cvss_band=severity_to_cvss_band(Severity.Critical),
                affected_file=hit.filename,
                affected_lines=affected_lines,
                description=(
                    f"Hardcoded credential (detector: {hit.detector}) was found "
                    f"at line {affected_lines} and redacted before analysis. "
                    f"Remove the credential from the codebase and rotate the "
                    f"exposed value.{hint_clause}"
                ),
                suggested_fix=(
                    "Move the credential out of the repository (use environment "
                    "variables or the Launchpad secrets pipeline via /add-secret) "
                    "and rotate the exposed value."
                ),
                owasp_reference=SECRET_OWASP_REFERENCE,
                patch_file_path="",  # no auto-patch — remediation is removal + rotation
                exploit_scenario=(
                    f"An attacker who clones the repository extracts the "
                    f"hardcoded credential from {hit.filename}:{affected_lines} "
                    f"and forges authenticated requests using it."
                ),
                # Secret detection is deterministic (regex), so the finding is
                # already verified — BR-009 second-pass is unnecessary.
                verification_status=VerificationStatus.verified,
            )
        )
    return findings


def _decide_gate(
    findings: list[VulnerabilityFinding],
    *,
    partial: bool,
    is_gate: bool = True,
) -> GateDecision:
    if any(should_block(f) for f in findings):
        # On-demand (skill) scans are informational — demote blockers to
        # advisory so the developer is notified but not stopped. Only the
        # deployment gate path actually blocks.
        return GateDecision.blocked if is_gate else GateDecision.advisory
    if partial:
        return GateDecision.advisory
    if findings:
        return GateDecision.advisory
    return GateDecision.pass_


def _build_result(
    *,
    repo_url: str,
    scan_target: ScanTarget,
    scan_type: ScanType,
    triggered_by: str,
    findings: list[VulnerabilityFinding],
    gate_decision: GateDecision,
    partial_scan: bool,
    unscanned_files: list[str],
    warnings: list[str] | None = None,
) -> ScanResult:
    return ScanResult(
        repo_url=repo_url,
        scan_target=scan_target,
        scan_type=scan_type,
        triggered_by=triggered_by,
        timestamp=datetime.now(UTC),
        findings_count=len(findings),
        gate_decision=gate_decision,
        partial_scan=partial_scan,
        unscanned_files=unscanned_files,
        findings=findings,
        warnings=warnings or [],
    )


def _scan_failed(
    repo_url: str,
    scan_target: ScanTarget,
    scan_type: ScanType,
    triggered_by: str,
    *,
    reason: str,
) -> ScanResult:
    log.warning("scan failed", reason=reason)
    return _build_result(
        repo_url=repo_url,
        scan_target=scan_target,
        scan_type=scan_type,
        triggered_by=triggered_by,
        findings=[],
        gate_decision=GateDecision.scan_failed,
        partial_scan=False,
        unscanned_files=[],
    )
