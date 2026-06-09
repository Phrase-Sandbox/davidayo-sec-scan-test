"""Production-mode binary vulnerability verifier.

Mirrors the architecture of ``shared/verification/secrets.py``:
- Batch size: 5 candidates per LLM call.
- Parallelism: ``VULN_VERIFIER_PARALLELISM`` env var, clamped [1, 16], default 2.
- Fan-out via ``concurrent.futures.ThreadPoolExecutor``.
- Fail-safe: any LLM error keeps the finding unverified.
- Threshold: keep only ``verdict=real AND confidence in KEEP_CONFIDENCES``.
  Default KEEP_CONFIDENCES = {``high``, ``medium``}, env ``VULN_VERIFIER_KEEP_CONFIDENCES``
  (comma-separated).
- Advisory lane: ``ADVISORY_CONFIDENCES`` env var (default ``{"low"}``):
  ``verdict=real AND confidence in ADVISORY_CONFIDENCES`` → kept with
  ``verification_status=advisory_real`` (non-blocking).
- Risk routing: files under high-risk path prefixes treat medium-confidence
  real findings as verified+blocking instead of advisory.
- Prompt-injection defence: all ``<source_code>``/``</source_code>`` tokens in
  candidate content are defanged before inclusion in the user message.
"""

from __future__ import annotations

import concurrent.futures
import os
import re
from collections.abc import Iterator

from security_scanner.shared.claude.client import ClaudeClient, ClaudeError
from security_scanner.shared.context.models import ContextBundle
from security_scanner.shared.context.packager import is_high_risk_path
from security_scanner.shared.logging_util import get_logger
from security_scanner.shared.models.enums import (
    Confidence,
    Severity,
    VerificationStatus,
)
from security_scanner.shared.models.finding import VulnerabilityFinding
from security_scanner.shared.prompts.system import _defang_source_code_tags
from security_scanner.shared.scanners.types import CandidateForVerification
from security_scanner.shared.severity.mapping import severity_to_cvss_band
from security_scanner.shared.verification.prompts import build_vuln_verifier_system_prompt

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Tuneable parameters.
# ---------------------------------------------------------------------------
_BATCH_SIZE = 5


def _read_parallelism_env(default: int = 2) -> int:
    raw = os.environ.get("VULN_VERIFIER_PARALLELISM")
    if not raw:
        return default
    try:
        n = int(raw)
    except ValueError:
        log.warning(
            "VULN_VERIFIER_PARALLELISM not an integer; using default",
            value=raw,
            default=default,
        )
        return default
    return max(1, min(n, 16))


def _read_keep_confidences_env() -> frozenset[str]:
    # Default: high AND medium are blocking findings.
    # Medium-confidence real vulns (e.g. os.system with a parameter, subprocess shell=True)
    # were previously demoted to advisory_real, causing a significant recall drop.
    # Env var VULN_VERIFIER_KEEP_CONFIDENCES overrides this for tuning.
    raw = os.environ.get("VULN_VERIFIER_KEEP_CONFIDENCES", "high,medium")
    return frozenset(v.strip().lower() for v in raw.split(",") if v.strip())


def _read_advisory_confidences_env() -> frozenset[str]:
    # Advisory lane now holds low-confidence real findings only (medium is blocking above).
    # Env var ADVISORY_CONFIDENCES overrides.
    raw = os.environ.get("ADVISORY_CONFIDENCES", "low")
    return frozenset(v.strip().lower() for v in raw.split(",") if v.strip())


_MAX_PARALLELISM = _read_parallelism_env()
_KEEP_CONFIDENCES: frozenset[str] = _read_keep_confidences_env()
_ADVISORY_CONFIDENCES: frozenset[str] = _read_advisory_confidences_env()


def _is_high_risk_path(filepath: str) -> bool:
    """Delegate to the context packager's path check."""
    return is_high_risk_path(filepath)

# ---------------------------------------------------------------------------
# Response parsing.
# ---------------------------------------------------------------------------
_VERDICT_RE = re.compile(
    r"^\s*VERDICT\s*#?\s*(\d+)\s*:\s*(real|false_positive)\b",
    re.IGNORECASE | re.MULTILINE,
)
_CONFIDENCE_RE = re.compile(
    r"^\s*CONFIDENCE\s*#?\s*(\d+)\s*:\s*(high|medium|low)\b",
    re.IGNORECASE | re.MULTILINE,
)
_REASON_RE = re.compile(
    r"^\s*REASON\s*#?\s*(\d+)\s*:\s*(.+)$",
    re.IGNORECASE | re.MULTILINE,
)


def _parse_verifier_response(
    response: str,
    *,
    batch_size: int,
) -> dict[int, tuple[str, str, str]]:
    """Return ``{0-based-index: (verdict, confidence, reason)}``.

    Missing entries for a candidate mean "no verdict" — the fail-safe keeps
    the finding.
    """
    verdicts: dict[int, str] = {}
    for m in _VERDICT_RE.finditer(response):
        idx = int(m.group(1)) - 1
        if 0 <= idx < batch_size:
            verdicts[idx] = m.group(2).lower()

    confidences: dict[int, str] = {}
    for m in _CONFIDENCE_RE.finditer(response):
        idx = int(m.group(1)) - 1
        if 0 <= idx < batch_size:
            confidences[idx] = m.group(2).lower()

    reasons: dict[int, str] = {}
    for m in _REASON_RE.finditer(response):
        idx = int(m.group(1)) - 1
        if 0 <= idx < batch_size:
            reasons[idx] = m.group(2).strip()[:240]

    result: dict[int, tuple[str, str, str]] = {}
    for idx in range(batch_size):
        if idx in verdicts:
            result[idx] = (
                verdicts[idx],
                confidences.get(idx, "low"),
                reasons.get(idx, ""),
            )
    return result


# ---------------------------------------------------------------------------
# Batch builder.
# ---------------------------------------------------------------------------

def _chunk(items: list[int], size: int) -> Iterator[list[int]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def _render_upload_context_section(bundle: ContextBundle) -> str:
    """Render the UPLOAD CONTEXT block when the bundle has upload context.

    Returns an empty string when upload_context is None or all fields empty.
    """
    uc = bundle.upload_context
    if uc is None:
        return ""

    # Check if any field has meaningful content — only render if non-trivial.
    any_content = any([
        uc.route_summary,
        uc.middleware_summary,
        uc.authz_signals,
        uc.filename_handling and uc.filename_handling != ["unknown"],
        uc.validation_signals and uc.validation_signals != ["none"],
        uc.size_limit_signals and uc.size_limit_signals != ["none"],
        uc.storage_signals and uc.storage_signals != ["unknown"],
        uc.retrieval_signals and uc.retrieval_signals != ["none"],
        uc.post_processing_signals and uc.post_processing_signals != ["none"],
    ])
    if not any_content:
        return ""

    parts: list[str] = ["UPLOAD CONTEXT:"]

    if uc.route_summary:
        parts.append("  Routes: " + "; ".join(uc.route_summary))
    if uc.middleware_summary:
        parts.append("  Middleware: " + " → ".join(uc.middleware_summary))
    if uc.authz_signals:
        parts.append("  Auth/z: " + "; ".join(uc.authz_signals))
    if uc.filename_handling:
        parts.append("  Naming: " + " | ".join(uc.filename_handling))
    if uc.validation_signals:
        parts.append("  Validation: " + " | ".join(uc.validation_signals))
    if uc.size_limit_signals:
        parts.append("  Limits: " + " | ".join(uc.size_limit_signals))
    if uc.storage_signals:
        parts.append("  Storage: " + " | ".join(uc.storage_signals))
    if uc.retrieval_signals:
        parts.append("  Retrieval: " + " | ".join(uc.retrieval_signals))
    if uc.post_processing_signals:
        parts.append("  Processing: " + " | ".join(uc.post_processing_signals))

    return "\n".join(parts)


def _render_bundle_sections(bundle: ContextBundle) -> str:
    """Render labelled context sections from a ContextBundle.

    Only non-empty sections are emitted.  Returns an empty string when the
    bundle contributes nothing (all lists empty).
    """
    parts: list[str] = []

    if bundle.route_definitions:
        lines = [
            f"  {r.method} {r.path} → {r.handler} (file: {r.file}:{r.line})"
            for r in bundle.route_definitions
        ]
        parts.append("ROUTES:\n" + "\n".join(lines))

    if bundle.middleware_chain:
        chain = " → ".join(m.name for m in bundle.middleware_chain)
        parts.append(f"MIDDLEWARE: {chain}")

    if bundle.callers:
        lines = [
            f"  {c.file}:{c.line} — {c.function_name}"
            for c in bundle.callers
        ]
        parts.append("CALLERS:\n" + "\n".join(lines))

    if bundle.callees:
        names = ", ".join(c.name for c in bundle.callees)
        parts.append(f"CALLEES: {names}")

    if bundle.ownership_checks:
        lines = [
            f"  {o.file}:{o.line} — {o.pattern}, identifier: {o.identifier}, "
            f"current_user-derived: {'yes' if o.current_user_derived else 'no'}"
            for o in bundle.ownership_checks
        ]
        parts.append("OWNERSHIP CHECKS:\n" + "\n".join(lines))

    return "\n".join(parts)


def _build_candidate_block(
    idx: int,
    candidate: CandidateForVerification,
    files: dict[str, str],
    bundle: ContextBundle | None = None,
) -> str:
    """Render one CANDIDATE #N block for the verifier user message."""
    file_content = files.get(candidate.file, "")
    # Prefer the packager's context-aware snippet (±8 for Claude-sourced findings,
    # ±14 for scanner-only candidates).  Fall back to a direct ±4-line extraction
    # when no bundle is available or the packager returned an empty snippet.
    if bundle is not None and bundle.snippet:
        snippet = bundle.snippet
    elif candidate.line_start and file_content:
        lines = file_content.splitlines()
        lo = max(0, candidate.line_start - 4)
        hi = min(len(lines), (candidate.line_end or candidate.line_start) + 4)
        snippet = "\n".join(lines[lo:hi])
    else:
        snippet = file_content[:2000] if file_content else "(file content unavailable)"

    # Defang prompt-injection attempts in source content and scanner messages.
    safe_snippet = _defang_source_code_tags(snippet)
    safe_scanner_msg = _defang_source_code_tags(candidate.scanner_message or "")
    safe_description = _defang_source_code_tags(candidate.description or "")

    lines_text = (
        f"{candidate.line_start}-{candidate.line_end}"
        if candidate.line_end and candidate.line_end != candidate.line_start
        else str(candidate.line_start or "unknown")
    )

    # File path can contain attacker-controlled chars (e.g. a malicious
    # filename echoed from a candidate). Defang so it can't smuggle a
    # ``</source_code>`` close-tag into the verifier user message.
    safe_file = _defang_source_code_tags(candidate.file)
    parts = [
        f"CANDIDATE #{idx}",
        f"FILE: {safe_file}",
        f"LINES: {lines_text}",
        f"VULN CLASS: {candidate.vuln_class}",
        f"SOURCES: {', '.join(candidate.sources)}",
    ]
    if safe_description:
        parts.append(f"DESCRIPTION: {safe_description}")
    if safe_scanner_msg and safe_scanner_msg != safe_description:
        parts.append(f"SCANNER MESSAGE: {safe_scanner_msg}")

    # Render cross-file context sections before the primary code block.
    if bundle is not None:
        # Upload context block first (when present).
        upload_section = _render_upload_context_section(bundle)
        if upload_section:
            parts.append(upload_section)
        # Then regular context sections.
        context_sections = _render_bundle_sections(bundle)
        if context_sections:
            parts.append(context_sections)

    parts.append("SOURCE CODE:")
    # Use a non-XML delimiter so a literal </source_code> can't appear in the
    # rendered message via the wrapper itself — the defang routine handles
    # any such tokens inside the snippet content.
    parts.append(f"<<<BEGIN CODE filename={safe_file}>>>")
    parts.append(safe_snippet)
    parts.append("<<<END CODE>>>")

    return "\n".join(parts)


def _build_batch_user_message(
    blocks: list[str],
    *,
    total: int,
) -> str:
    joined = "\n\n".join(blocks)
    return (
        f"{joined}\n\n"
        f"Issue ONE verdict per candidate ({total} total). "
        "Use VERDICT #N, CONFIDENCE #N, REASON #N for each."
    )


def _batch_vuln_class(batch_candidates: list[CandidateForVerification]) -> str | None:
    """Return the shared vuln_class when the whole batch is the same class.

    Returns None for mixed batches so the generic prompt is used.
    """
    classes = {c.vuln_class.lower() for c in batch_candidates}
    if len(classes) == 1:
        return next(iter(classes))
    return None


# ---------------------------------------------------------------------------
# Core verification.
# ---------------------------------------------------------------------------

def _verify_batch(
    batch_candidates: list[CandidateForVerification],
    files: dict[str, str],
    claude_client: ClaudeClient,
    keep_confidences: frozenset[str],
    bundles: dict[int, ContextBundle] | None = None,
    advisory_confidences: frozenset[str] | None = None,
    high_risk_paths: list[str] | None = None,
) -> list[VulnerabilityFinding | None]:
    """Verify up to _BATCH_SIZE candidates in one Claude call.

    Returns one element per input candidate:
    - ``VulnerabilityFinding`` if kept (verdict=real AND confidence in keep_confidences
      OR in advisory_confidences → advisory_real status).
    - ``None`` if dropped (false_positive or confidence below threshold).
    - Original finding (unverified) if LLM error or no verdict (fail-safe).
    """
    effective_advisory = (
        advisory_confidences if advisory_confidences is not None else _ADVISORY_CONFIDENCES
    )

    blocks = [
        _build_candidate_block(
            i + 1, c, files,
            bundle=(bundles or {}).get(id(c)),
        )
        for i, c in enumerate(batch_candidates)
    ]
    user_message = _build_batch_user_message(blocks, total=len(batch_candidates))

    # Use class-specific prompt when the entire batch shares the same vuln class.
    shared_class = _batch_vuln_class(batch_candidates)
    system_prompt = build_vuln_verifier_system_prompt(vuln_class=shared_class)

    try:
        response = claude_client.ask(system_prompt, user_message)
    except ClaudeError as exc:
        log.warning(
            "vuln verifier: claude error — keeping batch (fail-safe)",
            batch_size=len(batch_candidates),
            error=type(exc).__name__,
        )
        # Fail-safe: keep all candidates unverified.
        return [candidate_to_finding(c, verification_status=VerificationStatus.unverified)
                for c in batch_candidates]

    parsed = _parse_verifier_response(response or "", batch_size=len(batch_candidates))
    results: list[VulnerabilityFinding | None] = []

    for idx, candidate in enumerate(batch_candidates):
        if idx not in parsed:
            log.warning(
                "vuln verifier: no verdict — keeping (fail-safe)",
                file=candidate.file,
                vuln_class=candidate.vuln_class,
            )
            results.append(
                candidate_to_finding(candidate, verification_status=VerificationStatus.unverified)
            )
            continue

        verdict, confidence, reason = parsed[idx]

        if verdict == "false_positive":
            log.info(
                "vuln verifier: false positive suppressed",
                file=candidate.file,
                vuln_class=candidate.vuln_class,
                confidence=confidence,
                reason=reason,
            )
            results.append(None)
            continue

        # verdict == "real" — determine effective keep set for this candidate.
        # High-risk paths widen KEEP_CONFIDENCES to include medium.
        # is_high_risk_path falls back to the YAML list when prefixes=None.
        if is_high_risk_path(candidate.file, prefixes=high_risk_paths):
            effective_keep = keep_confidences | frozenset({"medium"})
        else:
            effective_keep = keep_confidences

        if confidence in effective_keep:
            log.info(
                "vuln verifier: confirmed real",
                file=candidate.file,
                vuln_class=candidate.vuln_class,
                confidence=confidence,
            )
            finding = candidate_to_finding(
                candidate,
                verification_status=VerificationStatus.verified,
            )
            if reason:
                finding = finding.model_copy(
                    update={"description": f"{finding.description}\n\nVerifier: {reason}"}
                )
            results.append(finding)
            continue

        if confidence in effective_advisory:
            log.info(
                "vuln verifier: real+advisory confidence — keeping as advisory_real",
                file=candidate.file,
                vuln_class=candidate.vuln_class,
                confidence=confidence,
            )
            finding = candidate_to_finding(
                candidate,
                verification_status=VerificationStatus.advisory_real,
            )
            if reason:
                finding = finding.model_copy(
                    update={"description": f"{finding.description}\n\nVerifier: {reason}"}
                )
            results.append(finding)
            continue

        # Below both thresholds — drop.
        log.info(
            "vuln verifier: real but confidence below threshold — dropping",
            file=candidate.file,
            vuln_class=candidate.vuln_class,
            confidence=confidence,
            threshold=sorted(effective_keep),
        )
        results.append(None)

    return results


def candidate_to_finding(
    candidate: CandidateForVerification,
    *,
    verification_status: VerificationStatus = VerificationStatus.unverified,
    bundle: ContextBundle | None = None,
) -> VulnerabilityFinding:
    """Convert a ``CandidateForVerification`` to a ``VulnerabilityFinding``.

    Public so the pipeline can use it on the skill path where the verifier
    is skipped for cost — candidates flow through unverified.

    Parameters
    ----------
    bundle:
        Optional context bundle.  When present and the bundle has an
        ``UploadContext``, ``context_summary`` is populated from
        ``UploadContext.overall_summary``.
    """
    # Map severity string to enum.
    try:
        severity = Severity(candidate.severity)
    except ValueError:
        severity = Severity.Medium

    # Map confidence string to enum.
    confidence_map = {"High": Confidence.High, "Medium": Confidence.Medium, "Low": Confidence.Low}
    confidence = confidence_map.get(candidate.confidence, Confidence.Medium)

    cvss_band = candidate.cvss_band or severity_to_cvss_band(severity)

    lines_text = None
    if candidate.line_start:
        if candidate.line_end and candidate.line_end != candidate.line_start:
            lines_text = f"{candidate.line_start}-{candidate.line_end}"
        else:
            lines_text = str(candidate.line_start)

    vuln_id = candidate.vulnerability_id or candidate.vuln_class.upper()

    # Populate context_summary from UploadContext.overall_summary when available.
    context_summary = ""
    if bundle is not None and bundle.upload_context is not None:
        context_summary = bundle.upload_context.overall_summary or ""

    return VulnerabilityFinding(
        vulnerability_id=vuln_id,
        severity=severity,
        confidence=confidence,
        cvss_band=cvss_band,
        affected_file=candidate.file,
        affected_lines=lines_text,
        description=(
            candidate.description or candidate.scanner_message or f"{candidate.vuln_class} detected"
        ),
        suggested_fix=(
            candidate.suggested_fix or "Review and remediate the identified vulnerability."
        ),
        owasp_reference=candidate.owasp_reference or "",
        patch_file_path="",
        exploit_scenario=(
            candidate.exploit_scenario
            or f"Attacker exploits {candidate.vuln_class} in {candidate.file}."
        ),
        verification_status=verification_status,
        sources=candidate.sources,
        consensus_score=candidate.consensus_score,
        context_summary=context_summary,
    )


def verify_vuln_candidates(
    candidates: list[CandidateForVerification],
    files: dict[str, str],
    claude_client: ClaudeClient,
    *,
    keep_confidences: frozenset[str] | None = None,
    advisory_confidences: frozenset[str] | None = None,
    bundles: dict[int, ContextBundle] | None = None,
    parallelism: int | None = None,
    high_risk_paths: list[str] | None = None,
) -> list[VulnerabilityFinding]:
    """Run the production-mode binary verifier over all vuln candidates.

    Parameters
    ----------
    candidates:
        Merged list of LLM + scanner candidates.
    files:
        Source file contents (pre-secret-strip) for snippet extraction.
    claude_client:
        Claude client instance.
    keep_confidences:
        Set of confidence levels to retain as blocking findings
        (default: from env or ``{"high","medium"}``).
    advisory_confidences:
        Set of confidence levels to keep as non-blocking advisory_real findings
        (default: from env or ``{"low"}``).
    bundles:
        Optional dict mapping ``id(candidate)`` → ``ContextBundle`` produced
        by ``ContextPackager.attach()``.  When present, context sections are
        rendered in the user message and the authz rubric is injected for
        auth_bypass/idor classes.

    Returns
    -------
    list[VulnerabilityFinding]
        Verified findings (false positives dropped, below-threshold dropped,
        unverified kept on LLM error).  Advisory-lane findings carry
        ``verification_status=advisory_real``.
    """
    if not candidates:
        return []

    effective_keep = keep_confidences if keep_confidences is not None else _KEEP_CONFIDENCES
    indices = list(range(len(candidates)))
    batches: list[list[int]] = list(_chunk(indices, _BATCH_SIZE))
    workers = min(parallelism or _MAX_PARALLELISM, len(batches))

    slots: list[VulnerabilityFinding | None] = [None] * len(candidates)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        future_to_batch: dict[concurrent.futures.Future, list[int]] = {
            pool.submit(
                _verify_batch,
                [candidates[i] for i in batch],
                files,
                claude_client,
                effective_keep,
                bundles,
                advisory_confidences,
                high_risk_paths,
            ): batch
            for batch in batches
        }
        for fut in concurrent.futures.as_completed(future_to_batch):
            batch = future_to_batch[fut]
            try:
                batch_results = fut.result()
            except Exception as exc:  # noqa: BLE001
                log.warning(
                    "vuln verifier: unexpected error — keeping batch",
                    batch_size=len(batch),
                    error=type(exc).__name__,
                    error_message=str(exc),
                )
                batch_results = [
                    candidate_to_finding(
                        candidates[i], verification_status=VerificationStatus.unverified
                    )
                    for i in batch
                ]
            for slot_idx, result in zip(batch, batch_results, strict=True):
                slots[slot_idx] = result

    return [f for f in slots if f is not None]
