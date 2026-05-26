"""Local-advisory jurisdiction — ``POST /scan/local`` (Appendix D-12).

A developer, on their own machine, uploads their working tree and gets a
**report back**. This endpoint is *structurally incapable of enforcement*:

- It runs the **on-demand** pipeline (``ScanType.on_demand``) — same as the
  pre-push skill — so no BR-009 gate verification.
- Its response model has **no ``gate_decision``**. It returns a Markdown
  report + severity counts only. It can never block a deployment or open a
  PR. That separation is the whole point of the two-jurisdiction design.

Auth has two modes, selected by ``settings.USE_TOKEN_REGISTRY``:

- **Legacy** (``USE_TOKEN_REGISTRY=false``, default): a single shared
  ``LOCAL_SCAN_TOKEN`` env var. The CI gate's ``PHRASE_SCAN_TOKEN`` is
  rejected here and vice-versa — the jurisdiction boundary is enforced by
  distinct credentials, not trust. If ``LOCAL_SCAN_TOKEN`` is unset, every
  call 401s (endpoint effectively disabled).
- **Registry** (``USE_TOKEN_REGISTRY=true``): per-developer revocable tokens
  issued via the SSO portal. Verify outcomes are observable via the
  ``local_scan_auth_outcomes_total`` Prometheus counter and audited (with
  the user's email) into the ``audit_events`` table for the admin UI.

§12: uploaded source is scanned in-memory and never persisted or logged —
only the file *count* and the auth identity are logged, never paths or
content. Secret stripping still runs as a normal pipeline step before any
Claude call.
"""

from __future__ import annotations

import asyncio
import hmac
import os
import re
from collections.abc import Callable
from html import escape
from dataclasses import dataclass
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from security_scanner.agent.slack_alert import send_llm_unavailable_alert
from security_scanner.agent.test_endpoint import _MockGitHubClient
from security_scanner.observability.metrics import local_scan_auth_outcomes_total
from security_scanner.pipeline import ScanPipeline, TokenLimitError
from security_scanner.shared.config import Settings, get_settings
from security_scanner.shared.llm.base import LLMConfigError
from security_scanner.shared.llm.factory import (
    build_llm_client,
    build_local_llm_client,
    build_org_llm_client_for,
)
from security_scanner.shared.logging_util import get_logger
from security_scanner.shared.models.enums import GateDecision, ScanTarget, ScanType, Severity
from security_scanner.shared.models.finding import VulnerabilityFinding
from security_scanner.shared.reports.html import build_html_report
from security_scanner.shared.reports.markdown import build_markdown_report
from security_scanner.tokens import audit as token_audit
from security_scanner.tokens import registry as token_registry
from security_scanner.tokens.db import get_session_factory
from security_scanner.tokens.models import AuditEventType

log = get_logger(__name__)

router = APIRouter(prefix="/scan", tags=["local-scan"])

_REPO_URL_RE = re.compile(r"^https://github\.com/[^/\s]+/[^/\s]+?(\.git)?/?$")

def _read_max_concurrent_scans(default: int = 4) -> int:
    """Per-process concurrent-scan cap, tunable via ``MAX_CONCURRENT_SCANS``.

    Clamped to [1, 64]. The cap protects the shared Anthropic key from
    one client stacking up async tasks that all compete for the same
    per-minute quota.
    """
    raw = os.environ.get("MAX_CONCURRENT_SCANS")
    if not raw:
        return default
    try:
        n = int(raw)
    except ValueError:
        return default
    return max(1, min(n, 64))


_MAX_CONCURRENT_SCANS = _read_max_concurrent_scans()
_scan_semaphore = asyncio.Semaphore(_MAX_CONCURRENT_SCANS)
_BUSY_RETRY_AFTER_SECONDS = 10

# Hard ceiling on request body size. Token-limit gate later would catch
# legitimate over-large repos, but only AFTER Pydantic has deserialised
# the whole dict into RAM. This fast-path rejects obvious garbage
# (accidentally pointing the CLI at $HOME, etc.) before that.
_MAX_REQUEST_BYTES = 100 * 1024 * 1024  # 100 MB

# User-facing messages. The registry path can produce a more specific detail
# (the outcome) without leaking exploit-useful info — see _detail_for_outcome.
_LEGACY_AUTH_FAILURE = "Local scan authentication failed (LOCAL_SCAN_TOKEN)."
_REGISTRY_AUTH_FAILURE = "Local scan authentication failed (token)."


# --- Caller identity returned by the auth dep --------------------------------


@dataclass(frozen=True)
class AuthenticatedLocalCaller:
    """The result of a successful ``/scan/local`` auth check.

    In legacy mode, ``token_id`` and ``user_email`` are ``None`` — the
    legacy single-token path carries no identity. In registry mode they are
    populated from the matched row.
    """

    token: str
    token_id: str | None
    user_email: str | None


# --- Helpers -----------------------------------------------------------------


def _extract_bearer(headers) -> str | None:
    raw = headers.get("Authorization") or headers.get("authorization")
    if not raw:
        return None
    scheme, _, value = raw.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        return None
    return value.strip()


def _detail_for_outcome(outcome: str) -> str:
    """Map a registry-verify outcome to a user-facing 401 detail.

    We say enough that an honest developer can self-diagnose (e.g. "your
    token was revoked, request a new one") without giving an attacker a
    distinguishing oracle they don't already have from the audit log.
    """
    return {
        "bad_format": "Missing or malformed Authorization header.",
        "unknown_token": "Token not recognised. Issue or rotate one at /portal/.",
        "revoked": "Token has been revoked. Issue a new one at /portal/.",
        "bad_signature": _REGISTRY_AUTH_FAILURE,
    }.get(outcome, _REGISTRY_AUTH_FAILURE)


# --- Auth dep ----------------------------------------------------------------


async def verify_local_scan_token(request: Request) -> AuthenticatedLocalCaller:
    """Validate the bearer token. Records a Prometheus outcome on every call.

    Legacy mode preserves today's behaviour byte-for-byte. Registry mode
    consults the DB-backed registry, audits failures with the resolved
    identity (when known), and updates ``last_used_at`` on success.
    """
    settings = get_settings()
    token = _extract_bearer(request.headers)

    # --- Legacy single-token path -------------------------------------------
    if not settings.USE_TOKEN_REGISTRY:
        expected = settings.LOCAL_SCAN_TOKEN
        if token is None or expected is None or not hmac.compare_digest(token, expected):
            local_scan_auth_outcomes_total.labels(outcome="legacy_unauthorized").inc()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=_LEGACY_AUTH_FAILURE,
            )
        local_scan_auth_outcomes_total.labels(outcome="legacy_ok").inc()
        return AuthenticatedLocalCaller(token=token, token_id=None, user_email=None)

    # --- Registry path ------------------------------------------------------
    if token is None:
        local_scan_auth_outcomes_total.labels(outcome="bad_format").inc()
        # We deliberately do NOT audit "header missing" — every random
        # internet hit would create a row. Real attacks send well-formed
        # tokens; those land in unknown_token / bad_signature audits below.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_detail_for_outcome("bad_format"),
        )

    factory = get_session_factory()
    async with factory() as session:
        result = await token_registry.verify(session, token)
        local_scan_auth_outcomes_total.labels(outcome=result.outcome).inc()

        if result.outcome != "ok":
            # Garbage-shaped tokens (``bad_format``) get the counter bump
            # but no audit row. Otherwise every random bot hit with a
            # well-formed Authorization header would spam audit_events.
            # Real attacks send shape-valid tokens and DO land in the
            # unknown_token / bad_signature audits below.
            if result.outcome != "bad_format":
                await token_audit.record(
                    session,
                    event_type=AuditEventType.scan_unauthorized,
                    user_email=result.user_email,
                    token_id=result.token_id,
                    outcome=result.outcome,
                )
                await session.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=_detail_for_outcome(result.outcome),
            )

        # Commit the last_used_at update set by registry.verify.
        await session.commit()
        return AuthenticatedLocalCaller(
            token=token,
            token_id=result.token_id,
            user_email=result.user_email,
        )


# --- Request / response models -----------------------------------------------


class LLMOverride(BaseModel):
    """Per-request LLM credentials supplied by the caller (BYO key).

    The CLI's ``--local`` mode populates this so the scanner uses the
    developer's personal LLM API key for this single scan instead of its
    org credentials. The key is held only in memory for the request
    lifecycle, never logged, cached, or persisted. ``api_key`` is treated
    as a secret value — the logging filter in ``shared.logging_util``
    redacts any field literally named ``api_key``.
    """

    provider: Literal["anthropic", "claude", "google", "gemini"]
    api_key: str = Field(..., min_length=1)
    model: str | None = None  # provider default if unset


class ProviderOverride(BaseModel):
    """Per-request *routing* override — picks which org-configured provider
    runs this scan, without shipping a personal API key.

    Used by CLI default mode (`phrase-sec-scan --provider gemini .`) and CI
    workflows that want to flip provider per-job. The server uses its own
    `ANTHROPIC_API_KEY` or `GOOGLE_API_KEY` — whichever matches
    ``provider`` — so the org bills LLM costs, not the caller. If the
    matching server-side key is not configured the request is rejected
    422-style at routing time so the caller knows up-front.

    NOTE: ``llm_override`` (BYO key) takes precedence if both are sent.
    """

    provider: Literal["anthropic", "claude", "google", "gemini"]
    model: str | None = None


class LocalScanRequest(BaseModel):
    """Body of ``POST /scan/local`` — the dev's uploaded working tree."""

    files: dict[str, str] = Field(..., description="{relative_path: file_content}")
    triggered_by: str = "local-dev"
    directory: str = ""
    repo_url: str = "https://github.com/local/workspace"
    # Optional. When None (default), the scanner uses its env-configured
    # org credentials — the master-pipeline CI path. When set, this scan's
    # LLM call uses the caller's key instead.
    llm_override: LLMOverride | None = None
    # Optional. Picks which org-configured provider runs this scan (uses
    # the server's own ANTHROPIC_API_KEY / GOOGLE_API_KEY). Ignored when
    # ``llm_override`` is set — BYO key wins.
    provider_override: ProviderOverride | None = None


class LocalScanResponse(BaseModel):
    """Advisory result. Deliberately has NO ``gate_decision`` field —
    the local jurisdiction cannot communicate an enforcement verdict."""

    markdown: str
    html: str
    findings_count: int
    critical: int
    high: int
    medium: int
    low: int
    findings: list[VulnerabilityFinding]


LocalPipelineFactory = Callable[
    [dict[str, str], "LLMOverride | None", "ProviderOverride | None"], ScanPipeline
]


def get_local_pipeline_factory(
    settings: Annotated[Settings, Depends(get_settings)],
) -> LocalPipelineFactory:
    """On-demand pipeline over uploaded files (no GitHub, no BR-009 gate).

    Resolution order (highest precedence wins):
    1. ``llm_override`` (BYO key) → ``build_local_llm_client`` with the
       caller-supplied key. CLI ``--local`` path.
    2. ``provider_override`` (no key) → ``build_org_llm_client_for`` using
       the matching server-side org key. CLI default `--provider X`, CI.
    3. Neither → ``build_llm_client(settings)`` reading env defaults. The
       legacy single-provider path.
    """

    def build(
        files: dict[str, str],
        llm_override: LLMOverride | None,
        provider_override: ProviderOverride | None = None,
    ) -> ScanPipeline:
        github_client = _MockGitHubClient(files)
        if llm_override is not None:
            llm_client = build_local_llm_client(
                provider=llm_override.provider,
                api_key=llm_override.api_key,
                model=llm_override.model,
            )
        elif provider_override is not None:
            llm_client = build_org_llm_client_for(
                provider=provider_override.provider,
                model=provider_override.model,
                settings=settings,
            )
        else:
            llm_client = build_llm_client(settings)
        return ScanPipeline(github_client, llm_client, mode=ScanType.on_demand)

    return build


_CallerDep = Annotated[AuthenticatedLocalCaller, Depends(verify_local_scan_token)]
_FactoryDep = Annotated[LocalPipelineFactory, Depends(get_local_pipeline_factory)]


async def _record_scan_ok_audit(
    *,
    caller: AuthenticatedLocalCaller,
    file_count: int,
    findings_count: int,
    severity_counts: dict[str, int],
) -> None:
    """Insert a ``scan_ok`` row into ``audit_events``. No-op in legacy mode."""
    if caller.user_email is None:
        # Legacy mode — no identity, no DB-backed audit. The structured log
        # line below is the only audit signal in that mode.
        return
    factory = get_session_factory()
    async with factory() as session:
        await token_audit.record(
            session,
            event_type=AuditEventType.scan_ok,
            user_email=caller.user_email,
            token_id=caller.token_id,
            file_count=file_count,
            findings_count=findings_count,
            **severity_counts,
        )
        await session.commit()


async def _check_request_size(request: Request) -> None:
    """Reject oversized requests before the body is read into memory.

    This is a router-level dependency so it runs **before** Pydantic
    deserialises ``LocalScanRequest`` — that order is what protects the
    server from holding a 2 GB dict in RAM just to reject it.
    """
    cl = request.headers.get("content-length")
    if not cl:
        return
    try:
        size = int(cl)
    except ValueError:
        return  # bad header — let normal parsing fail it
    if size > _MAX_REQUEST_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=(
                f"Request body too large ({size // 1_000_000} MB > "
                f"{_MAX_REQUEST_BYTES // 1_000_000} MB cap). "
                "Use --directory to scan a sub-tree."
            ),
        )


async def _check_concurrency_slot() -> None:
    """Reject when the per-process scan budget is exhausted.

    Returns 429 with ``Retry-After`` instead of waiting in line so callers
    can decide whether to back off or escalate.
    """
    if _scan_semaphore.locked() and _scan_semaphore._value <= 0:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            headers={"Retry-After": str(_BUSY_RETRY_AFTER_SECONDS)},
            detail=(
                "Scanner is at capacity. Retry shortly — the CLI will do this "
                "automatically. (Set MAX_CONCURRENT_SCANS higher to raise the "
                "limit if your Anthropic tier can handle it.)"
            ),
        )


@router.post(
    "/local",
    response_model=LocalScanResponse,
    dependencies=[Depends(_check_request_size), Depends(_check_concurrency_slot)],
)
async def scan_local(
    body: LocalScanRequest,
    caller: _CallerDep,
    factory: _FactoryDep,
) -> LocalScanResponse:

    if not _REPO_URL_RE.match(body.repo_url):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid repo_url (got {body.repo_url!r})",
        )
    if not body.files:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="No files supplied to scan.",
        )

    # §12: log the count only — never the paths or content. token_id +
    # user_email are populated in registry mode so the line is attributable;
    # in legacy mode both are None and the line falls back to triggered_by.
    # llm_override_used surfaces "did this caller send their own LLM key?"
    # for cost attribution; the key itself is NEVER logged.
    log.info(
        "local advisory scan",
        file_count=len(body.files),
        triggered_by=body.triggered_by,
        token_id=caller.token_id,
        user_email=caller.user_email,
        llm_override_used=body.llm_override is not None,
        llm_override_provider=(body.llm_override.provider if body.llm_override else None),
        provider_override=(
            body.provider_override.provider if body.provider_override else None
        ),
    )

    try:
        pipeline = factory(body.files, body.llm_override, body.provider_override)
    except LLMConfigError as exc:
        # provider_override pointed at a provider whose server-side key
        # is not configured (e.g. provider=gemini but GOOGLE_API_KEY unset).
        # Surface as 422 so the caller knows up-front instead of failing
        # mid-scan with an upstream error.
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    # Hold a semaphore slot for the duration of the pipeline call. The
    # locked() pre-check above ensures we don't *wait* for a slot if all
    # are taken; this `async with` is only entered when capacity exists.
    async with _scan_semaphore:
        try:
            result = await pipeline.run(
                repo_url=body.repo_url,
                scan_target=ScanTarget.directory if body.directory else ScanTarget.full_repo,
                triggered_by=body.triggered_by,
                directory=body.directory,
            )
        except TokenLimitError as exc:
            oversize_msg = (
                f"Project too large to scan in one pass "
                f"(~{exc.estimated_tokens} tokens > {exc.threshold}). "
                "Re-run scoped to a sub-directory."
            )
            return LocalScanResponse(
                markdown=f"# Security Scan Report\n\n> {oversize_msg}\n",
                html=(
                    "<!DOCTYPE html>\n<html lang=\"en\"><head>"
                    "<meta charset=\"utf-8\"><title>Security Scan Report</title>"
                    "</head><body><h1>Security Scan Report</h1>"
                    f"<p>{escape(oversize_msg)}</p></body></html>\n"
                ),
                findings_count=0,
                critical=0,
                high=0,
                medium=0,
                low=0,
                findings=[],
            )

        # Surface mid-scan parse failures (transient LLM truncation) as
        # 502 Bad Gateway rather than silently returning HTTP 200 + 0 findings.
        # Callers (CLI, CI) need to distinguish "clean repo" from "scanner
        # error mid-parse" — a 200/0 silently masks a quality loss.
        if result.gate_decision == GateDecision.scan_failed:
            reason = result.warnings[0] if result.warnings else "scanner upstream error"
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail={
                    "error": "scanner_upstream_error",
                    "message": str(reason),
                    "scan_id": str(result.scan_id),
                },
            )

        # Detect "LLM totally unavailable" — the pipeline tags the result
        # with this exact warning prefix only when ALL LLM calls failed
        # (every chunk exhausted retries). We trust the warning as the
        # definitive signal rather than comparing file counts (the pipeline
        # filters files before counting LLM-eligible inputs, so a count
        # comparison against body.files would miss).
        llm_unavailable = any(
            w.startswith("LLM upstream unavailable") for w in result.warnings
        )
        if llm_unavailable:
            reason = next(
                (w for w in result.warnings if w.startswith("LLM upstream unavailable")),
                "LLM upstream unavailable",
            )
            if body.llm_override is not None:
                # BYO-key mode: fail loud so the user sees the actual problem
                # (their personal LLM key is out of quota or otherwise broken).
                is_quota = any(
                    kw in reason.lower()
                    for kw in ("quota", "resource_exhausted", "exceeded", "billing")
                )
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail={
                        "error": "llm_quota_exhausted" if is_quota else "llm_upstream_unavailable",
                        "provider": body.llm_override.provider,
                        "message": reason,
                        "scan_id": str(result.scan_id),
                    },
                )
            # Default mode (org credentials): keep advisory fallback per
            # BR-006 fail-open, but alert #security so the org key gets
            # topped up / rotated promptly.
            try:
                await send_llm_unavailable_alert(
                    scan_id=str(result.scan_id),
                    reason=reason,
                    provider=type(pipeline._claude).__name__ if hasattr(pipeline, "_claude") else "unknown",
                    triggered_by=body.triggered_by,
                    repo_url=body.repo_url,
                )
            except Exception as exc:  # noqa: BLE001
                # Never let a Slack failure break the scan (BR-006 spirit).
                log.warning("slack llm-unavailable alert raised", error=type(exc).__name__)

        def _count(sev: Severity) -> int:
            return sum(1 for f in result.findings if f.severity == sev)

        severity_counts = {
            "critical": _count(Severity.Critical),
            "high": _count(Severity.High),
            "medium": _count(Severity.Medium),
            "low": _count(Severity.Low),
        }

        # Audit the successful scan (registry mode only — no-op in legacy mode).
        # Done AFTER the pipeline so we record real outcomes, not just intent.
        await _record_scan_ok_audit(
            caller=caller,
            file_count=len(body.files),
            findings_count=result.findings_count,
            severity_counts=severity_counts,
        )

        return LocalScanResponse(
            markdown=build_markdown_report(result),
            html=build_html_report(result, files=body.files),
            findings_count=result.findings_count,
            **severity_counts,
            findings=result.findings,
        )
