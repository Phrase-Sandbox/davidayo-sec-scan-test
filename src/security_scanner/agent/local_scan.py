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
from dataclasses import dataclass
from html import escape
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from security_scanner.agent.test_endpoint import _MockGitHubClient
from security_scanner.observability.metrics import local_scan_auth_outcomes_total
from security_scanner.pipeline import ScanPipeline, TokenLimitError
from security_scanner.shared.config import get_settings
from security_scanner.shared.llm.base import LLMConfigError
from security_scanner.shared.llm.factory import _get_model_for_provider, build_user_llm_client
from security_scanner.shared.logging_util import get_logger
from security_scanner.shared.models.enums import GateDecision, ScanTarget, ScanType, Severity
from security_scanner.shared.models.finding import VulnerabilityFinding
from security_scanner.shared.reports.html import build_html_report
from security_scanner.shared.reports.markdown import build_markdown_report
from security_scanner.tokens import audit as token_audit
from security_scanner.tokens import registry as token_registry
from security_scanner.tokens.db import get_session_factory
from security_scanner.tokens.models import (
    AuditEventType,
    LLMUsageMonthly,
    ScanRecord,
    ScanStatus,
    ScanUsage,
    UserLLMSettings,
)

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
        "expired": (
            "Your scanner token has expired (30-day TTL). Visit /portal/ to re-issue a new one."
        ),
        "deactivated": ("Your account has been deactivated. Contact your administrator."),
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


class LocalScanRequest(BaseModel):
    """Body of ``POST /scan/local`` — the dev's uploaded working tree.

    The LLM provider/model/key are resolved from the authenticated user's
    stored settings in ``user_llm_settings``.  The caller does NOT send a
    key — the server reads it from the DB, decrypts it, and uses it for
    this scan only.  If no settings are saved, the request is rejected 412.
    """

    files: dict[str, str] = Field(..., description="{relative_path: file_content}")
    triggered_by: str = "local-dev"
    directory: str = ""
    repo_url: str = "https://github.com/local/workspace"


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


_CallerDep = Annotated[AuthenticatedLocalCaller, Depends(verify_local_scan_token)]


async def _load_active_org_settings():
    """Return the latest ``OrgSettings`` row, or ``None`` if none exist yet.

    ``None`` means the bootstrap window (no admin has saved org settings yet).
    In that case ``_get_model_for_provider`` returns ``None`` → provider uses
    its own default model.
    """
    from sqlalchemy import select as _select  # noqa: PLC0415

    from security_scanner.tokens.models import OrgSettings  # noqa: PLC0415

    _factory = get_session_factory()
    async with _factory() as _session:
        _stmt = _select(OrgSettings).order_by(OrgSettings.id.desc()).limit(1)
        return (await _session.execute(_stmt)).scalar_one_or_none()


async def _load_user_llm_settings(user_email: str) -> UserLLMSettings:
    """Load the user's stored LLM settings from the DB.

    Raises
    ------
    HTTPException 412
        No settings row found — user must visit /portal/settings first.
    """
    from sqlalchemy import select  # local import — keeps module-level imports tight

    factory = get_session_factory()
    async with factory() as session:
        stmt = select(UserLLMSettings).where(UserLLMSettings.user_email == user_email)
        row = (await session.execute(stmt)).scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_412_PRECONDITION_FAILED,
            detail=(
                "No LLM provider configured for your account. "
                "Visit /portal/settings to choose a provider and save your API key."
            ),
        )
    return row


async def _persist_scan_data(
    *,
    result,
    user_email: str,
    token_id: str | None,
    file_count: int,
    severity_counts: dict[str, int],
    provider: str,
    model: str,
    scan_id,
    started_at,
    markdown_report: str,
    html_report: str,
) -> None:
    """Write scan_records + scan_usage, bump llm_usage_monthly, audit scan_ok.

    All four writes happen in a single transaction so the portal always
    shows a consistent state.  No-op in legacy mode (no user_email).
    """
    if not user_email:
        return

    from datetime import UTC, datetime  # noqa: PLC0415 — local to keep module clean

    factory = get_session_factory()
    now = datetime.now(UTC)
    year_month = now.strftime("%Y-%m")

    usage = result.llm_usage  # LLMUsage | None

    async with factory() as session:
        # --- scan_records ----------------------------------------------------
        record = ScanRecord(
            scan_id=scan_id,
            user_email=user_email,
            started_at=started_at,
            finished_at=now,
            repo_url=result.repo_url,
            scan_target=result.scan_target.value if result.scan_target else None,
            status=(
                ScanStatus.ok
                if result.gate_decision.value not in ("scan_failed",)
                else ScanStatus.failed
            ),
            findings_count=result.findings_count,
            critical=severity_counts.get("critical", 0),
            high=severity_counts.get("high", 0),
            medium=severity_counts.get("medium", 0),
            low=severity_counts.get("low", 0),
            markdown_report=markdown_report,
            html_report=html_report,
            provider=provider,
            model=model,
        )
        session.add(record)

        # --- scan_usage ------------------------------------------------------
        if usage is not None:
            scan_usage_row = ScanUsage(
                scan_id=scan_id,
                provider=provider,
                model=model,
                n_llm_calls=usage.n_calls,
                input_tokens=usage.input_tokens,
                output_tokens=usage.output_tokens,
                cache_creation_input_tokens=usage.cache_creation_input_tokens,
                cache_read_input_tokens=usage.cache_read_input_tokens,
                response_ids=usage.response_ids_csv or None,
            )
            session.add(scan_usage_row)

            # --- llm_usage_monthly (upsert) ----------------------------------
            # SQLAlchemy Core upsert for "ON CONFLICT DO UPDATE".
            # Falls back to a simple select+update+insert on SQLite (tests).
            from sqlalchemy import select as sa_select  # noqa: PLC0415

            stmt = sa_select(LLMUsageMonthly).where(
                LLMUsageMonthly.user_email == user_email,
                LLMUsageMonthly.year_month == year_month,
                LLMUsageMonthly.provider == provider,
                LLMUsageMonthly.model == model,
            )
            monthly = (await session.execute(stmt)).scalar_one_or_none()
            if monthly is None:
                monthly = LLMUsageMonthly(
                    user_email=user_email,
                    year_month=year_month,
                    provider=provider,
                    model=model,
                    input_tokens=usage.input_tokens,
                    output_tokens=usage.output_tokens,
                    cache_creation_input_tokens=usage.cache_creation_input_tokens,
                    cache_read_input_tokens=usage.cache_read_input_tokens,
                    scan_count=1,
                    last_updated=now,
                )
                session.add(monthly)
            else:
                monthly.input_tokens += usage.input_tokens
                monthly.output_tokens += usage.output_tokens
                monthly.cache_creation_input_tokens += usage.cache_creation_input_tokens
                monthly.cache_read_input_tokens += usage.cache_read_input_tokens
                monthly.scan_count += 1
                monthly.last_updated = now

        # --- audit scan_ok ---------------------------------------------------
        await token_audit.record(
            session,
            event_type=AuditEventType.scan_ok,
            user_email=user_email,
            token_id=token_id,
            file_count=file_count,
            findings_count=result.findings_count,
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
) -> LocalScanResponse:
    """Handle a CLI advisory scan.

    Auth flows through ``verify_local_scan_token`` (registry mode).  The
    user's stored LLM settings are loaded from the DB, the key is decrypted,
    and the pipeline runs entirely under the user's own credentials — the org
    key is never involved here.  Results are persisted to ``scan_records`` +
    ``scan_usage`` + ``llm_usage_monthly`` so the user can review them in
    ``/portal/scans``.
    """
    from datetime import UTC, datetime  # noqa: PLC0415 — local import keeps top-level clean

    from security_scanner.tokens import crypto  # noqa: PLC0415

    # Registry mode is required — legacy tokens carry no user_email and
    # therefore cannot resolve per-user LLM settings.  In practice this
    # branch is unreachable once USE_TOKEN_REGISTRY=true is the permanent
    # default, but guard explicitly so a misconfigured deploy fails loudly.
    if caller.user_email is None:
        raise HTTPException(
            status_code=status.HTTP_412_PRECONDITION_FAILED,
            detail=(
                "No user identity resolved from token. "
                "Issue a personal token at /portal/ and retry."
            ),
        )

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

    # Load the user's stored provider/key.  Raises 412 with a portal pointer
    # if the user has not yet visited /portal/settings.
    settings_row = await _load_user_llm_settings(caller.user_email)
    api_key = crypto.decrypt(settings_row.encrypted_api_key)
    provider_name = settings_row.provider.value  # "anthropic" | "google"

    # Model is admin-controlled: read from the active OrgSettings row so all
    # users (CLI + CI) get a consistent model regardless of their individual
    # settings.  Falls back to None (provider default) when no org settings row
    # exists yet (bootstrap window before admin has saved config).
    org_row = await _load_active_org_settings()
    model_name = _get_model_for_provider(org_row, provider_name)

    # §12: log the count only — never paths or content.
    log.info(
        "local advisory scan",
        file_count=len(body.files),
        triggered_by=body.triggered_by,
        token_id=caller.token_id,
        user_email=caller.user_email,
        provider=provider_name,
        model=model_name,
    )

    try:
        llm_client = build_user_llm_client(provider_name, api_key, model_name)
    except LLMConfigError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    pipeline = ScanPipeline(
        _MockGitHubClient(body.files),
        llm_client,
        mode=ScanType.on_demand,
    )
    started_at = datetime.now(UTC)

    # Hold a semaphore slot for the duration of the pipeline call.  The
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
                    '<!DOCTYPE html>\n<html lang="en"><head>'
                    '<meta charset="utf-8"><title>Security Scan Report</title>'
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
        # Callers (CLI) need to distinguish "clean repo" from "scanner error
        # mid-parse" — a 200/0 silently masks a quality loss.
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

        # BYO-key channel: ALWAYS loud-fail on LLM unavailability.
        # The user's personal key is exhausted or broken; they need to know.
        llm_unavailable = any(w.startswith("LLM upstream unavailable") for w in result.warnings)
        if llm_unavailable:
            reason = next(
                (w for w in result.warnings if w.startswith("LLM upstream unavailable")),
                "LLM upstream unavailable",
            )
            is_quota = any(
                kw in reason.lower()
                for kw in ("quota", "resource_exhausted", "exceeded", "billing")
            )
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail={
                    "error": "llm_quota_exhausted" if is_quota else "llm_upstream_unavailable",
                    "provider": provider_name,
                    "message": reason,
                    "scan_id": str(result.scan_id),
                },
            )

        def _count(sev: Severity) -> int:
            return sum(1 for f in result.findings if f.severity == sev)

        severity_counts = {
            "critical": _count(Severity.Critical),
            "high": _count(Severity.High),
            "medium": _count(Severity.Medium),
            "low": _count(Severity.Low),
        }

        markdown_report = build_markdown_report(result)
        html_report = build_html_report(result, files=body.files)

        # Persist scan_records + scan_usage + bump llm_usage_monthly + audit
        # in one transaction.  No-op in legacy mode (no user_email), but that
        # branch is already guarded above.
        await _persist_scan_data(
            result=result,
            user_email=caller.user_email,
            token_id=caller.token_id,
            file_count=len(body.files),
            severity_counts=severity_counts,
            provider=provider_name,
            model=model_name or "",
            scan_id=result.scan_id,
            started_at=started_at,
            markdown_report=markdown_report,
            html_report=html_report,
        )

        return LocalScanResponse(
            markdown=markdown_report,
            html=html_report,
            findings_count=result.findings_count,
            **severity_counts,
            findings=result.findings,
        )
