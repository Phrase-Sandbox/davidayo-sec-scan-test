"""Deployment-gate API for the GitHub Actions reusable workflow (§2.2 gate path, §7.3).

A single synchronous endpoint: ``POST /agent/scan``. The CI step blocks on
the response for up to ~5 min (gate sync decision — resolved-questions
section of the build plan) and reads ``gate_decision`` from the JSON body
to decide block vs pass.

The endpoint always returns HTTP 200 when the call is well-formed and
authenticated — the *gate* decision lives in the body, not the HTTP status.
Authentication failures (401) and request validation failures (422) are the
only non-200 responses.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from security_scanner.agent.auth import verify_scan_token
from security_scanner.agent.slack_alert import send_bypass_alert
from security_scanner.pipeline import ScanPipeline, TokenLimitError
from security_scanner.shared.config import Settings, get_settings
from security_scanner.shared.github.client import GitHubClient
from security_scanner.shared.llm.base import LLMConfigError
from security_scanner.shared.llm.factory import (
    build_llm_client,
    build_org_llm_client_from_settings,
)
from security_scanner.shared.logging_util import get_logger
from security_scanner.shared.models.enums import (
    GateDecision,
    ScanTarget,
    ScanType,
    Severity,
)
from security_scanner.shared.models.scan_result import ScanResult
from security_scanner.shared.reports.html import build_html_report
from security_scanner.tokens.db import get_session_factory
from security_scanner.tokens.models import CiScanRecord, ScanStatus

log = get_logger(__name__)

router = APIRouter(prefix="/agent", tags=["agent"])

_REPO_URL_RE = re.compile(r"^https://github\.com/[^/\s]+/[^/\s]+?(\.git)?/?$")


class ScanRequest(BaseModel):
    """Body of ``POST /agent/scan``."""

    repo_url: str
    scan_target: ScanTarget
    triggered_by: str
    ref: str = "HEAD"
    base: str | None = None
    head: str | None = None
    directory: str = ""
    # Optional per-run CI override: "anthropic" | "google".
    # Selects which org-configured key to use for this scan.
    # None → uses org_settings.default_provider (or env bootstrap fallback).
    provider_choice: str | None = None
    # Pre-fetched files from the CI runner. When provided the pipeline skips the
    # GitHub API fetch (no GitHub App credentials required on the scanner host).
    # Keys are repo-relative paths, values are UTF-8 source content.
    files: dict[str, str] | None = None


_SettingsDep = Annotated[Settings, Depends(get_settings)]


async def _load_active_org_settings():
    """Return the latest ``OrgSettings`` row, or ``None`` if none exist yet.

    ``None`` means we are in the bootstrap window (fresh install, no admin has
    saved keys via /admin/org-settings yet, or ``DATABASE_URL`` is not
    configured).  In that case the caller falls back to env-var credentials.
    """
    try:
        from sqlalchemy import select  # noqa: PLC0415

        from security_scanner.tokens.db import get_session_factory  # noqa: PLC0415
        from security_scanner.tokens.models import OrgSettings  # noqa: PLC0415

        factory = get_session_factory()
        async with factory() as session:
            stmt = select(OrgSettings).order_by(OrgSettings.id.desc()).limit(1)
            return (await session.execute(stmt)).scalar_one_or_none()
    except RuntimeError:
        # DATABASE_URL not configured (e.g. bootstrap / single-token mode).
        # Treat as "no org settings" → callers fall back to env-var credentials.
        return None


def _resolve_slack_webhook(org_row: object | None) -> str | None:
    """Decrypt the Slack webhook URL from org_row if one is stored.

    Returns ``None`` when no DB-stored webhook exists, signalling the caller
    (``send_*_alert``) to fall back to the ``SLACK_WEBHOOK_URL`` env var.
    """
    if org_row is None:
        return None
    encrypted = getattr(org_row, "encrypted_slack_webhook", None)
    if not encrypted:
        return None
    try:
        from security_scanner.tokens.crypto import decrypt  # noqa: PLC0415

        return decrypt(encrypted)
    except Exception:  # noqa: BLE001 — decryption error, fall back to env
        return None


async def get_pipeline(settings: _SettingsDep) -> ScanPipeline:
    """Build a gate-mode ``ScanPipeline`` from org settings (with env fallback).

    Production path: reads ``org_settings`` MAX(id) from DB, decrypts the
    configured provider's key, and builds a ``ScanPipeline`` using the org's
    credentials.

    Bootstrap fallback: when ``org_settings`` has no rows yet (first install
    window before an admin has saved keys via ``/admin/org-settings``), falls
    back to the ``ANTHROPIC_API_KEY`` / ``GOOGLE_API_KEY`` env vars exactly as
    before.  Once ``org_settings`` is populated, this fallback is never
    reached again.

    Tests override this via ``app.dependency_overrides[get_pipeline]`` to
    inject a mock pipeline — that override pattern is unaffected by this change.
    """
    github_client = GitHubClient(
        app_id=settings.GITHUB_APP_ID,
        private_key=settings.GITHUB_APP_PRIVATE_KEY,
    )
    org_row = await _load_active_org_settings()
    if org_row is not None:
        llm_client = build_org_llm_client_from_settings(org_row, settings=settings)
    else:
        # Bootstrap: no org_settings row yet — fall back to env vars.
        llm_client = build_llm_client(settings)
    return ScanPipeline(github_client, llm_client, mode=ScanType.deployment_gate)


_TokenDep = Annotated[str, Depends(verify_scan_token)]
_PipelineDep = Annotated[ScanPipeline, Depends(get_pipeline)]


async def _persist_ci_scan(
    result: ScanResult,
    started_at: datetime,
    html_report: str | None = None,
) -> None:
    """Write a row to ci_scan_records + bump llm_usage_monthly after /agent/scan."""

    def _count(sev: Severity) -> int:
        return sum(1 for f in result.findings if f.severity == sev)

    # Resolve provider/model from the same org_settings row the pipeline used.
    from security_scanner.shared.llm.factory import _get_model_for_provider  # noqa: PLC0415

    org_row = await _load_active_org_settings()
    provider = org_row.default_provider.value if org_row is not None else "anthropic"
    model = _get_model_for_provider(org_row, provider) or ""

    now = datetime.now(UTC)
    year_month = now.strftime("%Y-%m")

    record = CiScanRecord(
        scan_id=result.scan_id,
        triggered_by=result.triggered_by,
        repo_url=result.repo_url,
        started_at=started_at,
        finished_at=now,
        scan_target=result.scan_target.value if result.scan_target else None,
        status=ScanStatus.ok,
        findings_count=result.findings_count,
        critical=_count(Severity.Critical),
        high=_count(Severity.High),
        medium=_count(Severity.Medium),
        low=_count(Severity.Low),
        provider=provider,
        model=model,
        html_report=html_report,
    )

    usage = result.llm_usage
    factory = get_session_factory()
    async with factory() as session:
        session.add(record)

        # Upsert llm_usage_monthly so CI scans appear in the /admin/usage token spend table.
        if usage is not None:
            from sqlalchemy import select as sa_select  # noqa: PLC0415

            from security_scanner.tokens.models import LLMUsageMonthly  # noqa: PLC0415

            stmt = sa_select(LLMUsageMonthly).where(
                LLMUsageMonthly.user_email == result.triggered_by,
                LLMUsageMonthly.year_month == year_month,
                LLMUsageMonthly.provider == provider,
                LLMUsageMonthly.model == model,
            )
            monthly = (await session.execute(stmt)).scalar_one_or_none()
            if monthly is None:
                monthly = LLMUsageMonthly(
                    user_email=result.triggered_by,
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

        await session.commit()


@router.post("/scan")
async def scan(
    body: ScanRequest,
    _token: _TokenDep,
    pipeline: _PipelineDep,
    settings: _SettingsDep,
) -> StreamingResponse:
    if not _REPO_URL_RE.match(body.repo_url):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "Invalid repo_url; expected https://github.com/{org}/{repo} "
                f"(got {body.repo_url!r})"
            ),
        )

    # When provider_choice is sent, reload org_settings and rebuild the pipeline
    # for this scan only using the requested provider.  The injected `pipeline`
    # is otherwise reused — preserving test override patterns.
    if body.provider_choice is not None:
        org_row = await _load_active_org_settings()
        if org_row is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=(
                    "provider_choice is set but no org settings are configured. "
                    "Visit /admin/org-settings to save API keys first."
                ),
            )
        try:
            llm_client = build_org_llm_client_from_settings(
                org_row, body.provider_choice, settings=settings
            )
        except LLMConfigError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(exc),
            ) from exc
        pipeline = ScanPipeline(pipeline._github, llm_client, mode=pipeline._mode)

    started_at = datetime.now(UTC)

    async def _body() -> AsyncIterator[bytes]:
        # Run the scan as a task so we can yield heartbeat newlines while it
        # runs.  APISIX's read-idle timeout fires on silence; periodic \n bytes
        # prevent it without changing any platform config.
        task: asyncio.Task[ScanResult] = asyncio.create_task(
            pipeline.run(
                repo_url=body.repo_url,
                scan_target=body.scan_target,
                triggered_by=body.triggered_by,
                ref=body.ref,
                base=body.base,
                head=body.head,
                directory=body.directory,
                prefetched_files=body.files,
            )
        )

        while not task.done():
            done, _ = await asyncio.wait({task}, timeout=20)
            if not done:
                yield b"\n"

        try:
            result = task.result()
        except TokenLimitError as exc:
            log.warning(
                "token-limit exceeded — BR-005 advisory fallback",
                estimated_tokens=exc.estimated_tokens,
                threshold=exc.threshold,
            )
            result = _token_limit_advisory(body, exc)
        except Exception as exc:
            log.error("unexpected pipeline error", exc_info=True)
            result = _scan_failed_result(body, str(exc))

        if result.gate_decision == GateDecision.scan_failed:
            # Cannot return HTTP 502 once streaming has started — embed the
            # error in the body.  evaluate-findings treats scan_failed as a
            # pipeline error and fails the CI job.
            reason = result.warnings[0] if result.warnings else "scanner upstream error"
            log.warning("scan_failed streamed in body", reason=reason, scan_id=result.scan_id)
        else:
            try:
                try:
                    _html = build_html_report(result, files=body.files or [])
                except Exception:
                    _html = None
                await _persist_ci_scan(result, started_at, html_report=_html)
            except Exception:
                log.error("failed to persist ci_scan_record", scan_id=result.scan_id)

        yield result.model_dump_json().encode()

    return StreamingResponse(_body(), media_type="application/json")


class SlackConfigResponse(BaseModel):
    """Response from ``GET /agent/config/slack-webhook``."""

    webhook_url: str | None


@router.get("/config/slack-webhook", response_model=SlackConfigResponse)
async def get_slack_webhook_config(
    _token: _TokenDep,
    settings: _SettingsDep,
) -> SlackConfigResponse:
    """Return the active Slack webhook URL so CI can fetch it at runtime.

    Resolution order:
    1. Decrypted ``org_settings.encrypted_slack_webhook`` (set via admin portal).
    2. ``SLACK_WEBHOOK_URL`` environment variable (scanner host config).
    3. ``null`` — caller should fall back to its own local default.

    The CI pipeline calls this with its scanner bearer token so the webhook
    URL is managed in one place (the admin portal) rather than hardcoded in
    ``scanner.yml``.
    """
    org_row = await _load_active_org_settings()
    webhook_url = _resolve_slack_webhook(org_row) or settings.SLACK_WEBHOOK_URL
    return SlackConfigResponse(webhook_url=webhook_url)


class BypassRequest(BaseModel):
    """Body of ``POST /agent/bypass``.

    Carries the prior blocked ``ScanResult`` (already produced by
    ``/agent/scan``) plus who is bypassing and why. The reusable workflow
    invokes this when a developer opts to bypass a blocked gate.
    """

    result: ScanResult
    developer: str
    commit_sha: str
    justification: str | None = None
    caller_repo: str | None = None  # github.repository; distinguishes admin vs dev bypass


@router.post("/bypass", response_model=ScanResult)
async def bypass(body: BypassRequest, _token: _TokenDep) -> ScanResult:
    """Developer-invoked bypass of a blocked gate (BR-002 / EC-012).

    A written justification is **required** when Critical findings are
    present (BR-002). Records the bypass, posts the mandatory #security Slack
    alert, and returns a ``ScanResult`` with ``gate_decision=bypassed`` so
    CI/CD can proceed. The bypass itself never fails — Slack errors are
    swallowed by ``send_bypass_alert`` (BR-006 fail-open spirit).
    """
    result = body.result
    has_critical = any(f.severity == Severity.Critical for f in result.findings)
    if has_critical and not (body.justification and body.justification.strip()):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "Critical findings present — a written justification is "
                "required before a bypass is accepted (BR-002)."
            ),
        )

    bypassed = result.model_copy(
        update={
            "gate_decision": GateDecision.bypassed,
            "bypass_invoked": True,
            "triggered_by": body.developer,
        }
    )

    critical = sum(1 for f in bypassed.findings if f.severity == Severity.Critical)
    high = sum(1 for f in bypassed.findings if f.severity == Severity.High)
    log.warning(
        "deployment gate bypassed",
        developer=body.developer,
        repo=bypassed.repo_url,
        commit_sha=body.commit_sha,
        critical=critical,
        high=high,
        justification_provided=bool(body.justification),
    )
    org_row = await _load_active_org_settings()
    bypass_slack_mode = getattr(org_row, "bypass_slack_mode", "dev_only") if org_row else "dev_only"
    await send_bypass_alert(
        bypassed,
        body.developer,
        body.commit_sha,
        body.justification,
        caller_repo=body.caller_repo,
        bypass_slack_mode=bypass_slack_mode,
        webhook_url=_resolve_slack_webhook(org_row),
    )
    return bypassed


def _scan_failed_result(body: ScanRequest, reason: str) -> ScanResult:
    """Wrap an unexpected pipeline exception as a scan_failed ScanResult."""
    return ScanResult(
        repo_url=body.repo_url,
        scan_target=body.scan_target,
        scan_type=ScanType.deployment_gate,
        triggered_by=body.triggered_by,
        findings_count=0,
        gate_decision=GateDecision.scan_failed,
        partial_scan=False,
        unscanned_files=[],
        findings=[],
        warnings=[reason],
    )


def _token_limit_advisory(body: ScanRequest, exc: TokenLimitError) -> ScanResult:
    """Translate ``TokenLimitError`` into a 200/advisory ``ScanResult`` (BR-005)."""
    return ScanResult(
        repo_url=body.repo_url,
        scan_target=body.scan_target,
        scan_type=ScanType.deployment_gate,
        triggered_by=body.triggered_by,
        findings_count=0,
        gate_decision=GateDecision.advisory,
        partial_scan=False,
        unscanned_files=[],
        findings=[],
        warnings=[
            f"Repository exceeds scan size limit (~{exc.estimated_tokens} tokens, "
            f"max {exc.threshold}). Recommend scanning by directory before merge "
            "(BR-005). Deployment may proceed but the codebase was not analysed."
        ],
    )
