"""Slack #security alerter (BR-002, EC-012, Appendix D-16).

Two mandatory security-audit alerts (NOT general notifications, which stay
out of scope per §14 "Phase 2"):

* ``send_bypass_alert`` — a developer invoked bypass on a blocked gate
  (BR-002 / EC-012). Unchanged behaviour.
* ``send_pr_rejected_alert`` — a developer rejected (closed unmerged) the
  bot's auto-fix PR (D-16). Only sent for High/Critical findings; the caller
  applies that rule.

If ``SLACK_WEBHOOK_URL`` is not configured the function logs a warning and
returns silently. Slack HTTP failures are logged but never raised — the
deploy / repo action proceeds regardless of Slack availability (BR-006
fail-open spirit). The webhook secret lives only on the service.
"""

from __future__ import annotations

import httpx

from security_scanner.shared.config import get_settings
from security_scanner.shared.logging_util import get_logger
from security_scanner.shared.models.enums import Severity
from security_scanner.shared.models.scan_result import ScanResult

log = get_logger(__name__)

HTTP_TIMEOUT_SECONDS = 5.0


async def _post_to_slack(
    text: str,
    *,
    kind: str,
    http_client: httpx.AsyncClient | None,
    webhook_url: str | None = None,
    **log_ctx: object,
) -> None:
    """POST ``text`` to the #security webhook; fail-open.

    ``kind`` is the alert label used in the log line (e.g. ``"bypass"`` ⇒
    "slack bypass alert failed") so per-alert log assertions stay stable.
    ``log_ctx`` is non-sensitive context only — never the justification /
    rejection reason body (kept out of logs by the transport; the audit log
    that intentionally records the reason lives in the calling endpoint).

    ``webhook_url`` may be passed explicitly (e.g. from a DB-stored encrypted
    value decrypted by the caller).  If omitted, falls back to the
    ``SLACK_WEBHOOK_URL`` environment variable.  DB value takes precedence
    so the admin portal can override infra config without a restart.
    """
    webhook = webhook_url or get_settings().SLACK_WEBHOOK_URL
    if webhook is None:
        log.warning("slack webhook not configured — alert skipped", kind=kind)
        return

    owns_client = http_client is None
    client = http_client or httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS)
    try:
        try:
            response = await client.post(webhook, json={"text": text})
            response.raise_for_status()
        except httpx.HTTPError as exc:
            log.warning(
                f"slack {kind} alert failed — proceeding regardless",
                error=type(exc).__name__,
                **log_ctx,
            )
        else:
            log.info(f"{kind} alert sent to slack", **log_ctx)
    finally:
        if owns_client:
            await client.aclose()


async def send_bypass_alert(
    result: ScanResult,
    developer: str,
    commit_sha: str,
    justification: str | None = None,
    *,
    http_client: httpx.AsyncClient | None = None,
    webhook_url: str | None = None,
) -> None:
    """POST a structured bypass alert to the #security webhook.

    Enforcement of "Critical bypasses require justification" is the caller's
    responsibility (the ``/agent/bypass`` endpoint). This module sends
    whatever it is given.

    Pass ``webhook_url`` to override the ``SLACK_WEBHOOK_URL`` env var with a
    DB-stored value (e.g. decrypted from ``OrgSettings.encrypted_slack_webhook``).
    """
    await _post_to_slack(
        _build_message_text(result, developer, commit_sha, justification),
        kind="bypass",
        http_client=http_client,
        webhook_url=webhook_url,
        developer=developer,
        commit_sha=commit_sha,
    )


async def send_llm_unavailable_alert(
    *,
    scan_id: str,
    reason: str,
    provider: str,
    triggered_by: str,
    repo_url: str,
    http_client: httpx.AsyncClient | None = None,
    webhook_url: str | None = None,
) -> None:
    """POST a "scanner LLM upstream unavailable" alert to the #security webhook.

    Fired when default-mode scans (org credentials) fully fail to reach the
    LLM — typically org-key quota exhaustion or provider outage. The user's
    scan still returns an advisory partial result (BR-006 fail-open), but
    the security team needs an immediate signal to top up / rotate the key.

    Reason text from the upstream SDK is included verbatim so on-call can
    triage; we trust upstream errors not to embed credentials, and the
    field-name redaction (``api_key`` in REDACT_FIELDS) catches any
    accidental field-form key leakage at the structured-log layer.
    """
    is_quota = any(
        kw in reason.lower()
        for kw in ("quota", "resource_exhausted", "exceeded", "billing")
    )
    headline = (
        "🚨 *Scanner LLM quota exhausted*"
        if is_quota
        else "🚨 *Scanner LLM upstream unavailable*"
    )
    text = (
        f"{headline}\n"
        f"• Provider: `{provider}`\n"
        f"• Triggered by: `{triggered_by}`\n"
        f"• Repo: {repo_url}\n"
        f"• Scan id: `{scan_id}`\n"
        f"• Upstream error: {reason}\n"
        "Scan returned an advisory partial result; the codebase was NOT "
        "analysed. Top up / rotate the org LLM key, then re-run the gate."
    )
    await _post_to_slack(
        text,
        kind="llm-unavailable",
        http_client=http_client,
        webhook_url=webhook_url,
        provider=provider,
        scan_id=scan_id,
        is_quota=is_quota,
    )


async def send_pr_rejected_alert(
    *,
    repo_url: str,
    pr_number: int,
    pr_url: str,
    closed_by: str,
    closed_at: str,
    reason: str | None,
    critical: int,
    high: int,
    http_client: httpx.AsyncClient | None = None,
    webhook_url: str | None = None,
) -> None:
    """POST a "bot auto-fix PR rejected" alert (D-16).

    The caller (``/agent/pr-event``) only invokes this for High/Critical
    findings — the severity rule and the always-on audit log live there.
    """
    await _post_to_slack(
        _build_pr_rejected_text(
            repo_url, pr_number, pr_url, closed_by, closed_at, reason, critical, high
        ),
        kind="pr-rejected",
        http_client=http_client,
        webhook_url=webhook_url,
        pr_number=pr_number,
        closed_by=closed_by,
    )


def _build_message_text(
    result: ScanResult,
    developer: str,
    commit_sha: str,
    justification: str | None,
) -> str:
    critical_count = sum(1 for f in result.findings if f.severity == Severity.Critical)
    high_count = sum(1 for f in result.findings if f.severity == Severity.High)

    lines = [
        "🚨 *Security scan bypass invoked*",
        f"• *Developer*: {developer}",
        f"• *Repository*: {result.repo_url}",
        f"• *Commit*: `{commit_sha}`",
        f"• *Timestamp*: {result.timestamp.isoformat()}",
        f"• *Findings*: {critical_count} Critical, {high_count} High",
    ]
    if justification is not None:
        lines.append(f"• *Justification*: {justification}")
    return "\n".join(lines)


def _build_pr_rejected_text(
    repo_url: str,
    pr_number: int,
    pr_url: str,
    closed_by: str,
    closed_at: str,
    reason: str | None,
    critical: int,
    high: int,
) -> str:
    lines = [
        "🛑 *Security auto-fix PR rejected*",
        f"• *Repository*: {repo_url}",
        f"• *PR*: #{pr_number} {pr_url}",
        f"• *Closed by*: {closed_by}",
        f"• *When*: {closed_at}",
        f"• *Findings*: {critical} Critical, {high} High",
    ]
    if reason and reason.strip():
        lines.append(f"• *Reason*: {reason.strip()}")
    else:
        lines.append("• ⚠️ *REASON MISSING — follow up required*")
    return "\n".join(lines)
