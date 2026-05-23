"""Audit dual-write helper.

Every audit-worthy event lands in TWO places:

1. The ``audit_events`` table — queryable by the admin UI without needing
   ``kubectl logs`` access.
2. A structured ``log.info`` line — preserves the existing observability
   story (Loki/Datadog scrapes stdout already).

The DB row is the source of truth for the UI; the log line is for ops
scrape. Neither carries file paths or content — only severity counts,
outcomes, identifiers.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from security_scanner.shared.logging_util import get_logger
from security_scanner.tokens.models import AuditEvent, AuditEventType

log = get_logger(__name__)


async def record(
    session: AsyncSession,
    *,
    event_type: AuditEventType,
    user_email: str | None = None,
    token_id: str | None = None,
    actor_email: str | None = None,
    request_id: str | None = None,
    **metadata: Any,
) -> AuditEvent:
    """Insert an audit row and emit a structured log line. Returns the row.

    The caller owns the session/transaction. We deliberately do NOT commit
    here so the audit insert participates in the surrounding business
    transaction (e.g. ``issue_or_rotate`` writes the token row and the audit
    row atomically).
    """
    row = AuditEvent(
        at=datetime.now(UTC),
        event_type=event_type,
        user_email=user_email,
        token_id=token_id,
        actor_email=actor_email,
        event_metadata=metadata or None,
        request_id=request_id,
    )
    session.add(row)

    log.info(
        "audit",
        event_type=event_type.value,
        user_email=user_email,
        token_id=token_id,
        actor_email=actor_email,
        request_id=request_id,
        **metadata,
    )
    return row
