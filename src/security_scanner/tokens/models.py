"""ORM models for the token registry and the audit log.

Conventions:
- Soft-delete rather than hard-delete a token (``revoked_at``) so historic
  audit events still resolve ``token_id → user_email``.
- Token rotation = mark current row revoked, insert a new row reusing the
  same ``token_id`` prefix. That keeps the user's identity continuous in
  audit logs across rotations.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    DateTime,
    Enum,
    Index,
    String,
    Uuid,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from security_scanner.tokens.db import Base

# JSONB on Postgres, generic JSON elsewhere. Production stays JSONB
# (indexable / queryable); tests on SQLite get plain JSON.
_JsonType = JSON().with_variant(JSONB(), "postgresql")


class IssuedVia(str, enum.Enum):
    self_portal = "self_portal"
    admin_force_rotate = "admin_force_rotate"


class AuditEventType(str, enum.Enum):
    scan_ok = "scan_ok"
    scan_unauthorized = "scan_unauthorized"
    token_issued = "token_issued"
    token_rotated = "token_rotated"
    token_revoked = "token_revoked"
    admin_force_rotate = "admin_force_rotate"


class LocalScanToken(Base):
    __tablename__ = "local_scan_tokens"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    # 12-hex prefix embedded in the token string — stable per user across
    # rotations. NOT unique by itself (a user may have many historical rows
    # with the same prefix; only one is active at a time — enforced at the
    # app layer, plus a PG-only partial unique index for concurrency safety
    # added in the Alembic migration).
    # 16 chars: literal "tok-" (4) + 12 hex chars. NOT 12.
    token_id: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    user_email: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    issued_via: Mapped[IssuedVia] = mapped_column(
        Enum(IssuedVia, name="issued_via"), nullable=False
    )
    issued_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    event_type: Mapped[AuditEventType] = mapped_column(
        Enum(AuditEventType, name="audit_event_type"), nullable=False, index=True
    )
    user_email: Mapped[str | None] = mapped_column(String(320), nullable=True, index=True)
    token_id: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    actor_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    # Never paths or content — see CLAUDE.md §local-scan privacy. Free-form
    # bag for severity counts, outcomes, request IDs, etc.
    event_metadata: Mapped[dict | None] = mapped_column("metadata", _JsonType, nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
