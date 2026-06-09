"""Initial schema: local_scan_tokens + audit_events.

Revision ID: 0001_init
Revises:
Create Date: 2026-05-23
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0001_init"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    issued_via = sa.Enum("self_portal", "admin_force_rotate", name="issued_via")
    audit_event_type = sa.Enum(
        "scan_ok",
        "scan_unauthorized",
        "token_issued",
        "token_rotated",
        "token_revoked",
        "admin_force_rotate",
        name="audit_event_type",
    )

    op.create_table(
        "local_scan_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("token_id", sa.String(length=16), nullable=False),
        sa.Column("user_email", sa.String(length=320), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("issued_via", issued_via, nullable=False),
        sa.Column("issued_by", sa.String(length=320), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.String(length=320), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_local_scan_tokens_token_id",
        "local_scan_tokens",
        ["token_id"],
        unique=False,
    )
    op.create_index(
        "ix_local_scan_tokens_user_email",
        "local_scan_tokens",
        ["user_email"],
        unique=False,
    )
    # At most one active token per user — enforced at the DB layer.
    op.create_index(
        "ix_local_scan_tokens_one_active_per_user",
        "local_scan_tokens",
        ["user_email"],
        unique=True,
        postgresql_where=sa.text("revoked_at IS NULL"),
    )

    op.create_table(
        "audit_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_type", audit_event_type, nullable=False),
        sa.Column("user_email", sa.String(length=320), nullable=True),
        sa.Column("token_id", sa.String(length=16), nullable=True),
        sa.Column("actor_email", sa.String(length=320), nullable=True),
        sa.Column("metadata", postgresql.JSONB, nullable=True),
        sa.Column("request_id", sa.String(length=64), nullable=True),
    )
    op.create_index("ix_audit_events_at", "audit_events", ["at"])
    op.create_index("ix_audit_events_event_type", "audit_events", ["event_type"])
    op.create_index("ix_audit_events_user_email", "audit_events", ["user_email"])
    op.create_index("ix_audit_events_token_id", "audit_events", ["token_id"])


def downgrade() -> None:
    op.drop_index("ix_audit_events_token_id", table_name="audit_events")
    op.drop_index("ix_audit_events_user_email", table_name="audit_events")
    op.drop_index("ix_audit_events_event_type", table_name="audit_events")
    op.drop_index("ix_audit_events_at", table_name="audit_events")
    op.drop_table("audit_events")

    op.drop_index("ix_local_scan_tokens_one_active_per_user", table_name="local_scan_tokens")
    op.drop_index("ix_local_scan_tokens_user_email", table_name="local_scan_tokens")
    op.drop_index("ix_local_scan_tokens_token_id", table_name="local_scan_tokens")
    op.drop_table("local_scan_tokens")

    sa.Enum(name="audit_event_type").drop(op.get_bind(), checkfirst=False)
    sa.Enum(name="issued_via").drop(op.get_bind(), checkfirst=False)
