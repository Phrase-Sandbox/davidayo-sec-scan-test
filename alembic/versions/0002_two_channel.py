"""Two-channel model: per-user BYO settings + org CI config.

New tables:
  users, user_llm_settings, org_settings, scan_records, scan_usage,
  llm_usage_monthly, ci_tokens

Existing table changes:
  local_scan_tokens: add expires_at (nullable; NULL = legacy no-expiry)
  audit_events enum: add user_deactivated, user_reactivated,
    user_llm_settings_updated, org_config_changed, ci_token_rotated

Revision ID: 0002_two_channel
Revises: 0001_init
Create Date: 2026-05-26
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0002_two_channel"
down_revision: str | None = "0001_init"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ----- New enum types -----------------------------------------------

    user_role = sa.Enum("user", "admin", name="user_role")
    llm_provider = sa.Enum("anthropic", "google", name="llm_provider")
    scan_status = sa.Enum("ok", "partial", "failed", "unauthorized", name="scan_status")

    # ----- Extend existing audit_event_type enum ------------------------
    # Postgres requires ALTER TYPE … ADD VALUE; SQLite stores enums as
    # VARCHAR so this is a no-op there. We use a raw string to avoid
    # Alembic trying to drop/recreate the type on PG.
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for new_value in [
            "user_deactivated",
            "user_reactivated",
            "user_llm_settings_updated",
            "org_config_changed",
            "ci_token_rotated",
        ]:
            bind.execute(
                sa.text(f"ALTER TYPE audit_event_type ADD VALUE IF NOT EXISTS '{new_value}'")
            )

    # ----- local_scan_tokens: add expires_at ----------------------------
    op.add_column(
        "local_scan_tokens",
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
    )

    # ----- users --------------------------------------------------------
    op.create_table(
        "users",
        sa.Column("email", sa.String(length=320), primary_key=True),
        sa.Column(
            "role",
            user_role,
            nullable=False,
            server_default="user",
        ),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "okta_groups",
            postgresql.JSONB().with_variant(sa.JSON(), "sqlite"),
            nullable=True,
        ),
    )

    # ----- user_llm_settings -------------------------------------------
    op.create_table(
        "user_llm_settings",
        sa.Column("user_email", sa.String(length=320), primary_key=True),
        sa.Column("provider", llm_provider, nullable=False),
        sa.Column("model", sa.String(length=128), nullable=False),
        sa.Column("encrypted_api_key", sa.LargeBinary(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_email"], ["users.email"], ondelete="CASCADE"),
    )

    # ----- org_settings (immutable-history; latest row = MAX(id)) -------
    op.create_table(
        "org_settings",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("encrypted_anthropic_key", sa.LargeBinary(), nullable=True),
        sa.Column("encrypted_google_key", sa.LargeBinary(), nullable=True),
        sa.Column("default_provider", llm_provider, nullable=False, server_default="anthropic"),
        sa.Column("default_model", sa.String(length=128), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by_email", sa.String(length=320), nullable=False),
    )

    # ----- scan_records -------------------------------------------------
    op.create_table(
        "scan_records",
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_email", sa.String(length=320), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("repo_url", sa.String(length=2048), nullable=False),
        sa.Column("scan_target", sa.String(length=64), nullable=True),
        sa.Column("status", scan_status, nullable=False, server_default="ok"),
        sa.Column("findings_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("critical", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("high", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("medium", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("low", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("markdown_report", sa.Text(), nullable=True),
        sa.Column("html_report", sa.Text(), nullable=True),
        sa.Column("provider", sa.String(length=32), nullable=True),
        sa.Column("model", sa.String(length=128), nullable=True),
        sa.ForeignKeyConstraint(["user_email"], ["users.email"], ondelete="CASCADE"),
    )
    op.create_index("ix_scan_records_user_email", "scan_records", ["user_email"])
    op.create_index("ix_scan_records_started_at", "scan_records", ["started_at"])

    # ----- scan_usage (one row per scan) --------------------------------
    op.create_table(
        "scan_usage",
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("model", sa.String(length=128), nullable=False),
        sa.Column("n_llm_calls", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("input_tokens", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("output_tokens", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column(
            "cache_creation_input_tokens",
            sa.BigInteger(),
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "cache_read_input_tokens",
            sa.BigInteger(),
            nullable=False,
            server_default="0",
        ),
        # comma-separated provider response IDs for cross-referencing in
        # the provider's own console.  Kept as text; each ID ≤ 32 chars.
        sa.Column("response_ids", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["scan_id"], ["scan_records.scan_id"], ondelete="CASCADE"),
    )

    # ----- llm_usage_monthly (aggregate; updated UPSERT per scan) ------
    op.create_table(
        "llm_usage_monthly",
        sa.Column("user_email", sa.String(length=320), nullable=False),
        sa.Column("year_month", sa.String(length=7), nullable=False),  # "2026-05"
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("model", sa.String(length=128), nullable=False),
        sa.Column("input_tokens", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("output_tokens", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column(
            "cache_creation_input_tokens",
            sa.BigInteger(),
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "cache_read_input_tokens",
            sa.BigInteger(),
            nullable=False,
            server_default="0",
        ),
        sa.Column("scan_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_updated", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("user_email", "year_month", "provider", "model"),
    )

    # ----- ci_tokens (rotate = insert new row, revoke old) -------------
    op.create_table(
        "ci_tokens",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by_email", sa.String(length=320), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by_email", sa.String(length=320), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("ci_tokens")
    op.drop_table("llm_usage_monthly")
    op.drop_table("scan_usage")
    op.drop_index("ix_scan_records_started_at", table_name="scan_records")
    op.drop_index("ix_scan_records_user_email", table_name="scan_records")
    op.drop_table("scan_records")
    op.drop_table("org_settings")
    op.drop_table("user_llm_settings")
    op.drop_table("users")

    op.drop_column("local_scan_tokens", "expires_at")

    # Note: Postgres does not support removing enum values; the added
    # audit_event_type values remain in the type on downgrade.
    # The enums created in this migration are dropped below.
    for enum_name in ["scan_status", "llm_provider", "user_role"]:
        sa.Enum(name=enum_name).drop(op.get_bind(), checkfirst=True)
