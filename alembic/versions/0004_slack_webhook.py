"""Add encrypted_slack_webhook to org_settings; extend audit_event_type enum.

Stores the Slack webhook URL as a Fernet-encrypted blob alongside the other
org secrets.  NULL = not configured (fall back to SLACK_WEBHOOK_URL env var).

Revision ID: 0004_slack_webhook
Revises: 0003_admin_model_control
Create Date: 2026-05-26
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0004_slack_webhook"
down_revision: str | None = "0003_admin_model_control"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # --- Extend the audit_event_type enum (Postgres only) -------------------
    # SQLite stores enums as VARCHAR so the new value is automatically valid.
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        bind.execute(
            sa.text(
                "ALTER TYPE audit_event_type ADD VALUE IF NOT EXISTS 'slack_webhook_configured'"
            )
        )

    # --- Add encrypted_slack_webhook to org_settings -------------------------
    op.add_column(
        "org_settings",
        sa.Column("encrypted_slack_webhook", sa.LargeBinary(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("org_settings", "encrypted_slack_webhook")
    # Postgres cannot remove enum values once added; leave slack_webhook_configured
    # in the type — it simply becomes unused on downgrade.
