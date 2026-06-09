"""Add Okta identity fields and password reset support to users table.

Revision ID: 0006
Revises: 0005
Create Date: 2026-06-07
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0006"
down_revision = "0005_bypass_slack_mode"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("okta_user_id", sa.String(255), nullable=True))
    op.add_column(
        "users",
        sa.Column("auth_provider", sa.String(16), nullable=False, server_default="local"),
    )
    op.add_column("users", sa.Column("password_hash", sa.LargeBinary(), nullable=True))
    op.add_column(
        "users",
        sa.Column(
            "must_change_password", sa.Boolean(), nullable=False, server_default="false"
        ),
    )
    op.add_column(
        "users",
        sa.Column("last_reactivation_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column("users", sa.Column("display_name", sa.String(255), nullable=True))
    op.create_unique_constraint("uq_users_okta_user_id", "users", ["okta_user_id"])
    op.create_index("ix_users_okta_user_id", "users", ["okta_user_id"])

    # Extend the Postgres enum — IF NOT EXISTS guards idempotent replay
    for val in (
        "user_password_force_reset",
        "user_password_changed",
        "user_okta_login",
        "user_local_login",
    ):
        op.execute(
            f"ALTER TYPE audit_event_type ADD VALUE IF NOT EXISTS '{val}'"
        )


def downgrade() -> None:
    op.drop_index("ix_users_okta_user_id", "users")
    op.drop_constraint("uq_users_okta_user_id", "users", type_="unique")
    for col in (
        "display_name",
        "last_reactivation_at",
        "must_change_password",
        "password_hash",
        "auth_provider",
        "okta_user_id",
    ):
        op.drop_column("users", col)
    # Note: Postgres does not support DROP VALUE on enums.
    # The four new enum values are left in place on downgrade (harmless).
