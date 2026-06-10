"""Add app_groups, app_group_members, app_group_permissions tables.

Revision ID: 0015
Revises: 0014
Create Date: 2026-06-10

These three tables implement an app-managed RBAC layer independent of Okta.
Protected admins bypass all group checks server-side; this table is purely
for additional view-level access delegation.
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID as PG_UUID

from alembic import op

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Extend the native PostgreSQL audit_event_type enum with group operations.
    # IF NOT EXISTS makes this safe to re-run if the value was already added.
    for value in (
        "group_created",
        "group_deleted",
        "group_member_added",
        "group_member_removed",
        "group_permission_added",
        "group_permission_removed",
    ):
        op.execute(f"ALTER TYPE audit_event_type ADD VALUE IF NOT EXISTS '{value}'")

    op.create_table(
        "app_groups",
        sa.Column(
            "id",
            sa.Uuid().with_variant(PG_UUID(as_uuid=True), "postgresql"),
            primary_key=True,
        ),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("description", sa.String(512), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(320), nullable=False),
        sa.UniqueConstraint("name", name="uq_app_groups_name"),
    )

    op.create_table(
        "app_group_members",
        sa.Column(
            "group_id",
            sa.Uuid().with_variant(PG_UUID(as_uuid=True), "postgresql"),
            sa.ForeignKey("app_groups.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "user_email",
            sa.String(320),
            sa.ForeignKey("users.email", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("added_by", sa.String(320), nullable=False),
    )
    op.create_index("ix_app_group_members_user_email", "app_group_members", ["user_email"])

    op.create_table(
        "app_group_permissions",
        sa.Column(
            "group_id",
            sa.Uuid().with_variant(PG_UUID(as_uuid=True), "postgresql"),
            sa.ForeignKey("app_groups.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("permission", sa.String(64), primary_key=True),
    )


def downgrade() -> None:
    op.drop_table("app_group_permissions")
    op.drop_index("ix_app_group_members_user_email", table_name="app_group_members")
    op.drop_table("app_group_members")
    op.drop_table("app_groups")
