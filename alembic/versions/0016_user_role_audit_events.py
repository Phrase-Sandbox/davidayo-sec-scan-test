"""Add user_promoted and user_demoted to audit_event_type enum.

Revision ID: 0016
Revises: 0015
Create Date: 2026-06-10

These two values were added to the AuditEventType Python enum alongside the
user role-management feature but the corresponding ALTER TYPE statements were
never included in a migration, causing a 500 on promote/demote actions.
"""

from __future__ import annotations

from alembic import op

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for value in ("user_promoted", "user_demoted"):
        op.execute(f"ALTER TYPE audit_event_type ADD VALUE IF NOT EXISTS '{value}'")


def downgrade() -> None:
    # PostgreSQL does not support removing enum values; downgrade is a no-op.
    pass
