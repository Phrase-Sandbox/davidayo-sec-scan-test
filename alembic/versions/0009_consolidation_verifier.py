"""Add enable_consolidation_verifier column to scanner_settings.

Revision ID: 0009
Revises: 0008
Create Date: 2026-06-09
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scanner_settings",
        sa.Column(
            "enable_consolidation_verifier",
            sa.Boolean(),
            nullable=False,
            server_default="false",
        ),
    )


def downgrade() -> None:
    op.drop_column("scanner_settings", "enable_consolidation_verifier")
