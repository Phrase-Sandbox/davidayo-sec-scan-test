"""Add enable_quality_gate to scanner_settings.

Revision ID: 0011
Revises: 0010
Create Date: 2026-06-09
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scanner_settings",
        sa.Column(
            "enable_quality_gate",
            sa.Boolean(),
            nullable=False,
            server_default="false",
        ),
    )


def downgrade() -> None:
    op.drop_column("scanner_settings", "enable_quality_gate")
