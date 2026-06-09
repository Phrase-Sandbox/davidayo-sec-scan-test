"""Add report_retention_days to scanner_settings.

Revision ID: 0012
Revises: 0011
Create Date: 2026-06-09
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scanner_settings",
        sa.Column("report_retention_days", sa.Integer(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("scanner_settings", "report_retention_days")
