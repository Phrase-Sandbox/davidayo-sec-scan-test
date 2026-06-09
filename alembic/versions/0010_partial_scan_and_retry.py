"""Add enable_partial_scan and enable_zero_findings_retry to scanner_settings.

Revision ID: 0010
Revises: 0009
Create Date: 2026-06-09
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scanner_settings",
        sa.Column(
            "enable_partial_scan",
            sa.Boolean(),
            nullable=False,
            server_default="true",
        ),
    )
    op.add_column(
        "scanner_settings",
        sa.Column(
            "enable_zero_findings_retry",
            sa.Boolean(),
            nullable=False,
            server_default="true",
        ),
    )


def downgrade() -> None:
    op.drop_column("scanner_settings", "enable_zero_findings_retry")
    op.drop_column("scanner_settings", "enable_partial_scan")
