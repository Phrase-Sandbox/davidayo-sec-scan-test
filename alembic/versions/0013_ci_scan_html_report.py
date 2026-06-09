"""Add html_report to ci_scan_records.

Revision ID: 0013
Revises: 0012
Create Date: 2026-06-09
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("ci_scan_records", sa.Column("html_report", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("ci_scan_records", "html_report")
