"""Add ci_scan_records table for CI pipeline scan tracking.

Revision ID: 0007
Revises: 0006
Create Date: 2026-06-09
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ci_scan_records",
        sa.Column("scan_id", sa.Uuid(), primary_key=True),
        sa.Column("triggered_by", sa.String(320), nullable=False),
        sa.Column("repo_url", sa.String(2048), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("scan_target", sa.String(64), nullable=True),
        sa.Column(
            "status",
            sa.Enum("ok", "failed", name="scan_status", create_type=False),
            nullable=False,
            server_default="ok",
        ),
        sa.Column("findings_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("critical", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("high", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("medium", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("low", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("provider", sa.String(32), nullable=True),
        sa.Column("model", sa.String(128), nullable=True),
    )
    op.create_index("ix_ci_scan_records_triggered_by", "ci_scan_records", ["triggered_by"])
    op.create_index("ix_ci_scan_records_started_at", "ci_scan_records", ["started_at"])


def downgrade() -> None:
    op.drop_index("ix_ci_scan_records_started_at", "ci_scan_records")
    op.drop_index("ix_ci_scan_records_triggered_by", "ci_scan_records")
    op.drop_table("ci_scan_records")
