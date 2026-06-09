"""Add scanner_settings table for runtime scanner tuning.

Revision ID: 0008
Revises: 0007
Create Date: 2026-06-09
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scanner_settings",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("keep_confidences", sa.String(64), nullable=False, server_default="high,medium"),
        sa.Column("advisory_confidences", sa.String(64), nullable=False, server_default="low"),
        sa.Column("enable_semgrep", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("enable_bandit", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("enable_gosec", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("enable_eslint", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("semgrep_owasp", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("semgrep_audit", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("semgrep_upload", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("vuln_verifier_parallelism", sa.Integer(), nullable=False, server_default="2"),
        sa.Column("high_risk_paths", sa.Text(), nullable=False, server_default=""),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by_email", sa.String(320), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("scanner_settings")
