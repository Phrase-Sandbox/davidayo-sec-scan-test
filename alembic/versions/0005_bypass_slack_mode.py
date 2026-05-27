"""Add bypass_slack_mode to org_settings.

Controls whether Slack bypass alerts fire for every bypass ("all"),
only for dev-repo bypasses ("dev_only", new default), or never ("none").
The server_default of "dev_only" backfills existing rows atomically.

Revision ID: 0005_bypass_slack_mode
Revises: 0004_slack_webhook
Create Date: 2026-05-27
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0005_bypass_slack_mode"
down_revision: Union[str, None] = "0004_slack_webhook"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "org_settings",
        sa.Column(
            "bypass_slack_mode",
            sa.String(16),
            nullable=False,
            server_default="dev_only",
        ),
    )


def downgrade() -> None:
    op.drop_column("org_settings", "bypass_slack_mode")
