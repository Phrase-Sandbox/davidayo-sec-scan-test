"""Admin-controlled per-provider model columns.

Changes:
  org_settings:
    - ADD anthropic_model VARCHAR(128) nullable
    - ADD google_model VARCHAR(128) nullable
    - DROP default_model

  user_llm_settings:
    - ALTER model DROP NOT NULL (column kept for backward-compat; no longer
      read in application logic — admin-set org model is used instead)

Revision ID: 0003_admin_model_control
Revises: 0002_two_channel
Create Date: 2026-05-26
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0003_admin_model_control"
down_revision: str | None = "0002_two_channel"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()

    # ----- org_settings: add per-provider model columns --------------------
    op.add_column(
        "org_settings",
        sa.Column("anthropic_model", sa.String(128), nullable=True),
    )
    op.add_column(
        "org_settings",
        sa.Column("google_model", sa.String(128), nullable=True),
    )

    # Migrate data: copy default_model into the appropriate per-provider column
    # based on the default_provider for each row. This preserves existing config.
    if bind.dialect.name == "postgresql":
        bind.execute(
            sa.text(
                """
                UPDATE org_settings
                SET anthropic_model = default_model
                WHERE default_provider = 'anthropic' AND default_model IS NOT NULL;

                UPDATE org_settings
                SET google_model = default_model
                WHERE default_provider = 'google' AND default_model IS NOT NULL;
                """
            )
        )

    # ----- org_settings: drop the now-superseded default_model column ------
    op.drop_column("org_settings", "default_model")

    # ----- user_llm_settings: make model nullable --------------------------
    if bind.dialect.name == "postgresql":
        bind.execute(sa.text("ALTER TABLE user_llm_settings ALTER COLUMN model DROP NOT NULL"))
    else:
        # SQLite doesn't support ALTER COLUMN; recreate the table.
        # In practice tests use SQLite; production uses Postgres.
        with op.batch_alter_table("user_llm_settings") as batch_op:
            batch_op.alter_column("model", existing_type=sa.String(128), nullable=True)


def downgrade() -> None:
    bind = op.get_bind()

    # ----- user_llm_settings: restore NOT NULL on model --------------------
    if bind.dialect.name == "postgresql":
        # Backfill NULLs with a placeholder before restoring NOT NULL.
        bind.execute(
            sa.text("UPDATE user_llm_settings SET model = '(restored)' WHERE model IS NULL")
        )
        bind.execute(sa.text("ALTER TABLE user_llm_settings ALTER COLUMN model SET NOT NULL"))
    else:
        with op.batch_alter_table("user_llm_settings") as batch_op:
            batch_op.alter_column("model", existing_type=sa.String(128), nullable=False)

    # ----- org_settings: restore default_model -----------------------------
    op.add_column(
        "org_settings",
        sa.Column("default_model", sa.String(128), nullable=True),
    )

    # Migrate back: restore default_model from the per-provider columns.
    if bind.dialect.name == "postgresql":
        bind.execute(
            sa.text(
                """
                UPDATE org_settings
                SET default_model = COALESCE(anthropic_model, google_model);
                """
            )
        )

    op.drop_column("org_settings", "anthropic_model")
    op.drop_column("org_settings", "google_model")
