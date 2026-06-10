"""Encrypt existing html_report and markdown_report rows at rest.

Revision ID: 0014
Revises: 0013
Create Date: 2026-06-10

If SCANNER_ENCRYPTION_KEY is set in the environment, every non-null report
column in scan_records and ci_scan_records is encrypted with Fernet in-place.
If the key is absent (e.g. local dev without secrets), the migration is a
no-op so startup is not blocked — new writes will also be unencrypted until
the key is configured.

Legacy plaintext rows are detected by the absence of the Fernet token prefix
(``gAAAAA``) so the upgrade is idempotent: running it twice is safe.
"""

from __future__ import annotations

import os

import sqlalchemy as sa

from alembic import op

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None

_FERNET_PREFIX = "gAAAAA"


def upgrade() -> None:
    key = os.environ.get("SCANNER_ENCRYPTION_KEY")
    if not key:
        return

    try:
        from cryptography.fernet import Fernet  # noqa: PLC0415

        fernet = Fernet(key.encode())
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(
            "SCANNER_ENCRYPTION_KEY is set but invalid — cannot encrypt report columns."
        ) from exc

    bind = op.get_bind()

    # ── scan_records ────────────────────────────────────────────────────────
    rows = bind.execute(
        sa.text(
            "SELECT scan_id, html_report, markdown_report FROM scan_records "
            "WHERE html_report IS NOT NULL OR markdown_report IS NOT NULL"
        )
    ).fetchall()

    for row in rows:
        updates: dict[str, str] = {}
        if row.html_report and not row.html_report.startswith(_FERNET_PREFIX):
            updates["html_report"] = fernet.encrypt(
                row.html_report.encode("utf-8")
            ).decode("ascii")
        if row.markdown_report and not row.markdown_report.startswith(_FERNET_PREFIX):
            updates["markdown_report"] = fernet.encrypt(
                row.markdown_report.encode("utf-8")
            ).decode("ascii")
        if updates:
            set_clause = ", ".join(f"{col} = :{col}" for col in updates)
            bind.execute(
                sa.text(f"UPDATE scan_records SET {set_clause} WHERE scan_id = :scan_id"),  # noqa: S608
                {**updates, "scan_id": str(row.scan_id)},
            )

    # ── ci_scan_records ─────────────────────────────────────────────────────
    ci_rows = bind.execute(
        sa.text(
            "SELECT scan_id, html_report FROM ci_scan_records WHERE html_report IS NOT NULL"
        )
    ).fetchall()

    for row in ci_rows:
        if row.html_report and not row.html_report.startswith(_FERNET_PREFIX):
            encrypted = fernet.encrypt(row.html_report.encode("utf-8")).decode("ascii")
            bind.execute(
                sa.text(
                    "UPDATE ci_scan_records SET html_report = :html_report "
                    "WHERE scan_id = :scan_id"
                ),
                {"html_report": encrypted, "scan_id": str(row.scan_id)},
            )


def downgrade() -> None:
    # Decryption on downgrade is intentionally omitted: reverting to plaintext
    # storage requires the key to still be present, and the value of the
    # downgrade is low. If a rollback is needed, restore from a backup taken
    # before migration 0014 was applied.
    pass
