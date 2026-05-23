"""Alembic environment.

Reads ``DATABASE_URL`` from the app's Pydantic settings so there is one
source of truth for the connection string. The async driver
(``postgresql+psycopg``) is converted to the sync form Alembic expects.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from security_scanner.shared.config import get_settings
from security_scanner.tokens.db import Base
from security_scanner.tokens import models  # noqa: F401 — register tables with Base.metadata

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _resolve_db_url() -> str:
    url = get_settings().DATABASE_URL
    if not url:
        raise RuntimeError("DATABASE_URL is required to run migrations.")
    # Alembic uses the synchronous driver; strip the +psycopg async marker
    # if it's present (psycopg3 is happy either way for the sync side).
    if url.startswith("postgresql+psycopg://"):
        return url.replace("postgresql+psycopg://", "postgresql+psycopg://", 1)
    return url


def run_migrations_offline() -> None:
    context.configure(
        url=_resolve_db_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    cfg = config.get_section(config.config_ini_section, {})
    cfg["sqlalchemy.url"] = _resolve_db_url()
    connectable = engine_from_config(
        cfg,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
