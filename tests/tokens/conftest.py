"""Shared fixtures for ``tests/tokens`` — in-memory async SQLite for fast unit tests.

Each test gets a fresh database (the engine is per-test) so there's no
cross-test state. Production uses Postgres; SQLite is acceptable for these
unit tests because the model uses cross-dialect types (``Uuid``, generic
``JSON``). The PG-only partial unique index on ``local_scan_tokens`` is
defined only in the Alembic migration, not in the ORM — so we don't test
that race-condition safety net here (production migration covers it).
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from security_scanner.tokens.db import Base


@pytest.fixture
async def session() -> AsyncIterator[AsyncSession]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False)
    async with factory() as s:
        yield s
    await engine.dispose()
