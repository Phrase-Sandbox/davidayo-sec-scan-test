"""Async SQLAlchemy engine + session factory for the token registry.

Engine is constructed lazily so importing this module does not require
``DATABASE_URL`` to be set — tests that never touch the registry can keep
running without a Postgres.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from security_scanner.shared.config import get_settings


class Base(DeclarativeBase):
    """Declarative base for token registry + audit ORM models."""


_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def _build_engine() -> AsyncEngine:
    url = get_settings().DATABASE_URL
    if not url:
        raise RuntimeError(
            "DATABASE_URL is not set; the token registry requires Postgres. "
            "Set USE_TOKEN_REGISTRY=false to keep the legacy single-token path."
        )
    # echo=False — we do not want SQL in stdout (would leak token hashes in
    # query bind params during audit DEBUG sessions). pool_pre_ping handles
    # idle-connection recycling so a Postgres restart doesn't strand the app.
    # Explicit pool limits prevent unbounded connection growth under load:
    #   pool_size=5    — base pool, always kept open.
    #   max_overflow=10 — burst headroom on top of pool_size.
    #   pool_timeout=30 — seconds to wait for a connection before raising.
    #   pool_recycle=1800 — discard and re-open connections older than 30 min
    #                       (avoids stale TCP on long-idle deployments).
    return create_async_engine(
        url,
        echo=False,
        pool_pre_ping=True,
        future=True,
        pool_size=5,
        max_overflow=10,
        pool_timeout=30,
        pool_recycle=1800,
    )


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        _engine = _build_engine()
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=get_engine(),
            expire_on_commit=False,
            class_=AsyncSession,
        )
    return _session_factory


async def session_scope() -> AsyncIterator[AsyncSession]:
    """Async generator suitable for FastAPI ``Depends(session_scope)``."""
    factory = get_session_factory()
    async with factory() as session:
        yield session


async def reset_for_tests() -> None:
    """Dispose the cached engine so tests can swap ``DATABASE_URL`` between cases."""
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _session_factory = None
