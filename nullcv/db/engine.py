"""Database engine & session helpers (SQLite + async).
Keeps *all* DB‑connection details in one place so other modules don’t import SQLAlchemy directly.
"""
from __future__ import annotations
import logging, os
from functools import lru_cache
from pathlib import Path
from typing import AsyncIterator

from sqlalchemy import event
from sqlalchemy.ext.asyncio import (AsyncEngine, AsyncSession, create_async_engine,
                                    async_sessionmaker)
from sqlalchemy.engine import Engine

from nullcv.core.config import settings  # <- light import (only reads .db singleton)

logger = logging.getLogger(__name__)

BUSY_TIMEOUT_MS = 5_000  # 5 seconds

# ──────────────────────────────────────────────────────────────────────────────

@event.listens_for(Engine, "connect")
def _set_sqlite_pragmas(dbapi_conn, _):  # pragma: no cover
    """
    Configures SQLite connection settings for each new database connection.
    
    Enables foreign key constraints, sets the journal mode to WAL, and applies a busy timeout to ensure consistent SQLite behavior across all connections.
    """
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA foreign_keys=ON")
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
    cur.close()

# ──────────────────────────────────────────────────────────────────────────────

@lru_cache(maxsize=1)
def get_engine(sqlite_path: str | Path | None = None) -> AsyncEngine:
    """
    Creates and returns a cached asynchronous SQLAlchemy engine for a SQLite database.
    
    If no database path is provided, uses the default path from configuration. Ensures the
    parent directory exists before creating the engine. The engine is configured for use
    with the aiosqlite driver and echo logging as specified in settings.
    
    Args:
        sqlite_path: Optional path to the SQLite database file. If not provided, the
            configured default path is used.
    
    Returns:
        An asynchronous SQLAlchemy engine instance for the specified SQLite database.
    """
    path = Path(sqlite_path or settings.db.SQLITE_DATABASE_PATH).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    logger.info("SQLite database path: %s", path)
    return create_async_engine(f"sqlite+aiosqlite:///{path}", echo=settings.db.SQLALCHEMY_ECHO)

# ──────────────────────────────────────────────────────────────────────────────

_session_factory: async_sessionmaker[AsyncSession] | None = None

def get_session_maker() -> async_sessionmaker[AsyncSession]:
    """
    Returns a singleton async session factory for creating database sessions.
    
    Lazily initializes the session factory on first call using the cached async engine,
    with sessions configured not to expire objects on commit.
    
    Returns:
        An async_sessionmaker instance for creating AsyncSession objects.
    """
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(get_engine(), expire_on_commit=False)
    return _session_factory

# Convenience async context manager -------------------------------------------------
from contextlib import asynccontextmanager

@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    """
    Asynchronous context manager for transactional database sessions.
    
    Yields an async SQLAlchemy session, automatically committing on successful exit or rolling back on exception. Intended for use with `async with session_scope() as session:`.
    """
    async with get_session_maker()() as s:  # type: AsyncSession
        try:
            yield s
            await s.commit()
        except Exception:
            await s.rollback()
            raise