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
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA foreign_keys=ON")
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
    cur.close()

# ──────────────────────────────────────────────────────────────────────────────

@lru_cache(maxsize=1)
def get_engine(sqlite_path: str | Path | None = None) -> AsyncEngine:
    path = Path(sqlite_path or settings.db.SQLITE_DATABASE_PATH).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    logger.info("SQLite database path: %s", path)
    return create_async_engine(f"sqlite+aiosqlite:///{path}", echo=settings.db.SQLALCHEMY_ECHO)

# ──────────────────────────────────────────────────────────────────────────────

_session_factory: async_sessionmaker[AsyncSession] | None = None

def get_session_maker() -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(get_engine(), expire_on_commit=False)
    return _session_factory

# Convenience async context manager -------------------------------------------------
from contextlib import asynccontextmanager

@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    """Usage: `async with session_scope() as session:`"""
    async with get_session_maker()() as s:  # type: AsyncSession
        try:
            yield s
            await s.commit()
        except Exception:
            await s.rollback()
            raise