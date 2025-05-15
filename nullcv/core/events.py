from contextlib import suppress
import asyncio, logging

from nullcv.db import db, session_scope, engine  # grabs singleton + helpers

logger = logging.getLogger(__name__)

async def startup_event_handler() -> None:
    """Called by FastAPI on application start."""
    await db.start()                 # create tables + genesis signature
    logger.info("Database initialised")

async def shutdown_event_handler() -> None:
    """Gracefully dispose the engine."""
    with suppress(Exception):
        await engine.get_engine().dispose()
    logger.info("Database engine disposed")
