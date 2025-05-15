from contextlib import suppress
import asyncio, logging

from nullcv.db import db, session_scope, engine  # grabs singleton + helpers

logger = logging.getLogger(__name__)

async def startup_event_handler() -> None:
    """
    Initializes the database when the application starts.
    
    Awaits database setup, including table creation and genesis signature initialization, and logs completion.
    """
    await db.start()                 # create tables + genesis signature
    logger.info("Database initialised")

async def shutdown_event_handler() -> None:
    """
    Asynchronously disposes of the database engine during application shutdown.
    
    Suppresses any exceptions that occur during disposal to ensure a graceful shutdown.
    """
    with suppress(Exception):
        await engine.get_engine().dispose()
    logger.info("Database engine disposed")
