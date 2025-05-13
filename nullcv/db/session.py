"""Database session management."""
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from typing import AsyncGenerator

from nullcv.core.config import settings

# Create async database engine
async def create_db_engine():
    """Create SQLAlchemy async engine."""
    engine = create_async_engine(
        settings.SQLALCHEMY_DATABASE_URI,
        echo=settings.DEBUG,
        future=True,
    )
    return engine

# Create async session factory
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Get database session."""
    engine = await create_db_engine()
    async_session = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    
    async with async_session() as session:
        try:
            yield session
        finally:
            await session.close()
