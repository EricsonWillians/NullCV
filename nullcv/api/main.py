"""Main FastAPI application instance for NullCV."""
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware

from nullcv.core.config import settings
from nullcv.api.endpoints import router as api_router
from nullcv.core.events import startup_event_handler, shutdown_event_handler
from nullcv.api.middleware.logging import LoggingMiddleware

app = FastAPI(
    title=settings.PROJECT_NAME,
    description=settings.PROJECT_DESCRIPTION,
    version=settings.VERSION,
    docs_url="/api/docs" if settings.DEBUG else None,
    redoc_url="/api/redoc" if settings.DEBUG else None,
)

# Set up CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add custom middleware
app.add_middleware(LoggingMiddleware)

# Register event handlers
app.add_event_handler("startup", startup_event_handler)
app.add_event_handler("shutdown", shutdown_event_handler)

# Include API router
app.include_router(api_router, prefix="/api")
