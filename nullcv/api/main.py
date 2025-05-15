from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from nullcv.api.endpoints.users import router as users_router
from nullcv.core.config import settings
from nullcv.core.events import startup_event_handler, shutdown_event_handler
from nullcv.api.middleware.logging import LoggingMiddleware

app = FastAPI(
    title=settings.app.PROJECT_NAME,
    description=settings.app.PROJECT_DESCRIPTION,
    version=settings.app.VERSION,
    docs_url="/api/docs" if settings.app.DEBUG else None,
    redoc_url="/api/redoc" if settings.app.DEBUG else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.server.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(LoggingMiddleware)

app.add_event_handler("startup", startup_event_handler)
app.add_event_handler("shutdown", shutdown_event_handler)

app.include_router(users_router, prefix="/api/users", tags=["users"])
