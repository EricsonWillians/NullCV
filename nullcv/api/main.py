from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from nullcv.api.endpoints.users import router as users_router
# Only add those that exist and work
# from nullcv.api.endpoints.jobs import router as jobs_router
# from nullcv.api.endpoints.identity import router as identity_router
# from nullcv.api.endpoints.projects import router as projects_router
# from nullcv.api.endpoints.reputation import router as reputation_router

from nullcv.core.config import settings
from nullcv.core.events import startup_event_handler, shutdown_event_handler
from nullcv.api.middleware.logging import LoggingMiddleware

app = FastAPI(
    title=settings.PROJECT_NAME,
    description=settings.PROJECT_DESCRIPTION,
    version=settings.VERSION,
    docs_url="/api/docs" if settings.DEBUG else None,
    redoc_url="/api/redoc" if settings.DEBUG else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(LoggingMiddleware)

app.add_event_handler("startup", startup_event_handler)
app.add_event_handler("shutdown", shutdown_event_handler)

# Add routers directly
app.include_router(users_router, prefix="/api/users", tags=["users"])
# app.include_router(jobs_router, prefix="/api/jobs", tags=["jobs"])
