"""API endpoints for NullCV platform."""
from fastapi import APIRouter

from nullcv.api.endpoints import jobs, users, projects, identity, reputation

router = APIRouter()
router.include_router(jobs.router, prefix="/jobs", tags=["jobs"])
router.include_router(users.router, prefix="/users", tags=["users"])
router.include_router(projects.router, prefix="/projects", tags=["projects"])
router.include_router(identity.router, prefix="/identity", tags=["identity"])
router.include_router(reputation.router, prefix="/reputation", tags=["reputation"])
