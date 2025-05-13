"""User endpoints for identity management."""
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from nullcv.identity.crypto import generate_identity
from nullcv.models.schemas.users import UserCreate, UserResponse
from nullcv.services.identity import IdentityService
from nullcv.api.dependencies.services import get_identity_service

router = APIRouter()

@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    user_create: UserCreate,
    identity_service: IdentityService = Depends(get_identity_service),
):
    """
    Create a new anonymous user identity with optional pseudonym.
    No personal information is required.
    """
    return await identity_service.create_identity(user_create)

@router.get("/prove/{user_id}", response_model=UserResponse)
async def get_user_proof(
    user_id: str,
    identity_service: IdentityService = Depends(get_identity_service),
):
    """
    Get cryptographic proof of user identity without revealing personal information.
    """
    user = await identity_service.get_identity_proof(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    return user
