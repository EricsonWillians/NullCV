"""User schema models."""
from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime

class UserBase(BaseModel):
    """Base user schema."""
    pseudonym: Optional[str] = None

class UserCreate(UserBase):
    """User creation schema."""
    pass

class WorkItem(BaseModel):
    """Work history item with proof."""
    id: str
    title: str
    description: str
    proof_hash: str
    completion_date: datetime
    verified: bool = False

class Attestation(BaseModel):
    """Cryptographically signed peer validation."""
    id: str
    issuer_id: str
    skill: str
    level: int
    signature: str
    issued_at: datetime

class UserResponse(UserBase):
    """User response schema."""
    id: str
    public_key: str
    work_history: List[WorkItem] = []
    attestations: List[Attestation] = []
    skills: List[str] = []
    created_at: datetime
    
    class Config:
        """Pydantic config."""
        orm_mode = True
