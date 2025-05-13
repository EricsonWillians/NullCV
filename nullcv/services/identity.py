"""Identity management service."""
from typing import Optional
import uuid
from datetime import datetime, timedelta

from nullcv.models.schemas.users import UserCreate, UserResponse, WorkItem, Attestation
from nullcv.identity.crypto import generate_keypair, sign_message, verify_signature
from nullcv.db.repositories.users import UserRepository

class IdentityService:
    """Service for managing cryptographic identities."""
    
    def __init__(self, user_repository: UserRepository):
        self.user_repository = user_repository
    
    async def create_identity(self, user_create: UserCreate) -> UserResponse:
        """Create a new anonymous identity with optional pseudonym."""
        # Generate cryptographic keypair
        private_key, public_key = generate_keypair()
        
        # Create user entity
        user_id = str(uuid.uuid4())
        user = UserResponse(
            id=user_id,
            pseudonym=user_create.pseudonym,
            public_key=public_key,
            work_history=[],
            attestations=[],
            skills=[],
            created_at=datetime.utcnow(),
        )
        
        # Store in repository (with encrypted private key)
        await self.user_repository.create(user, private_key)
        
        return user
    
    async def get_identity_proof(self, user_id: str) -> Optional[UserResponse]:
        """Get user with cryptographic proof of identity."""
        user = await self.user_repository.get_by_id(user_id)
        if not user:
            return None
            
        # Here we'd implement zero-knowledge proofs to verify identity
        # without revealing any personal information
        return user
    
    async def add_work_item(self, user_id: str, work_item: WorkItem) -> Optional[UserResponse]:
        """Add verified work to user's history."""
        user = await self.user_repository.get_by_id(user_id)
        if not user:
            return None
            
        # Add work item with verification
        user.work_history.append(work_item)
        
        # Update skills based on work history
        user.skills = self._derive_skills_from_work(user.work_history)
        
        # Update in repository
        await self.user_repository.update(user)
        
        return user
    
    def _derive_skills_from_work(self, work_history: list[WorkItem]) -> list[str]:
        """Algorithmically derive skills from work history."""
        # In a real implementation, this would use NLP and pattern matching
        # to extract skills from work descriptions and titles
        skills = set()
        for work in work_history:
            # Simplistic example - would be much more sophisticated
            for word in work.description.lower().split():
                if len(word) > 3 and word not in ["and", "the", "for", "with"]:
                    skills.add(word)
        
        return sorted(list(skills))
