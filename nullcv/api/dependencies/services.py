# nullcv/api/dependencies/services.py

from nullcv.services.identity import IdentityService
from nullcv.db.repositories.users import UserRepository

def get_identity_service() -> IdentityService:
    """Dependency injection for IdentityService."""
    # In the future, inject DB session here
    return IdentityService(user_repository=UserRepository())
