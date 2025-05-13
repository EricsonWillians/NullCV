# nullcv/db/repositories/users.py

from typing import Optional
from nullcv.models.schemas.users import UserResponse

class UserRepository:
    """Stub UserRepository — replace with DB integration."""
    
    def __init__(self):
        self.fake_db = {}

    async def create(self, user: UserResponse, private_key: str) -> None:
        self.fake_db[user.id] = {
            "user": user,
            "private_key": private_key,
        }

    async def get_by_id(self, user_id: str) -> Optional[UserResponse]:
        entry = self.fake_db.get(user_id)
        if entry:
            return entry["user"]
        return None

    async def update(self, user: UserResponse) -> None:
        if user.id in self.fake_db:
            self.fake_db[user.id]["user"] = user
