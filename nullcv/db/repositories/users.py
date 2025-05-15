from typing import Optional
from nullcv.db import Tables, db, session_scope
import json

async def create_user(username: str, email: str, payload: dict) -> str:
    data = {"username": username, "email": email, **payload}
    return await db.insert_json(Tables.User, data)

async def get_user_by_id(uid: str) -> Optional[dict]:
    return await db.get_json(Tables.User, uid)
