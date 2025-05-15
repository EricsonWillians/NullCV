from typing import Optional
from nullcv.db import Tables, db, session_scope
import json

async def create_user(username: str, email: str, payload: dict) -> str:
    """
    Creates a new user record in the database with the specified username, email, and additional data.
    
    Args:
        username: The user's unique username.
        email: The user's email address.
        payload: Additional key-value pairs to include in the user record.
    
    Returns:
        The unique identifier of the newly created user.
    """
    data = {"username": username, "email": email, **payload}
    return await db.insert_json(Tables.User, data)

async def get_user_by_id(uid: str) -> Optional[dict]:
    """
    Retrieves a user record from the database by user ID.
    
    Args:
        uid: The unique identifier of the user.
    
    Returns:
        A dictionary containing user data if found, otherwise None.
    """
    return await db.get_json(Tables.User, uid)
