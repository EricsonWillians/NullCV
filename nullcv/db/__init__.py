"""Public DB façade.

Typical usage in a repository:

    from nullcv.db import db, Tables

    async def get_user(id: str):
        return await db.get_json(Tables.User, id)
"""
from .secure_db import SecureDatabase
from .engine import session_scope
from .mixins import JsonRecordMixin
from .ledger import DatabaseSignature, Base as _LedgerBase

# Domain tables live here to avoid circulars ----------------------------
from sqlalchemy.orm import Mapped, mapped_column

class Tables:  # namespace pseudo‑package
    class User(JsonRecordMixin, _LedgerBase):
        __tablename__ = "users"
        username: Mapped[str] = mapped_column(unique=True)
        email:    Mapped[str] = mapped_column(unique=True, index=True)

# Singleton instance ----------------------------------------------------
from nullcv.identity.crypto import KeyPair, generate_keypair

_keypair = generate_keypair()
db = SecureDatabase(_keypair)

__all__ = ["session_scope", "db", "Tables", "DatabaseSignature"]