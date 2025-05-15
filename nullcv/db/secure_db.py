"""High‑level façade combining engine + ledger and exposing small CRUD helpers.
Only *domain repositories* should import this module – not the rest of the app.
"""
from __future__ import annotations
import json, logging, time
from typing import Any

from sqlalchemy import select

from .engine import session_scope, get_engine
from .ledger import ledger, _Ledger, DatabaseSignature, Base
from nullcv.identity.crypto import generate_keypair, KeyPair, hash_data
from nullcv.core.config import settings

logger = logging.getLogger(__name__)

class SecureDatabase:
    def __init__(self, keypair: KeyPair | None = None):
        self.keypair = keypair or generate_keypair()
        ledger.__class__  # lgtm

    async def start(self):
        """Create tables & initialise ledger genesis."""
        async with get_engine().begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        # attach ledger singleton
        global ledger
        ledger = _Ledger(self.keypair)
        await ledger.init_genesis()
        logger.info("SecureDatabase ready (public key %s)", self.keypair.public_key[:16])

    # ───────────────────────────────────────────── CRUD convenience
    async def insert_json(self, table_model, data: dict[str, Any]) -> str:
        from uuid import uuid4
        pk = uuid4().hex[:16]
        async with session_scope() as s:
            obj = table_model(id=pk, data=json.dumps(data))
            s.add(obj)
            await s.flush()
        return pk

    async def get_json(self, table_model, pk: str) -> dict[str, Any] | None:
        async with session_scope() as s:
            obj = await s.get(table_model, pk)
            if not obj:
                return None
            return json.loads(obj.data)