"""Signature chain model + event hooks that record INSERT/UPDATE/DELETE ops."""
from __future__ import annotations
import time, json, logging
from typing import Any

from sqlalchemy import Column, Integer, String, select, event
from sqlalchemy.orm import DeclarativeBase, Session

from nullcv.identity.crypto import hash_data, sign_data, verify_signature, KeyPair
from .engine import get_session_maker

logger = logging.getLogger(__name__)

class Base(DeclarativeBase):
    pass

# ──────────────────────────────────────────────────────────────────────────────

class DatabaseSignature(Base):
    __tablename__ = "db_signatures"

    id = Column(Integer, primary_key=True)
    timestamp = Column(Integer, nullable=False, index=True)
    operation = Column(String, nullable=False)
    table_name = Column(String, nullable=False, index=True)
    record_id = Column(String, nullable=False)
    previous_hash = Column(String, nullable=False)
    data_hash = Column(String, nullable=False)
    signature = Column(String, nullable=False)
    signer_public_key = Column(String, nullable=False, index=True)

# ──────────────────────────────────────────────────────────────────────────────

class _Ledger:
    """Encapsulate signature‑chain logic; stateless helper bound to a KeyPair."""

    def __init__(self, keypair: KeyPair | None):
        """
        Initializes the ledger with an optional cryptographic key pair.
        
        Args:
            keypair: The cryptographic key pair used for signing audit entries, or None if signing is not enabled.
        """
        self.keypair = keypair
        self._last_hash: str | None = None

    async def init_genesis(self):
        """
        Initializes the signature chain with a genesis audit record if none exists.
        
        If no prior audit entries are found, creates a genesis record with a unique hash and zeroed previous hash, and commits it to the database. Otherwise, sets the last hash to the most recent audit entry's data hash.
        """
        async with get_session_maker()() as s:
            res = await s.scalar(select(DatabaseSignature.data_hash).order_by(DatabaseSignature.id.desc()))
            if res is None:
                self._last_hash = hash_data({"genesis": True, "ts": time.time()})
                genesis = DatabaseSignature(
                    timestamp=int(time.time()),
                    operation="GENESIS",
                    table_name="-",
                    record_id="-",
                    previous_hash="0" * 64,
                    data_hash=self._last_hash,
                    signature="",
                    signer_public_key=""
                )
                s.add(genesis)
                await s.commit()
            else:
                self._last_hash = res

    # ---------------------------------------------------------

    def sign_row(self, *, operation: str, table: str, pk: str, payload: dict[str, Any]) -> DatabaseSignature:
        """
        Creates a cryptographically signed audit record for a database operation.
        
        Args:
            operation: The type of database operation (e.g., "INSERT", "UPDATE", "DELETE").
            table: The name of the affected database table.
            pk: The primary key or unique identifier of the affected record.
            payload: The data associated with the operation to be hashed and signed.
        
        Returns:
            A DatabaseSignature instance containing the operation metadata, data hash, signature, and signer's public key.
        
        Raises:
            AssertionError: If the keypair is not configured.
        """
        assert self.keypair, "Node keypair not configured"
        data_hash = hash_data(payload)
        sig_payload = {
            "timestamp": int(time.time()),
            "operation": operation,
            "table_name": table,
            "record_id": pk,
            "previous_hash": self._last_hash,
            "data_hash": data_hash,
        }
        sig = sign_data(sig_payload, self.keypair.private_key)
        self._last_hash = data_hash
        return DatabaseSignature(**sig_payload, signature=sig, signer_public_key=self.keypair.public_key)

ledger: _Ledger | None = None  # will be set by secure_db.start()

# ──────────────────────────────────────────────────────────────────────────────
# Event listeners (record audit rows automatically)

from sqlalchemy.orm import Mapper

AUDITED_OPS = {"insert": "INSERT", "update": "UPDATE", "delete": "DELETE"}

@event.listens_for(Mapper, "after_insert")
def _after_insert(mapper, connection, target):  # noqa: N802 – SQLA naming
    """
    SQLAlchemy event listener that records a cryptographically signed audit entry after an INSERT operation.
    
    This function is triggered after a new ORM-mapped object is inserted into the database. If a global ledger is configured and the target object has an `id`, it generates a signature record for the operation—using the object's table name, primary key, and optionally its JSON-parsed `data` attribute as payload—and inserts the resulting audit entry into the signature chain table.
    """
    if ledger and hasattr(target, "id"):
        payload = json.loads(target.data) if hasattr(target, "data") else {}
        sig = ledger.sign_row(operation="INSERT", table=target.__tablename__, pk=str(target.id), payload=payload)
        connection.execute(DatabaseSignature.__table__.insert(), sig.__dict__)

@event.listens_for(Mapper, "after_update")
def _after_update(mapper, connection, target):
    """
    SQLAlchemy event listener that records a cryptographically signed audit entry after an UPDATE operation on a mapped object.
    
    This function is triggered automatically after an ORM-mapped object's data is updated. If a global ledger is configured and the target object has an `id`, it extracts the updated data payload, generates a signature record for the update, and inserts it into the audit table.
    """
    if ledger and hasattr(target, "id"):
        payload = json.loads(target.data)
        sig = ledger.sign_row(operation="UPDATE", table=target.__tablename__, pk=str(target.id), payload=payload)
        connection.execute(DatabaseSignature.__table__.insert(), sig.__dict__)

@event.listens_for(Mapper, "after_delete")
def _after_delete(mapper, connection, target):
    """
    SQLAlchemy event listener that records a cryptographically signed audit entry after a row is deleted.
    
    This function is triggered after a mapped ORM object's deletion. If a global ledger is configured and the object has an `id`, it creates a signature record for the DELETE operation and inserts it into the audit table.
    """
    if ledger and hasattr(target, "id"):
        sig = ledger.sign_row(operation="DELETE", table=target.__tablename__, pk=str(target.id), payload={})
        connection.execute(DatabaseSignature.__table__.insert(), sig.__dict__)