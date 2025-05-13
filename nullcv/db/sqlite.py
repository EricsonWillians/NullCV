"""
SQLite database with cryptographic signature verification.

This module implements a secure, portable SQLite database that:
1. Supports cryptographic signatures for data integrity
2. Enables decentralized verification of database records
3. Maintains an append-only log of changes for auditability
4. Allows peer validation of database state
"""

import json
import sqlite3
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from datetime import datetime

from sqlalchemy import event, Column, Integer, String, JSON, ForeignKey, Table, MetaData
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.engine import Engine

from nullcv.identity.crypto import (
    generate_keypair, 
    sign_data, 
    verify_signature,
    hash_data,
    KeyPair
)
from nullcv.core.config import settings

# Configure logging
logger = logging.getLogger(__name__)

# Base class for SQLAlchemy models
Base = declarative_base()

# Create metadata object for direct table creation
metadata = MetaData()

# Enforce foreign key constraints in SQLite
@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()

# Enable WAL mode for better concurrency
@event.listens_for(Engine, "connect")
def enable_wal_mode(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.close()

class DatabaseSignature(Base):
    """Tracks cryptographic signatures for database changes."""
    
    __tablename__ = "db_signatures"
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(Integer, nullable=False, index=True)  # Unix timestamp
    operation = Column(String, nullable=False)  # INSERT, UPDATE, DELETE
    table_name = Column(String, nullable=False, index=True)
    record_id = Column(String, nullable=False)  # Primary key of affected record
    previous_hash = Column(String, nullable=False)  # Hash of previous signature
    data_hash = Column(String, nullable=False)  # Hash of the data being signed
    signature = Column(String, nullable=False)  # Cryptographic signature
    signer_public_key = Column(String, nullable=False, index=True)  # Public key of signer
    
    def __repr__(self):
        return f"<DatabaseSignature(id={self.id}, table={self.table_name}, record_id={self.record_id})>"


class SecureDatabase:
    """
    Secure database implementation with cryptographic verification.
    
    Features:
    - Cryptographic signatures for all database changes
    - Chain of signatures for auditability
    - Verification of database integrity
    - Support for local-first operations with later synchronization
    """
    
    def __init__(
        self, 
        db_path: str = None, 
        keypair: Optional[KeyPair] = None,
        verify_on_read: bool = True,
        auto_sync: bool = True
    ):
        """
        Initialize the secure database.
        
        Args:
            db_path: Path to the SQLite database file
            keypair: Node's cryptographic keypair for signing
            verify_on_read: Whether to verify signatures when reading data
            auto_sync: Whether to automatically sync with peers
        """
        self.db_path = db_path or settings.SQLITE_DATABASE_PATH
        self.keypair = keypair
        self.verify_on_read = verify_on_read
        self.auto_sync = auto_sync
        self._last_signature_hash = None
        
        # Initialize database connection
        self._initialize_database()
        
        # Load the last signature hash
        self._load_last_signature()
    
    def _initialize_database(self) -> None:
        """Initialize the SQLite database and create tables."""
        db_file = Path(self.db_path)
        db_dir = db_file.parent
        
        # Create directory if it doesn't exist
        if not db_dir.exists():
            db_dir.mkdir(parents=True)
            logger.info(f"Created database directory: {db_dir}")
        
        # Create SQLite database
        self.engine = create_async_engine(
            f"sqlite+aiosqlite:///{self.db_path}",
            echo=settings.DATABASE_ECHO,
        )
        
        # Create session factory
        self.async_session = sessionmaker(
            self.engine, class_=AsyncSession, expire_on_commit=False
        )
        
        # Create tables if they don't exist
        self._create_tables()
    
    async def _create_tables(self) -> None:
        """Create database tables if they don't exist."""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            logger.info("Database tables created or verified")
    
    async def _load_last_signature(self) -> None:
        """Load the hash of the last signature in the chain."""
        async with self.get_session() as session:
            result = await session.execute(
                "SELECT data_hash FROM db_signatures ORDER BY id DESC LIMIT 1"
            )
            row = result.fetchone()
            
            if row:
                self._last_signature_hash = row[0]
                logger.debug(f"Loaded last signature hash: {self._last_signature_hash}")
            else:
                # Genesis state - no signatures yet
                self._last_signature_hash = hash_data({
                    "timestamp": int(time.time()),
                    "operation": "GENESIS",
                    "message": "Database initialization"
                })
                logger.info(f"Created genesis signature hash: {self._last_signature_hash}")
    
    async def get_session(self) -> AsyncSession:
        """Get a database session."""
        return self.async_session()
    
    async def sign_operation(
        self, 
        operation: str, 
        table_name: str, 
        record_id: str, 
        data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Sign a database operation.
        
        Args:
            operation: The operation type (INSERT, UPDATE, DELETE)
            table_name: The name of the affected table
            record_id: The primary key of the affected record
            data: The data being modified
            
        Returns:
            A signature record
        """
        if not self.keypair:
            raise ValueError("No keypair available for signing")
        
        # Create signature payload
        timestamp = int(time.time())
        data_hash = hash_data(data)
        
        signature_data = {
            "timestamp": timestamp,
            "operation": operation,
            "table_name": table_name,
            "record_id": record_id,
            "previous_hash": self._last_signature_hash,
            "data_hash": data_hash
        }
        
        # Sign the payload
        signature = sign_data(signature_data, self.keypair.private_key)
        
        # Create signature record
        signature_record = {
            "timestamp": timestamp,
            "operation": operation,
            "table_name": table_name,
            "record_id": record_id,
            "previous_hash": self._last_signature_hash,
            "data_hash": data_hash,
            "signature": signature,
            "signer_public_key": self.keypair.public_key
        }
        
        # Update last signature hash
        self._last_signature_hash = data_hash
        
        return signature_record
    
    async def insert(
        self, 
        table_name: str, 
        data: Dict[str, Any], 
        record_id: Optional[str] = None
    ) -> str:
        """
        Insert data with cryptographic signature.
        
        Args:
            table_name: The table to insert into
            data: The data to insert
            record_id: Optional record ID, will be generated if not provided
            
        Returns:
            The ID of the inserted record
        """
        # Generate record ID if not provided
        if not record_id:
            record_id = hash_data({**data, "timestamp": time.time()})[:16]
        
        # Sign the operation
        signature = await self.sign_operation("INSERT", table_name, record_id, data)
        
        async with self.get_session() as session:
            # Begin transaction
            async with session.begin():
                # Insert data
                await session.execute(
                    f"INSERT INTO {table_name} (id, data, signature_id) VALUES (?, ?, ?)",
                    (record_id, json.dumps(data), None)
                )
                
                # Insert signature
                await session.execute(
                    """
                    INSERT INTO db_signatures 
                    (timestamp, operation, table_name, record_id, previous_hash, 
                     data_hash, signature, signer_public_key)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        signature["timestamp"], 
                        signature["operation"],
                        signature["table_name"],
                        signature["record_id"],
                        signature["previous_hash"],
                        signature["data_hash"],
                        signature["signature"],
                        signature["signer_public_key"]
                    )
                )
                
                # Get signature ID
                result = await session.execute(
                    "SELECT last_insert_rowid()"
                )
                signature_id = result.scalar()
                
                # Update data record with signature ID
                await session.execute(
                    f"UPDATE {table_name} SET signature_id = ? WHERE id = ?",
                    (signature_id, record_id)
                )
                
                # Commit transaction
                await session.commit()
        
        logger.debug(f"Inserted record {record_id} into {table_name} with signature {signature_id}")
        return record_id
    
    async def update(
        self, 
        table_name: str, 
        record_id: str, 
        data: Dict[str, Any]
    ) -> bool:
        """
        Update data with cryptographic signature.
        
        Args:
            table_name: The table to update
            record_id: The ID of the record to update
            data: The new data
            
        Returns:
            True if the update was successful
        """
        # Sign the operation
        signature = await self.sign_operation("UPDATE", table_name, record_id, data)
        
        async with self.get_session() as session:
            # Begin transaction
            async with session.begin():
                # Insert signature
                await session.execute(
                    """
                    INSERT INTO db_signatures 
                    (timestamp, operation, table_name, record_id, previous_hash, 
                     data_hash, signature, signer_public_key)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        signature["timestamp"], 
                        signature["operation"],
                        signature["table_name"],
                        signature["record_id"],
                        signature["previous_hash"],
                        signature["data_hash"],
                        signature["signature"],
                        signature["signer_public_key"]
                    )
                )
                
                # Get signature ID
                result = await session.execute(
                    "SELECT last_insert_rowid()"
                )
                signature_id = result.scalar()
                
                # Update data record
                await session.execute(
                    f"UPDATE {table_name} SET data = ?, signature_id = ? WHERE id = ?",
                    (json.dumps(data), signature_id, record_id)
                )
                
                # Commit transaction
                await session.commit()
        
        logger.debug(f"Updated record {record_id} in {table_name} with signature {signature_id}")
        return True
    
    async def delete(
        self, 
        table_name: str, 
        record_id: str
    ) -> bool:
        """
        Delete data with cryptographic signature.
        
        Args:
            table_name: The table to delete from
            record_id: The ID of the record to delete
            
        Returns:
            True if the delete was successful
        """
        # Get current data for signature
        async with self.get_session() as session:
            result = await session.execute(
                f"SELECT data FROM {table_name} WHERE id = ?",
                (record_id,)
            )
            row = result.fetchone()
            
            if not row:
                logger.warning(f"Cannot delete: Record {record_id} not found in {table_name}")
                return False
            
            data = json.loads(row[0])
        
        # Sign the delete operation
        signature = await self.sign_operation("DELETE", table_name, record_id, data)
        
        async with self.get_session() as session:
            # Begin transaction
            async with session.begin():
                # Insert signature
                await session.execute(
                    """
                    INSERT INTO db_signatures 
                    (timestamp, operation, table_name, record_id, previous_hash, 
                     data_hash, signature, signer_public_key)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        signature["timestamp"], 
                        signature["operation"],
                        signature["table_name"],
                        signature["record_id"],
                        signature["previous_hash"],
                        signature["data_hash"],
                        signature["signature"],
                        signature["signer_public_key"]
                    )
                )
                
                # Delete data record
                await session.execute(
                    f"DELETE FROM {table_name} WHERE id = ?",
                    (record_id,)
                )
                
                # Commit transaction
                await session.commit()
        
        logger.debug(f"Deleted record {record_id} from {table_name}")
        return True
    
    async def get(
        self, 
        table_name: str, 
        record_id: str,
        verify: Optional[bool] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Get data with optional signature verification.
        
        Args:
            table_name: The table to query
            record_id: The ID of the record to retrieve
            verify: Whether to verify the signature (defaults to self.verify_on_read)
            
        Returns:
            The record data or None if not found
        """
        verify = self.verify_on_read if verify is None else verify
        
        async with self.get_session() as session:
            result = await session.execute(
                f"""
                SELECT d.data, d.signature_id, s.signature, s.signer_public_key, 
                       s.data_hash, s.previous_hash
                FROM {table_name} d
                LEFT JOIN db_signatures s ON d.signature_id = s.id
                WHERE d.id = ?
                """,
                (record_id,)
            )
            row = result.fetchone()
            
            if not row:
                return None
            
            data, signature_id, signature, signer_public_key, data_hash, previous_hash = row
            
            # Parse JSON data
            try:
                data = json.loads(data)
            except json.JSONDecodeError:
                logger.error(f"Failed to parse JSON data for record {record_id} in {table_name}")
                return None
            
            # Verify signature if requested
            if verify and signature:
                calculated_hash = hash_data(data)
                
                if calculated_hash != data_hash:
                    logger.warning(
                        f"Data integrity error: Hash mismatch for record {record_id} in {table_name}"
                    )
                    return None
                
                # Verify the signature
                signature_data = {
                    "timestamp": data.get("timestamp", 0),
                    "operation": "INSERT" if signature_id else "UPDATE",
                    "table_name": table_name,
                    "record_id": record_id,
                    "previous_hash": previous_hash,
                    "data_hash": data_hash
                }
                
                if not verify_signature(signature_data, signature, signer_public_key):
                    logger.warning(
                        f"Signature verification failed for record {record_id} in {table_name}"
                    )
                    return None
            
            return data
    
    async def query(
        self, 
        table_name: str, 
        conditions: Optional[Dict[str, Any]] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        verify: Optional[bool] = None
    ) -> List[Dict[str, Any]]:
        """
        Query data with optional signature verification.
        
        Args:
            table_name: The table to query
            conditions: Optional conditions to filter by
            limit: Maximum number of records to return
            offset: Number of records to skip
            verify: Whether to verify signatures (defaults to self.verify_on_read)
            
        Returns:
            A list of matching records
        """
        verify = self.verify_on_read if verify is None else verify
        
        # Build query
        query = f"SELECT id, data, signature_id FROM {table_name}"
        params = []
        
        if conditions:
            # Handle conditions by JSON paths
            # Note: This is simplified; a real implementation would need more sophisticated
            # JSON querying for SQLite
            wheres = []
            for key, value in conditions.items():
                wheres.append(f"json_extract(data, '$.{key}') = ?")
                params.append(value)
            
            if wheres:
                query += " WHERE " + " AND ".join(wheres)
        
        if limit:
            query += f" LIMIT {limit}"
            
        if offset:
            query += f" OFFSET {offset}"
        
        # Execute query
        async with self.get_session() as session:
            result = await session.execute(query, params)
            rows = result.fetchall()
            
            records = []
            for row in rows:
                record_id, data, signature_id = row
                
                try:
                    data = json.loads(data)
                except json.JSONDecodeError:
                    logger.error(f"Failed to parse JSON data for record {record_id}")
                    continue
                
                # Add ID to data
                data["id"] = record_id
                
                # Verify signature if requested
                if verify and signature_id:
                    # Get signature details
                    sig_result = await session.execute(
                        """
                        SELECT signature, signer_public_key, data_hash, previous_hash
                        FROM db_signatures WHERE id = ?
                        """,
                        (signature_id,)
                    )
                    sig_row = sig_result.fetchone()
                    
                    if sig_row:
                        signature, signer_public_key, data_hash, previous_hash = sig_row
                        
                        calculated_hash = hash_data(data)
                        if calculated_hash != data_hash:
                            logger.warning(
                                f"Data integrity error: Hash mismatch for record {record_id}"
                            )
                            continue
                        
                        # We'll skip full signature verification in queries for performance
                        # but warn if needed
                        logger.debug(f"Record {record_id} hash verified")
                    else:
                        logger.warning(f"Record {record_id} has invalid signature reference")
                
                records.append(data)
            
            return records
    
    async def verify_database_integrity(self) -> Tuple[bool, List[str]]:
        """
        Verify the integrity of the entire database.
        
        Returns:
            A tuple of (is_valid, error_messages)
        """
        errors = []
        
        async with self.get_session() as session:
            # Get all signatures in order
            result = await session.execute(
                """
                SELECT id, timestamp, operation, table_name, record_id, 
                       previous_hash, data_hash, signature, signer_public_key
                FROM db_signatures
                ORDER BY id ASC
                """
            )
            signatures = result.fetchall()
            
            if not signatures:
                logger.info("No signatures found in database")
                return True, []
            
            # Verify signature chain
            previous_hash = None
            for sig in signatures:
                (
                    sig_id, timestamp, operation, table_name, record_id, 
                    prev_hash, data_hash, signature, signer_public_key
                ) = sig
                
                # Check previous hash linkage
                if previous_hash is not None and prev_hash != previous_hash:
                    error = f"Signature chain broken at signature {sig_id}"
                    errors.append(error)
                    logger.error(error)
                
                # Verify data hash
                if operation != "DELETE":
                    # Get the record data
                    data_result = await session.execute(
                        f"SELECT data FROM {table_name} WHERE id = ?",
                        (record_id,)
                    )
                    data_row = data_result.fetchone()
                    
                    if data_row:
                        try:
                            data = json.loads(data_row[0])
                            calculated_hash = hash_data(data)
                            
                            if calculated_hash != data_hash:
                                error = f"Data hash mismatch for record {record_id} in {table_name}"
                                errors.append(error)
                                logger.error(error)
                        except json.JSONDecodeError:
                            error = f"Invalid JSON data for record {record_id} in {table_name}"
                            errors.append(error)
                            logger.error(error)
                    else:
                        if operation != "DELETE":
                            error = f"Missing data for record {record_id} in {table_name}"
                            errors.append(error)
                            logger.error(error)
                
                # Verify signature
                signature_data = {
                    "timestamp": timestamp,
                    "operation": operation,
                    "table_name": table_name,
                    "record_id": record_id,
                    "previous_hash": prev_hash,
                    "data_hash": data_hash
                }
                
                if not verify_signature(signature_data, signature, signer_public_key):
                    error = f"Invalid signature for record {record_id} in {table_name}"
                    errors.append(error)
                    logger.error(error)
                
                # Update previous hash for next iteration
                previous_hash = data_hash
        
        is_valid = len(errors) == 0
        if is_valid:
            logger.info("Database integrity verification passed")
        else:
            logger.warning(f"Database integrity verification failed with {len(errors)} errors")
        
        return is_valid, errors
    
    async def export_signatures(
        self, 
        since_timestamp: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Export signatures for peer synchronization.
        
        Args:
            since_timestamp: Only export signatures after this timestamp
            
        Returns:
            A list of signature records
        """
        query = """
            SELECT id, timestamp, operation, table_name, record_id, 
                  previous_hash, data_hash, signature, signer_public_key
            FROM db_signatures
        """
        params = []
        
        if since_timestamp:
            query += " WHERE timestamp > ?"
            params.append(since_timestamp)
        
        query += " ORDER BY id ASC"
        
        async with self.get_session() as session:
            result = await session.execute(query, params)
            rows = result.fetchall()
            
            signatures = []
            for row in rows:
                (
                    sig_id, timestamp, operation, table_name, record_id, 
                    prev_hash, data_hash, signature, signer_public_key
                ) = row
                
                signatures.append({
                    "id": sig_id,
                    "timestamp": timestamp,
                    "operation": operation,
                    "table_name": table_name,
                    "record_id": record_id,
                    "previous_hash": prev_hash,
                    "data_hash": data_hash,
                    "signature": signature,
                    "signer_public_key": signer_public_key
                })
            
            return signatures
    
    async def import_signatures(
        self, 
        signatures: List[Dict[str, Any]],
        verify: bool = True
    ) -> Tuple[bool, List[str]]:
        """
        Import signatures from peers.
        
        Args:
            signatures: List of signature records to import
            verify: Whether to verify signatures during import
            
        Returns:
            A tuple of (success, error_messages)
        """
        if not signatures:
            return True, []
        
        errors = []
        imported_count = 0
        
        async with self.get_session() as session:
            async with session.begin():
                # Get the last signature hash
                last_sig_result = await session.execute(
                    "SELECT data_hash FROM db_signatures ORDER BY id DESC LIMIT 1"
                )
                last_sig_row = last_sig_result.fetchone()
                last_hash = last_sig_row[0] if last_sig_row else None
                
                for sig in signatures:
                    # Skip if we already have this signature
                    sig_exists_result = await session.execute(
                        """
                        SELECT 1 FROM db_signatures 
                        WHERE data_hash = ? AND signer_public_key = ?
                        """,
                        (sig["data_hash"], sig["signer_public_key"])
                    )
                    
                    if sig_exists_result.fetchone():
                        continue
                    
                    # Verify signature if requested
                    if verify:
                        signature_data = {
                            "timestamp": sig["timestamp"],
                            "operation": sig["operation"],
                            "table_name": sig["table_name"],
                            "record_id": sig["record_id"],
                            "previous_hash": sig["previous_hash"],
                            "data_hash": sig["data_hash"]
                        }
                        
                        if not verify_signature(
                            signature_data, sig["signature"], sig["signer_public_key"]
                        ):
                            error = f"Invalid signature for import: {sig['data_hash']}"
                            errors.append(error)
                            logger.warning(error)
                            continue
                    
                    # Insert the signature
                    await session.execute(
                        """
                        INSERT INTO db_signatures 
                        (timestamp, operation, table_name, record_id, previous_hash, 
                         data_hash, signature, signer_public_key)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            sig["timestamp"], 
                            sig["operation"],
                            sig["table_name"],
                            sig["record_id"],
                            sig["previous_hash"],
                            sig["data_hash"],
                            sig["signature"],
                            sig["signer_public_key"]
                        )
                    )
                    
                    imported_count += 1
                
                # Commit transaction
                await session.commit()
        
        logger.info(f"Imported {imported_count} signatures")
        return len(errors) == 0, errors


# Global database instance
_db: Optional[SecureDatabase] = None

async def get_secure_database() -> SecureDatabase:
    """Get the global secure database instance."""
    global _db
    
    if _db is None:
        # Create keypair if we have private key in settings
        keypair = None
        if settings.NODE_PRIVATE_KEY:
            private_key = settings.NODE_PRIVATE_KEY.get_secret_value()
            public_key = settings.NODE_PUBLIC_KEY
            
            if private_key and public_key:
                keypair = KeyPair(private_key=private_key, public_key=public_key)
            else:
                # Generate new keypair
                keypair = generate_keypair()
                logger.info("Generated new node keypair")
        
        # Create database
        _db = SecureDatabase(
            db_path=settings.SQLITE_DATABASE_PATH,
            keypair=keypair,
            verify_on_read=settings.VERIFY_SIGNATURES_ON_READ,
            auto_sync=settings.AUTO_SYNC_DATABASE
        )
        
        # Initialize database
        await _db._create_tables()
        await _db._load_last_signature()
    
    return _db


def create_table_schema(table_name: str) -> str:
    """
    Create SQL schema for data tables that includes signature verification.
    
    Args:
        table_name: The name of the table to create
        
    Returns:
        SQL statement to create the table
    """
    return f"""
    CREATE TABLE IF NOT EXISTS {table_name} (
        id TEXT PRIMARY KEY,
        data TEXT NOT NULL,  -- JSON data
        signature_id INTEGER,
        created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
        updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
        FOREIGN KEY (signature_id) REFERENCES db_signatures(id)
    );
    CREATE INDEX IF NOT EXISTS idx_{table_name}_created_at ON {table_name}(created_at);
    """