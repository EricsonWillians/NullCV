#!/bin/bash

# NullCV Project Initialization Script

# Create project directory
mkdir -p nullcv
cd nullcv

# Initialize Poetry
poetry init \
  --name "nullcv" \
  --description "Proof-of-Work, Not Promises - A decentralized talent marketplace" \
  --author "NullCV Team" \
  --python "^3.10" \
  --no-interaction

# Add project dependencies
poetry add fastapi uvicorn pydantic pydantic-settings python-multipart python-jose[cryptography] passlib[bcrypt] 
poetry add sqlalchemy alembic psycopg2-binary asyncpg
poetry add web3 eth-account eth-keys py-ipfs-http-client
poetry add pytest pytest-asyncio httpx --group dev
poetry add python-dotenv cryptography requests aiohttp
poetry add pyzmq msgpack-python merkletools zk-snarks
poetry add fastapi-socketio redis celery flower
poetry add pyopenssl watchdog pycryptodome
poetry add pyjwt dynaconf structlog

# Create project structure
mkdir -p nullcv/{api,blockchain,core,db,federation,identity,ipfs,models,reputation,services,utils,workers}
mkdir -p nullcv/api/{endpoints,middleware,dependencies}
mkdir -p nullcv/blockchain/{contracts,escrow,validators}
mkdir -p nullcv/core/{config,security,events}
mkdir -p nullcv/db/{migrations,repositories,session}
mkdir -p nullcv/federation/{activitypub,protocol}
mkdir -p nullcv/identity/{crypto,verification,attestation}
mkdir -p nullcv/ipfs/{client,storage}
mkdir -p nullcv/models/{schemas,entities,enums}
mkdir -p nullcv/reputation/{algorithms,proof}
mkdir -p nullcv/services/{jobs,matching,disputes,notifications}
mkdir -p nullcv/utils/{crypto,validators,logging}
mkdir -p nullcv/workers/{tasks,scheduler}
mkdir -p migrations scripts deployment

# Create base files
cat > nullcv/__init__.py << 'EOF'
"""NullCV: Proof-of-Work, Not Promises."""

__version__ = "0.1.0"
EOF

cat > nullcv/__main__.py << 'EOF'
"""Command-line execution for NullCV."""
import uvicorn
from nullcv.core.config import settings

if __name__ == "__main__":
    uvicorn.run(
        "nullcv.api.main:app",
        host=settings.SERVER_HOST,
        port=settings.SERVER_PORT,
        reload=settings.DEBUG,
        log_level="debug" if settings.DEBUG else "info",
    )
EOF

# Create main API application
cat > nullcv/api/main.py << 'EOF'
"""Main FastAPI application instance for NullCV."""
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware

from nullcv.core.config import settings
from nullcv.api.endpoints import router as api_router
from nullcv.core.events import startup_event_handler, shutdown_event_handler
from nullcv.api.middleware.logging import LoggingMiddleware

app = FastAPI(
    title=settings.PROJECT_NAME,
    description=settings.PROJECT_DESCRIPTION,
    version=settings.VERSION,
    docs_url="/api/docs" if settings.DEBUG else None,
    redoc_url="/api/redoc" if settings.DEBUG else None,
)

# Set up CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add custom middleware
app.add_middleware(LoggingMiddleware)

# Register event handlers
app.add_event_handler("startup", startup_event_handler)
app.add_event_handler("shutdown", shutdown_event_handler)

# Include API router
app.include_router(api_router, prefix="/api")
EOF

# Create main API router
cat > nullcv/api/endpoints/__init__.py << 'EOF'
"""API endpoints for NullCV platform."""
from fastapi import APIRouter

from nullcv.api.endpoints import jobs, users, projects, identity, reputation

router = APIRouter()
router.include_router(jobs.router, prefix="/jobs", tags=["jobs"])
router.include_router(users.router, prefix="/users", tags=["users"])
router.include_router(projects.router, prefix="/projects", tags=["projects"])
router.include_router(identity.router, prefix="/identity", tags=["identity"])
router.include_router(reputation.router, prefix="/reputation", tags=["reputation"])
EOF

# Create user router example
cat > nullcv/api/endpoints/users.py << 'EOF'
"""User endpoints for identity management."""
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from nullcv.identity.crypto import generate_identity
from nullcv.models.schemas.users import UserCreate, UserResponse
from nullcv.services.identity import IdentityService
from nullcv.api.dependencies.services import get_identity_service

router = APIRouter()

@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    user_create: UserCreate,
    identity_service: IdentityService = Depends(get_identity_service),
):
    """
    Create a new anonymous user identity with optional pseudonym.
    No personal information is required.
    """
    return await identity_service.create_identity(user_create)

@router.get("/prove/{user_id}", response_model=UserResponse)
async def get_user_proof(
    user_id: str,
    identity_service: IdentityService = Depends(get_identity_service),
):
    """
    Get cryptographic proof of user identity without revealing personal information.
    """
    user = await identity_service.get_identity_proof(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    return user
EOF

# Create configuration
cat > nullcv/core/config/__init__.py << 'EOF'
"""Configuration management for NullCV."""
from pydantic_settings import BaseSettings
from pydantic import AnyHttpUrl, validator
from typing import Any, Dict, List, Optional, Union

class Settings(BaseSettings):
    """Application settings."""
    
    # Base
    PROJECT_NAME: str = "NullCV"
    PROJECT_DESCRIPTION: str = "Proof-of-Work, Not Promises - A decentralized talent marketplace"
    VERSION: str = "0.1.0"
    DEBUG: bool = False
    
    # API
    SERVER_HOST: str = "0.0.0.0"
    SERVER_PORT: int = 8000
    API_PREFIX: str = "/api"
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days
    
    # CORS
    CORS_ORIGINS: List[AnyHttpUrl] = []
    
    # Database
    POSTGRES_SERVER: str
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str
    POSTGRES_DB: str
    SQLALCHEMY_DATABASE_URI: Optional[str] = None
    
    # Blockchain
    ETHEREUM_NODE_URL: str
    ETHEREUM_CHAIN_ID: int = 1  # Mainnet by default
    CONTRACT_ADDRESS: str
    
    # IPFS
    IPFS_API_URL: str = "http://localhost:5001/api/v0"
    
    # Federation
    ACTIVITYPUB_ENABLED: bool = True
    
    @validator("SQLALCHEMY_DATABASE_URI", pre=True)
    def assemble_db_connection(cls, v: Optional[str], values: Dict[str, Any]) -> Any:
        """Assemble database connection string."""
        if isinstance(v, str):
            return v
        return f"postgresql+asyncpg://{values.get('POSTGRES_USER')}:{values.get('POSTGRES_PASSWORD')}@{values.get('POSTGRES_SERVER')}/{values.get('POSTGRES_DB')}"

    class Config:
        """Pydantic config."""
        env_file = ".env"
        case_sensitive = True

settings = Settings()
EOF

# Create models
cat > nullcv/models/schemas/users.py << 'EOF'
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
EOF

# Create identity service
cat > nullcv/services/identity.py << 'EOF'
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
EOF

# Create crypto utilities
cat > nullcv/identity/crypto.py << 'EOF'
"""Cryptographic identity utilities."""
from eth_account import Account
from eth_keys import keys
import os
import hashlib
from typing import Tuple, Optional
import base64

def generate_keypair() -> Tuple[str, str]:
    """Generate a cryptographic keypair for user identity."""
    # Ethereum-style key generation
    entropy = os.urandom(32)
    account = Account.create(entropy)
    private_key = account.key.hex()
    public_key = account.address
    
    return private_key, public_key

def sign_message(message: str, private_key: str) -> str:
    """Sign a message with a private key."""
    account = Account.from_key(private_key)
    message_hash = hashlib.sha256(message.encode()).digest()
    signed_message = account.sign_message(message_hash)
    
    return signed_message.signature.hex()

def verify_signature(message: str, signature: str, public_key: str) -> bool:
    """Verify a signature using a public key."""
    message_hash = hashlib.sha256(message.encode()).digest()
    try:
        # Recover the address from the signature
        recovered_address = Account.recover_message(message_hash, signature=signature)
        return recovered_address.lower() == public_key.lower()
    except Exception:
        return False

def generate_identity() -> dict:
    """Generate a complete cryptographic identity."""
    private_key, public_key = generate_keypair()
    return {
        "private_key": private_key,
        "public_key": public_key,
        "created_at": import_time(),
    }

def hash_work_proof(content: bytes) -> str:
    """Create a cryptographic hash of work as proof."""
    return hashlib.sha256(content).hexdigest()

def create_zero_knowledge_proof(private_key: str, challenge: str) -> str:
    """
    Create a zero-knowledge proof that user possesses a private key
    without revealing it.
    """
    # Simplified implementation - a real zk-SNARK would be used here
    signature = sign_message(challenge, private_key)
    return signature
EOF

# Create blockchain escrow implementation
cat > nullcv/blockchain/escrow/contract.py << 'EOF'
"""Smart contract integration for escrow services."""
from web3 import Web3
from eth_account import Account
import json
from typing import Dict, Any, Optional

from nullcv.core.config import settings

class EscrowContract:
    """Interface to the NullCV escrow smart contract."""
    
    def __init__(self):
        """Initialize connection to Ethereum node."""
        self.w3 = Web3(Web3.HTTPProvider(settings.ETHEREUM_NODE_URL))
        self.contract_address = settings.CONTRACT_ADDRESS
        
        # Load contract ABI
        with open("nullcv/blockchain/contracts/escrow_abi.json") as f:
            contract_abi = json.load(f)
        
        # Initialize contract interface
        self.contract = self.w3.eth.contract(
            address=self.contract_address,
            abi=contract_abi
        )
    
    async def create_escrow(
        self, 
        client_address: str, 
        worker_address: str, 
        amount: int,
        project_id: str,
        private_key: str
    ) -> Dict[str, Any]:
        """
        Create a new escrow for a project.
        
        Args:
            client_address: Ethereum address of the client
            worker_address: Ethereum address of the worker
            amount: Amount in wei to escrow
            project_id: Unique project identifier
            private_key: Private key to sign the transaction
        """
        account = Account.from_key(private_key)
        
        # Prepare transaction
        tx = self.contract.functions.createEscrow(
            worker_address,
            project_id,
        ).build_transaction({
            'from': client_address,
            'value': amount,
            'gas': 200000,
            'gasPrice': self.w3.eth.gas_price,
            'nonce': self.w3.eth.get_transaction_count(client_address),
            'chainId': settings.ETHEREUM_CHAIN_ID,
        })
        
        # Sign and send transaction
        signed_tx = self.w3.eth.account.sign_transaction(tx, private_key)
        tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        
        # Wait for transaction receipt
        tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        
        # Parse event logs to get escrow ID
        escrow_created_events = self.contract.events.EscrowCreated().process_receipt(tx_receipt)
        if not escrow_created_events:
            raise Exception("Failed to create escrow: Event not found in transaction logs")
        
        escrow_id = escrow_created_events[0]['args']['escrowId']
        
        return {
            "escrow_id": escrow_id,
            "transaction_hash": tx_hash.hex(),
            "client_address": client_address,
            "worker_address": worker_address,
            "amount": amount,
            "project_id": project_id,
            "status": "created"
        }
    
    async def release_payment(
        self, 
        escrow_id: int, 
        sender_address: str,
        private_key: str
    ) -> Dict[str, Any]:
        """
        Release payment from escrow to worker after successful completion.
        
        Args:
            escrow_id: ID of the escrow
            sender_address: Address of the transaction sender (client)
            private_key: Private key to sign the transaction
        """
        # Prepare transaction
        tx = self.contract.functions.releasePayment(
            escrow_id
        ).build_transaction({
            'from': sender_address,
            'gas': 100000,
            'gasPrice': self.w3.eth.gas_price,
            'nonce': self.w3.eth.get_transaction_count(sender_address),
            'chainId': settings.ETHEREUM_CHAIN_ID,
        })
        
        # Sign and send transaction
        signed_tx = self.w3.eth.account.sign_transaction(tx, private_key)
        tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        
        # Wait for transaction receipt
        tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        
        return {
            "escrow_id": escrow_id,
            "transaction_hash": tx_hash.hex(),
            "status": "released"
        }
        
    async def get_escrow_details(self, escrow_id: int) -> Optional[Dict[str, Any]]:
        """
        Get details about an escrow.
        
        Args:
            escrow_id: ID of the escrow
        """
        try:
            escrow = self.contract.functions.escrows(escrow_id).call()
            
            return {
                "escrow_id": escrow_id,
                "client": escrow[0],
                "worker": escrow[1],
                "amount": escrow[2],
                "project_id": escrow[3],
                "released": escrow[4],
                "completed": escrow[5],
                "disputed": escrow[6],
            }
        except Exception:
            return None
EOF

# Create IPFS storage service
cat > nullcv/ipfs/storage.py << 'EOF'
"""IPFS storage integration for NullCV."""
import ipfshttpclient
import json
import hashlib
from typing import Any, Dict, Optional
import aiohttp
import asyncio

from nullcv.core.config import settings

class IPFSStorage:
    """Service for storing and retrieving data from IPFS."""
    
    def __init__(self):
        self.api_url = settings.IPFS_API_URL
    
    async def add_json(self, data: Dict[str, Any]) -> str:
        """
        Add JSON data to IPFS.
        
        Args:
            data: Dictionary to store on IPFS
            
        Returns:
            IPFS content hash (CID)
        """
        json_str = json.dumps(data)
        
        async with aiohttp.ClientSession() as session:
            endpoint = f"{self.api_url}/add"
            form = aiohttp.FormData()
            form.add_field('file', json_str, 
                          filename='data.json',
                          content_type='application/json')
            
            async with session.post(endpoint, data=form) as response:
                if response.status != 200:
                    raise Exception(f"IPFS add failed: {await response.text()}")
                
                result = await response.json()
                return result['Hash']
    
    async def get_json(self, ipfs_hash: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve JSON data from IPFS.
        
        Args:
            ipfs_hash: IPFS content hash (CID)
            
        Returns:
            Dictionary with retrieved data or None if not found
        """
        try:
            async with aiohttp.ClientSession() as session:
                endpoint = f"{self.api_url}/cat?arg={ipfs_hash}"
                
                async with session.post(endpoint) as response:
                    if response.status != 200:
                        return None
                    
                    content = await response.text()
                    return json.loads(content)
        except Exception:
            return None
    
    async def add_work_proof(self, 
                           user_id: str, 
                           project_id: str, 
                           content: bytes, 
                           metadata: Dict[str, Any]) -> Dict[str, str]:
        """
        Store work proof on IPFS with metadata.
        
        Args:
            user_id: ID of the user who completed the work
            project_id: ID of the project
            content: Binary content of the work
            metadata: Additional metadata about the work
            
        Returns:
            Dictionary with content hash and metadata hash
        """
        # Create content hash
        content_hash = hashlib.sha256(content).hexdigest()
        
        # Add metadata
        full_metadata = {
            **metadata,
            "user_id": user_id,
            "project_id": project_id,
            "content_hash": content_hash,
            "timestamp": import_time(),
        }
        
        # Store content on IPFS
        async with aiohttp.ClientSession() as session:
            content_endpoint = f"{self.api_url}/add"
            content_form = aiohttp.FormData()
            content_form.add_field('file', content, 
                          filename='work_content',
                          content_type='application/octet-stream')
            
            async with session.post(content_endpoint, data=content_form) as response:
                if response.status != 200:
                    raise Exception(f"IPFS add failed: {await response.text()}")
                
                content_result = await response.json()
                content_cid = content_result['Hash']
        
        # Add link to content in metadata
        full_metadata["ipfs_cid"] = content_cid
        
        # Store metadata on IPFS
        metadata_cid = await self.add_json(full_metadata)
        
        return {
            "content_cid": content_cid,
            "metadata_cid": metadata_cid,
            "content_hash": content_hash
        }
EOF

# Create event handlers
cat > nullcv/core/events.py << 'EOF'
"""Application event handlers."""
import logging
from typing import Callable
from fastapi import FastAPI

from nullcv.db.session import create_db_engine

logger = logging.getLogger(__name__)

async def startup_event_handler() -> None:
    """Handle application startup events."""
    logger.info("Running startup handlers")
    
    # Initialize database connection
    engine = await create_db_engine()
    
    # Initialize other services
    # ...
    
    logger.info("Application startup complete")

async def shutdown_event_handler() -> None:
    """Handle application shutdown events."""
    logger.info("Running shutdown handlers")
    
    # Close database connections
    # ...
    
    # Cleanup other resources
    # ...
    
    logger.info("Application shutdown complete")

def register_startup_event(app: FastAPI) -> Callable:
    """Register startup event handler."""
    
    async def start_app() -> None:
        await startup_event_handler()
    
    return start_app

def register_shutdown_event(app: FastAPI) -> Callable:
    """Register shutdown event handler."""
    
    async def stop_app() -> None:
        await shutdown_event_handler()
    
    return stop_app
EOF

# Create database session management
cat > nullcv/db/session.py << 'EOF'
"""Database session management."""
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from typing import AsyncGenerator

from nullcv.core.config import settings

# Create async database engine
async def create_db_engine():
    """Create SQLAlchemy async engine."""
    engine = create_async_engine(
        settings.SQLALCHEMY_DATABASE_URI,
        echo=settings.DEBUG,
        future=True,
    )
    return engine

# Create async session factory
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Get database session."""
    engine = await create_db_engine()
    async_session = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    
    async with async_session() as session:
        try:
            yield session
        finally:
            await session.close()
EOF

# Add some typings to __init__.py files to enable proper imports
for dir in $(find nullcv -type d); do
    if [ ! -f "$dir/__init__.py" ]; then
        echo '"""'$(basename $dir)' module."""' > "$dir/__init__.py"
    fi
done

# Create a sample .env file
cat > .env.example << 'EOF'
# API Configuration
SECRET_KEY=your_secret_key_here
DEBUG=True
SERVER_HOST=0.0.0.0
SERVER_PORT=8000

# Database Configuration
POSTGRES_SERVER=localhost
POSTGRES_USER=nullcv
POSTGRES_PASSWORD=nullcvpassword
POSTGRES_DB=nullcv

# Blockchain Configuration
ETHEREUM_NODE_URL=https://mainnet.infura.io/v3/your_infura_key
ETHEREUM_CHAIN_ID=1
CONTRACT_ADDRESS=0x0000000000000000000000000000000000000000

# IPFS Configuration
IPFS_API_URL=http://localhost:5001/api/v0

# CORS
CORS_ORIGINS=["http://localhost:3000"]
EOF

# Create sample smart contract ABI
mkdir -p nullcv/blockchain/contracts
cat > nullcv/blockchain/contracts/escrow_abi.json << 'EOF'
[
  {
    "inputs": [],
    "stateMutability": "nonpayable",
    "type": "constructor"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "internalType": "uint256",
        "name": "escrowId",
        "type": "uint256"
      },
      {
        "indexed": true,
        "internalType": "address",
        "name": "client",
        "type": "address"
      },
      {
        "indexed": true,
        "internalType": "address",
        "name": "worker",
        "type": "address"
      },
      {
        "indexed": false,
        "internalType": "uint256",
        "name": "amount",
        "type": "uint256"
      },
      {
        "indexed": false,
        "internalType": "string",
        "name": "projectId",
        "type": "string"
      }
    ],
    "name": "EscrowCreated",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "internalType": "uint256",
        "name": "escrowId",
        "type": "uint256"
      }
    ],
    "name": "EscrowReleased",
    "type": "event"
  },
  {
    "inputs": [
      {
        "internalType": "address",
        "name": "_worker",
        "type": "address"
      },
      {
        "internalType": "string",
        "name": "_projectId",
        "type": "string"
      }
    ],
    "name": "createEscrow",
    "outputs": [
      {
        "internalType": "uint256",
        "name": "",
        "type": "uint256"
      }
    ],
    "stateMutability": "payable",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "uint256",
        "name": "",
        "type": "uint256"
      }
    ],
    "name": "escrows",
    "outputs": [
      {
        "internalType": "address",
        "name": "client",
        "type": "address"
      },
      {
        "internalType": "address",
        "name": "worker",
        "type": "address"
      },
      {
        "internalType": "uint256",
        "name": "amount",
        "type": "uint256"
      },
      {
        "internalType": "string",
        "name": "projectId",
        "type": "string"
      },
      {
        "internalType": "bool",
        "name": "released",
        "type": "bool"
      },
      {
        "internalType": "bool",
        "name": "completed",
        "type": "bool"
      },
      {
        "internalType": "bool",
        "name": "disputed",
        "type": "bool"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "nextEscrowId",
    "outputs": [
      {
        "internalType": "uint256",
        "name": "",
        "type": "uint256"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "uint256",
        "name": "_escrowId",
        "type": "uint256"
      }
    ],
    "name": "releasePayment",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  }
]
EOF

# Create deployment Docker files
cat > Dockerfile << 'EOF'
FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libpq-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN pip install