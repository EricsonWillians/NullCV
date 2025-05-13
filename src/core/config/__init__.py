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
