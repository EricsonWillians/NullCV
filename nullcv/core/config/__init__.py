"""NullCV Configuration Management."""

import logging
from typing import Any, Dict, List, Optional
from pydantic import AnyHttpUrl, Field, validator
from pydantic_settings import BaseSettings


class AppConfig(BaseSettings):
    """Core application settings."""
    
    PROJECT_NAME: str = "NullCV"
    PROJECT_DESCRIPTION: str = (
        "Proof-of-Work, Not Promises — A decentralized talent marketplace."
    )
    VERSION: str = "0.1.0"
    DEBUG: bool = False
    ENVIRONMENT: str = Field("dev", description="Runtime environment: dev | prod | test")

    class Config:
        env_prefix = ""
        env_file = ".env"
        case_sensitive = True


class ServerConfig(BaseSettings):
    """Server settings."""
    
    SERVER_HOST: str = "0.0.0.0"
    SERVER_PORT: int = 8000
    API_PREFIX: str = "/api"
    CORS_ORIGINS: List[AnyHttpUrl] = []


class AuthConfig(BaseSettings):
    """Authentication & Security."""
    
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days


class DatabaseConfig(BaseSettings):
    """PostgreSQL connection settings."""

    POSTGRES_SERVER: str
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str
    POSTGRES_DB: str
    SQLALCHEMY_DATABASE_URI: Optional[str] = None

    @validator("SQLALCHEMY_DATABASE_URI", pre=True)
    def build_db_uri(cls, v: Optional[str], values: Dict[str, Any]) -> Optional[str]:
        """Construct full DB URI if not explicitly provided."""
        if v is not None:
            return v

        required = ["POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_SERVER", "POSTGRES_DB"]
        if not all(values.get(k) for k in required):
            return None  # Let Pydantic raise missing field errors cleanly

        return (
            f"postgresql+asyncpg://{values['POSTGRES_USER']}:"
            f"{values['POSTGRES_PASSWORD']}@"
            f"{values['POSTGRES_SERVER']}/"
            f"{values['POSTGRES_DB']}"
        )


class BlockchainConfig(BaseSettings):
    """Ethereum-related blockchain settings."""
    
    ETHEREUM_NODE_URL: str
    ETHEREUM_CHAIN_ID: int = 1  # Mainnet by default
    CONTRACT_ADDRESS: str


class IPFSConfig(BaseSettings):
    """IPFS client settings."""
    
    IPFS_API_URL: str = "http://localhost:5001/api/v0"


class FederationConfig(BaseSettings):
    """Federation protocol settings."""
    
    ACTIVITYPUB_ENABLED: bool = True


class Settings(
    AppConfig,
    ServerConfig,
    AuthConfig,
    DatabaseConfig,
    BlockchainConfig,
    IPFSConfig,
    FederationConfig,
):
    """Aggregated settings for NullCV application."""


# Load settings from environment or .env
settings = Settings()

# Bootstrap global logging
logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
