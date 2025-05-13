"""NullCV Configuration Management.

Features:
- Hierarchical .env file discovery
- Environment-aware configuration
- Validation with detailed error reporting
- Enhanced security for sensitive values
- Support for local development overrides
"""

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

from pydantic import AnyHttpUrl, Field, SecretStr, validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def find_env_file() -> List[Path]:
    """
    Hierarchically discover environment files in the following order (highest to lowest priority):
    1. .env.{ENVIRONMENT}.local (e.g. .env.dev.local) - for local developer overrides (gitignored)
    2. .env.local - for local developer overrides (gitignored)
    3. .env.{ENVIRONMENT} (e.g. .env.dev, .env.prod) - for environment-specific settings
    4. .env - for default settings
    
    Returns a list of discovered env files in priority order.
    """
    env_files = []
    base_dir = Path(__file__).resolve().parents[3]
    environment = os.getenv("ENVIRONMENT", "dev")
    
    # Define search paths in order of priority
    search_paths = [
        base_dir / f".env.{environment}.local",
        base_dir / ".env.local", 
        base_dir / f".env.{environment}",
        base_dir / ".env"
    ]
    
    # Add any existing files to the list
    for path in search_paths:
        if path.exists():
            env_files.append(path)
            logging.debug(f"Found env file: {path}")
    
    if not env_files:
        logging.warning("No .env files found in the project hierarchy.")
        
    return env_files


class LoggingConfig(BaseSettings):
    """Logging configuration."""
    
    LOG_LEVEL: str = Field("INFO", description="Logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL")
    LOG_FORMAT: str = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    LOG_TO_FILE: bool = False
    LOG_FILE_PATH: Optional[str] = None
    
    model_config = SettingsConfigDict(
        env_prefix="", 
        case_sensitive=True,
        env_file=find_env_file(),
        extra="ignore"
    )


class AppConfig(BaseSettings):
    """Core application settings."""
    
    PROJECT_NAME: str = "NullCV"
    PROJECT_DESCRIPTION: str = (
        "Proof-of-Work, Not Promises — A decentralized talent marketplace."
    )
    VERSION: str = "0.1.0"
    DEBUG: bool = False
    ENVIRONMENT: str = Field("dev", description="Runtime environment: dev | prod | test | staging")
    
    model_config = SettingsConfigDict(
        env_prefix="", 
        case_sensitive=True,
        env_file=find_env_file(),
        extra="ignore"
    )


class ServerConfig(BaseSettings):
    """Server settings."""
    
    SERVER_HOST: str = "0.0.0.0"
    SERVER_PORT: int = 8000
    API_PREFIX: str = "/api"
    CORS_ORIGINS: List[str] = Field(
        default=["http://localhost:3000"], 
        description="List of origins that are allowed to make cross-origin requests"
    )
    CORS_ALLOW_CREDENTIALS: bool = True
    MAX_REQUEST_SIZE_MB: int = 50
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_PERIOD_SECONDS: int = 60
    
    @validator("CORS_ORIGINS", pre=True)
    def validate_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        """Support comma-separated string of URLs or a list."""
        if isinstance(v, str) and not v.startswith("["):
            return [url.strip() for url in v.split(",")]
        elif isinstance(v, list):
            return v
        elif isinstance(v, str):
            import json
            return json.loads(v)
        raise ValueError(f"Invalid CORS_ORIGINS format: {v}")
    
    model_config = SettingsConfigDict(
        env_prefix="", 
        case_sensitive=True,
        env_file=find_env_file(),
        extra="ignore"
    )


class AuthConfig(BaseSettings):
    """Authentication & Security."""
    
    SECRET_KEY: SecretStr
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    PASSWORD_RESET_TOKEN_EXPIRE_MINUTES: int = 30
    VERIFY_EMAIL_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 1 day
    MIN_PASSWORD_LENGTH: int = 12
    
    model_config = SettingsConfigDict(
        env_prefix="", 
        case_sensitive=True,
        env_file=find_env_file(),
        extra="ignore"
    )


class DatabaseConfig(BaseSettings):
    """PostgreSQL database connection settings."""

    POSTGRES_SERVER: str
    POSTGRES_PORT: str = "5432"
    POSTGRES_USER: str
    POSTGRES_PASSWORD: SecretStr
    POSTGRES_DB: str
    SQLALCHEMY_DATABASE_URI: Optional[str] = None
    SQLALCHEMY_POOL_SIZE: int = 5
    SQLALCHEMY_MAX_OVERFLOW: int = 10
    SQLALCHEMY_POOL_TIMEOUT: int = 30  # seconds
    DATABASE_ECHO: bool = False  # Set to True to log all SQL queries

    @validator("SQLALCHEMY_DATABASE_URI", pre=True)
    def build_db_uri(cls, v: Optional[str], values: Dict[str, Any]) -> Optional[str]:
        """Construct full database URI if not explicitly provided."""
        if v is not None:
            return v

        required = ["POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_SERVER", "POSTGRES_DB"]
        missing = [key for key in required if key not in values or not values.get(key)]
        
        if missing:
            missing_fields = ", ".join(missing)
            raise ValueError(f"Missing required database connection fields: {missing_fields}")

        # Get the actual string value from SecretStr
        password = values["POSTGRES_PASSWORD"].get_secret_value()
        port = values.get("POSTGRES_PORT", "5432")
            
        return (
            f"postgresql+asyncpg://{values['POSTGRES_USER']}:"
            f"{password}@"
            f"{values['POSTGRES_SERVER']}:{port}/"
            f"{values['POSTGRES_DB']}"
        )
    
    model_config = SettingsConfigDict(
        env_prefix="", 
        case_sensitive=True,
        env_file=find_env_file(),
        extra="ignore"
    )


class BlockchainConfig(BaseSettings):
    """Ethereum and other blockchain-related settings."""
    
    ETHEREUM_NODE_URL: str
    ETHEREUM_CHAIN_ID: int = 1  # Mainnet by default
    CONTRACT_ADDRESS: str
    WALLET_PRIVATE_KEY: Optional[SecretStr] = None
    GAS_PRICE_STRATEGY: str = "medium"  # options: slow, medium, fast, fastest
    GAS_LIMIT_MARGIN: float = 1.2  # 20% margin for gas limit estimation
    TRANSACTION_TIMEOUT: int = 120  # seconds
    
    model_config = SettingsConfigDict(
        env_prefix="", 
        case_sensitive=True,
        env_file=find_env_file(),
        extra="ignore"
    )


class IPFSConfig(BaseSettings):
    """IPFS client and storage settings."""
    
    IPFS_API_URL: str = "http://localhost:5001/api/v0"
    IPFS_GATEWAY_URL: str = "https://ipfs.io/ipfs/"
    IPFS_CONNECT_TIMEOUT: int = 10  # seconds
    IPFS_READ_TIMEOUT: int = 30  # seconds
    IPFS_MAX_FILE_SIZE_MB: int = 50
    IPFS_PIN_FILES: bool = True
    
    model_config = SettingsConfigDict(
        env_prefix="", 
        case_sensitive=True,
        env_file=find_env_file(),
        extra="ignore"
    )


class FederationConfig(BaseSettings):
    """Federation protocol settings."""
    
    ACTIVITYPUB_ENABLED: bool = True
    ACTIVITYPUB_DOMAIN: Optional[str] = None
    FEDERATION_NODE_ID: Optional[str] = None
    FEDERATION_PUBLIC_KEY: Optional[str] = None
    FEDERATION_PRIVATE_KEY: Optional[SecretStr] = None
    ALLOW_REMOTE_FOLLOWS: bool = True
    
    model_config = SettingsConfigDict(
        env_prefix="", 
        case_sensitive=True,
        env_file=find_env_file(),
        extra="ignore"
    )


class Settings(
    AppConfig,
    ServerConfig,
    AuthConfig,
    DatabaseConfig,
    BlockchainConfig,
    IPFSConfig,
    FederationConfig,
    LoggingConfig,
):
    """Aggregated settings for the NullCV application."""
    
    @validator("ENVIRONMENT")
    def validate_environment(cls, v: str) -> str:
        """Ensure environment is one of the allowed values."""
        allowed = {"dev", "test", "staging", "prod"}
        if v not in allowed:
            raise ValueError(f"ENVIRONMENT must be one of: {', '.join(allowed)}")
        return v
    
    def configure_logging(self) -> None:
        """Configure application logging based on settings."""
        log_level = getattr(logging, self.LOG_LEVEL.upper(), logging.INFO)
        
        logging_config = {
            'level': log_level,
            'format': self.LOG_FORMAT,
            'handlers': []
        }
        
        # Always add console handler
        logging_config['handlers'].append(logging.StreamHandler())
        
        # Add file handler if configured
        if self.LOG_TO_FILE and self.LOG_FILE_PATH:
            file_handler = logging.FileHandler(self.LOG_FILE_PATH)
            logging_config['handlers'].append(file_handler)
        
        # Apply configuration
        for handler in logging_config['handlers']:
            handler.setLevel(log_level)
            handler.setFormatter(logging.Formatter(self.LOG_FORMAT))
        
        root_logger = logging.getLogger()
        root_logger.setLevel(log_level)
        
        # Clear existing handlers and add new ones
        root_logger.handlers = []
        for handler in logging_config['handlers']:
            root_logger.addHandler(handler)
        
        logging.info(f"Logging configured with level {self.LOG_LEVEL}")


# Load settings with hierarchical env file discovery
settings = Settings()

# Configure application logging
settings.configure_logging()

# Log discovered environment settings (except sensitive values)
if settings.DEBUG:
    logging.debug("Loaded configuration from environment files:")
    for env_file in find_env_file():
        logging.debug(f"  - {env_file}")