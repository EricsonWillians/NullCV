"""
Re-export all domain settings singletons so the façade can import them cleanly.
"""

from .app import AppConfig, app
from .server import ServerConfig, server
from .auth import AuthConfig, auth
from .database import DatabaseConfig, db
from .blockchain import BlockchainConfig, blockchain
from .ipfs import IPFSConfig, ipfs
from .federation import FederationConfig, federation
from .email import EmailConfig, email
from .redis import RedisConfig, redis
from .api_security import APISecurityConfig, api_sec
from .monitoring import MonitoringConfig, monitoring
from .cache import CacheConfig, cache

__all__ = [
    "AppConfig", "ServerConfig", "AuthConfig", "DatabaseConfig", "BlockchainConfig",
    "IPFSConfig", "FederationConfig", "EmailConfig", "RedisConfig",
    "APISecurityConfig", "MonitoringConfig", "CacheConfig",
    "app", "server", "auth", "db", "blockchain", "ipfs", "federation",
    "email", "redis", "api_sec", "monitoring", "cache",
]
