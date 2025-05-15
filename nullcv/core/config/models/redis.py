from typing import List, Optional
from pydantic import BaseSettings, Field, SecretStr

from ..base import global_manager


class RedisConfig(BaseSettings):
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: Optional[SecretStr] = None
    REDIS_DB: int = 0
    REDIS_USE_CLUSTER: bool = False
    REDIS_CLUSTER_NODES: List[str] = []
    REDIS_CACHE_TTL: int = 3600

    class Config:
        frozen = True
        case_sensitive = True


redis = RedisConfig(_env_override=global_manager().get)  # type: ignore
