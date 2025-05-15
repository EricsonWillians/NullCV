from typing import List
from pydantic import BaseSettings, Field, validator

from ..base import global_manager


class CacheConfig(BaseSettings):
    CACHE_ENABLED: bool = True
    CACHE_TYPE: str = Field("memory", description="memory|redis|memcached")
    CACHE_DEFAULT_TTL: int = 300
    CACHE_KEY_PREFIX: str = "nullcv:"
    CACHE_MAX_SIZE: int = 1000
    CACHE_MEMCACHED_SERVERS: List[str] = ["localhost:11211"]

    @validator("CACHE_TYPE")
    def _type(cls, v: str) -> str:
        """
        Validates that the provided cache type is one of the allowed options.
        
        Raises:
            ValueError: If the cache type is not "memory", "redis", or "memcached".
        
        Returns:
            The validated cache type string.
        """
        if v not in {"memory", "redis", "memcached"}:
            raise ValueError("Invalid CACHE_TYPE")
        return v

    class Config:
        frozen = True
        case_sensitive = True


cache = CacheConfig(_env_override=global_manager().get)  # type: ignore
