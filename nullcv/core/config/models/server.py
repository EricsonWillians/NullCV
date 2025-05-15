from typing import List, Union
from pydantic import BaseSettings, Field, validator

from ..base import global_manager


class ServerConfig(BaseSettings):
    SERVER_HOST: str = "0.0.0.0"
    SERVER_PORT: int = 8000
    API_PREFIX: str = "/api"
    API_VERSION: str = "v1"
    CORS_ORIGINS: List[str] = ["http://localhost:3000"]
    WORKER_COUNT: int | None = None

    @validator("CORS_ORIGINS", pre=True)
    def _split_csv(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str) and "," in v:
            return [s.strip() for s in v.split(",")]
        return v

    class Config:
        frozen = True
        case_sensitive = True


server = ServerConfig(_env_override=global_manager().get)  # type: ignore
