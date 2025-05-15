from typing import List, Optional
from pydantic import BaseSettings, Field

from ..base import global_manager


class APISecurityConfig(BaseSettings):
    API_KEY_HEADER_NAME: str = "X-API-Key"
    API_REQUIRE_HTTPS: bool = True
    API_RATE_LIMIT_BY_IP: bool = True
    API_RATE_LIMIT_EXEMPTED_IPS: List[str] = []
    API_ALLOWED_USER_AGENTS: Optional[List[str]] = None

    class Config:
        frozen = True
        case_sensitive = True


api_sec = APISecurityConfig(_env_override=global_manager().get)  # type: ignore
