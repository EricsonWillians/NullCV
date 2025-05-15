from typing import Dict, List
from pydantic import BaseSettings, Field, SecretStr, validator

from ..base import global_manager


class AuthConfig(BaseSettings):
    SECRET_KEY: SecretStr = Field(..., description=" ≥32 chars")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7
    MIN_PASSWORD_LENGTH: int = 12
    PASSWORD_COMPLEXITY: Dict[str, int] = {
        "uppercase": 1, "lowercase": 1, "digits": 1, "special": 1
    }
    ENABLE_2FA: bool = False
    DEFAULT_ROLE_NAME: str = "user"

    @validator("SECRET_KEY")
    def _strong_key(cls, v: SecretStr) -> SecretStr:
        if len(v.get_secret_value()) < 32:
            raise ValueError("SECRET_KEY must be ≥32 chars")
        return v

    class Config:
        frozen = True
        case_sensitive = True


auth = AuthConfig(_env_override=global_manager().get)  # type: ignore
