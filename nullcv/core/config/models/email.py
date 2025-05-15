from pathlib import Path
from typing import List, Optional
from pydantic import BaseSettings, Field, SecretStr, validator

from ..base import global_manager


class EmailConfig(BaseSettings):
    EMAIL_ENABLED: bool = True
    EMAIL_SENDER_ADDRESS: str = "noreply@nullcv.io"
    EMAIL_SMTP_SERVER: str = "localhost"
    EMAIL_SMTP_PORT: int = 587
    EMAIL_SMTP_USERNAME: Optional[str] = None
    EMAIL_SMTP_PASSWORD: Optional[SecretStr] = None
    EMAIL_TEMPLATES_DIR: Path = Path("./templates/email")
    EMAIL_RATE_LIMIT: int = 100
    EMAIL_TEST_MODE: bool = False
    EMAIL_TEST_RECIPIENTS: List[str] = []

    @validator("EMAIL_SENDER_ADDRESS")
    def _email(cls, v: str) -> str:
        if "@" not in v:
            raise ValueError("Invalid email")
        return v

    class Config:
        frozen = True
        case_sensitive = True


email = EmailConfig(_env_override=global_manager().get)  # type: ignore
