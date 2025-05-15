from pathlib import Path
from pydantic import Field
from pydantic_settings import BaseSettings

from ..base import global_manager


class AppConfig(BaseSettings):
    """Core application settings."""
    PROJECT_NAME: str = "NullCV"
    VERSION: str = "0.1.0"
    ENVIRONMENT: str = Field("dev", description="dev|test|staging|prod")
    DATA_DIR: Path = Path("./data")
    TEMP_DIR: Path = Path("./tmp")
    DEBUG: bool = False

    class Config:
        env_prefix = ""
        case_sensitive = True
        frozen = True  # ← makes the singleton hashable / immutable


app = AppConfig(_env_override=global_manager().get)  # type: ignore
