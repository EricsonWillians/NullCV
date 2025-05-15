from pathlib import Path
from typing import Any, Dict, Optional
from pydantic import BaseSettings, Field, SecretStr, validator

from ..base import global_manager


class DatabaseConfig(BaseSettings):
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_PORT: str = "5432"
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: SecretStr = SecretStr("postgres")
    POSTGRES_DB: str = "nullcv"
    SQLALCHEMY_DATABASE_URI: Optional[str] = None
    SQLITE_DATABASE_PATH: Path = Path("./data/nullcv.db")

    @validator("SQLALCHEMY_DATABASE_URI", pre=True)
    def _build_uri(cls, v: Optional[str], values: Dict[str, Any]) -> str:
        """
        Constructs the SQLAlchemy database URI from PostgreSQL settings if not explicitly provided.
        
        Args:
            v: The existing database URI, if any.
            values: A dictionary of current field values, including PostgreSQL credentials.
        
        Returns:
            The SQLAlchemy database URI as a string.
        """
        if v:
            return v
        pwd = values["POSTGRES_PASSWORD"].get_secret_value()
        return (f"postgresql+asyncpg://{values['POSTGRES_USER']}:{pwd}@"
                f"{values['POSTGRES_SERVER']}:{values['POSTGRES_PORT']}/"
                f"{values['POSTGRES_DB']}")

    class Config:
        frozen = True
        case_sensitive = True


db = DatabaseConfig(_env_override=global_manager().get)  # type: ignore
