from pathlib import Path
from typing import List
from pydantic import BaseSettings, Field, validator

from ..base import global_manager


class IPFSConfig(BaseSettings):
    IPFS_API_URL: str = "http://localhost:5001/api/v0"
    IPFS_GATEWAY_URL: str = "https://ipfs.io/ipfs/"
    IPFS_PIN_FILES: bool = True
    IPFS_LOCAL_STORAGE_PATH: Path = Path("./data/ipfs")
    IPFS_FALLBACK_GATEWAYS: List[str] = [
        "https://ipfs.io/ipfs/",
        "https://gateway.pinata.cloud/ipfs/",
    ]

    @validator("IPFS_API_URL", "IPFS_GATEWAY_URL")
    def _url(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v

    class Config:
        frozen = True
        case_sensitive = True


ipfs = IPFSConfig(_env_override=global_manager().get)  # type: ignore
