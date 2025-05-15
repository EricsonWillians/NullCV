from typing import List, Optional
from pydantic import BaseSettings, Field, SecretStr, validator

from ..base import global_manager


class FederationConfig(BaseSettings):
    ACTIVITYPUB_ENABLED: bool = True
    ACTIVITYPUB_DOMAIN: Optional[str] = None
    FEDERATION_NODE_ID: Optional[str] = None
    FEDERATION_PRIVATE_KEY: Optional[SecretStr] = None
    FEDERATION_SHARED_SECRET: Optional[SecretStr] = None
    FEDERATION_TRUSTED_INSTANCES: List[str] = []

    @validator("ACTIVITYPUB_DOMAIN")
    def _domain_required(cls, v, values):
        if values.get("ACTIVITYPUB_ENABLED") and not v:
            raise ValueError("ACTIVITYPUB_DOMAIN required when federation enabled")
        return v

    class Config:
        frozen = True
        case_sensitive = True


federation = FederationConfig(_env_override=global_manager().get)  # type: ignore
