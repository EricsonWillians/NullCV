from typing import Dict, List, Optional
from pydantic import BaseSettings, Field, SecretStr, validator

from ..base import global_manager


class BlockchainConfig(BaseSettings):
    ETHEREUM_NODE_URL: str = "https://mainnet.infura.io/v3/"
    ETHEREUM_CHAIN_ID: int = 1
    CONTRACT_ADDRESS: str = Field(..., description="0x…")
    WALLET_PRIVATE_KEY: Optional[SecretStr] = None
    MAX_GAS_PRICE_GWEI: int = 150
    SMART_CONTRACT_CONSTRUCTOR_ARGS: Dict[str, str] = {}

    @validator("CONTRACT_ADDRESS")
    def _addr(cls, v: str) -> str:
        """
        Validates that the provided string is a properly formatted Ethereum address.
        
        Raises:
            ValueError: If the address does not start with '0x' or is not 42 characters long.
        
        Returns:
            The validated Ethereum address string.
        """
        if not (v.startswith("0x") and len(v) == 42):
            raise ValueError("Invalid Ethereum address")
        return v

    class Config:
        frozen = True
        case_sensitive = True


blockchain = BlockchainConfig(_env_override=global_manager().get)  # type: ignore
