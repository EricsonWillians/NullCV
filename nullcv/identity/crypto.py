"""Cryptographic identity utilities."""
from eth_account import Account
from eth_keys import keys
import os
import hashlib
from typing import Tuple, Optional
import base64

def generate_keypair() -> Tuple[str, str]:
    """Generate a cryptographic keypair for user identity."""
    # Ethereum-style key generation
    entropy = os.urandom(32)
    account = Account.create(entropy)
    private_key = account.key.hex()
    public_key = account.address
    
    return private_key, public_key

def sign_message(message: str, private_key: str) -> str:
    """Sign a message with a private key."""
    account = Account.from_key(private_key)
    message_hash = hashlib.sha256(message.encode()).digest()
    signed_message = account.sign_message(message_hash)
    
    return signed_message.signature.hex()

def verify_signature(message: str, signature: str, public_key: str) -> bool:
    """Verify a signature using a public key."""
    message_hash = hashlib.sha256(message.encode()).digest()
    try:
        # Recover the address from the signature
        recovered_address = Account.recover_message(message_hash, signature=signature)
        return recovered_address.lower() == public_key.lower()
    except Exception:
        return False

def generate_identity() -> dict:
    """Generate a complete cryptographic identity."""
    private_key, public_key = generate_keypair()
    return {
        "private_key": private_key,
        "public_key": public_key,
        "created_at": import_time(),
    }

def hash_work_proof(content: bytes) -> str:
    """Create a cryptographic hash of work as proof."""
    return hashlib.sha256(content).hexdigest()

def create_zero_knowledge_proof(private_key: str, challenge: str) -> str:
    """
    Create a zero-knowledge proof that user possesses a private key
    without revealing it.
    """
    # Simplified implementation - a real zk-SNARK would be used here
    signature = sign_message(challenge, private_key)
    return signature
