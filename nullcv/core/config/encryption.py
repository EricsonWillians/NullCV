"""
Secure helpers for config encryption/decryption.
Uses Fernet (AES-128 GCM) instead of the custom XOR stream cipher.
"""

import base64, os, hashlib
from datetime import datetime
from cryptography.fernet import Fernet, InvalidToken  # pip install cryptography

__all__ = ["derive_key", "encrypt", "decrypt"]

def derive_key(base_key: str, salt: bytes | None = None) -> bytes:
    """
    Derives a Fernet-compatible encryption key from a base key using PBKDF2-HMAC-SHA256.
    
    Args:
        base_key: The input string to derive the key from.
        salt: Optional salt value. If not provided, a random 16-byte salt is generated.
    
    Returns:
        A 32-byte key encoded in URL-safe base64 suitable for Fernet encryption.
    """
    salt = salt or os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", base_key.encode(), salt, 100_000, dklen=32)
    return base64.urlsafe_b64encode(dk)

def encrypt(value: str, fernet_key: bytes) -> str:
    """
    Encrypts a string using the provided Fernet key.
    
    Args:
        value: The plaintext string to encrypt.
        fernet_key: The Fernet-compatible key used for encryption.
    
    Returns:
        The encrypted string encoded in UTF-8.
    """
    return Fernet(fernet_key).encrypt(value.encode()).decode()

def decrypt(token: str, fernet_key: bytes) -> str:
    """
    Decrypts an encrypted token string using the provided Fernet key.
    
    Args:
        token: The encrypted string to decrypt.
        fernet_key: The Fernet key used for decryption.
    
    Returns:
        The decrypted plaintext string.
    
    Raises:
        ValueError: If the token is invalid or corrupted.
    """
    try:
        return Fernet(fernet_key).decrypt(token.encode()).decode()
    except InvalidToken as exc:  # pragma: no cover
        raise ValueError("Invalid or corrupted encrypted value") from exc
