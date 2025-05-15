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
    PBKDF2-HMAC-SHA256 → 32-byte key → urlsafe_b64 for Fernet.
    """
    salt = salt or os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", base_key.encode(), salt, 100_000, dklen=32)
    return base64.urlsafe_b64encode(dk)

def encrypt(value: str, fernet_key: bytes) -> str:
    return Fernet(fernet_key).encrypt(value.encode()).decode()

def decrypt(token: str, fernet_key: bytes) -> str:
    try:
        return Fernet(fernet_key).decrypt(token.encode()).decode()
    except InvalidToken as exc:  # pragma: no cover
        raise ValueError("Invalid or corrupted encrypted value") from exc
