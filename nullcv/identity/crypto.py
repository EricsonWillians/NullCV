"""
Cryptographic identity and verification module.

This module provides cryptographic utilities for:
1. Key generation and management
2. Data signing and verification
3. Secure hashing
4. Encryption/decryption of sensitive data
"""

import os
import json
import hashlib
import base64
import logging
from typing import Any, Dict, NamedTuple, Optional, Union
from datetime import datetime, timezone

import nacl.signing
import nacl.encoding
import nacl.hash
import nacl.secret
import nacl.public
from nacl.exceptions import BadSignatureError

# Configure logging
logger = logging.getLogger(__name__)

class KeyPair(NamedTuple):
    """Cryptographic key pair."""
    
    private_key: str
    public_key: str


def generate_keypair() -> KeyPair:
    """
    Generate a new Ed25519 key pair.
    
    Returns:
        A KeyPair named tuple containing private_key and public_key as hex strings
    """
    # Generate a new signing key
    signing_key = nacl.signing.SigningKey.generate()
    
    # Get the verify key (public key)
    verify_key = signing_key.verify_key
    
    # Convert keys to hex format
    private_key_hex = signing_key.encode(encoder=nacl.encoding.HexEncoder).decode('utf-8')
    public_key_hex = verify_key.encode(encoder=nacl.encoding.HexEncoder).decode('utf-8')
    
    return KeyPair(private_key=private_key_hex, public_key=public_key_hex)


def sign_data(data: Any, private_key_hex: str) -> str:
    """
    Sign data with a private key.
    
    Args:
        data: The data to sign
        private_key_hex: Hex-encoded private key
        
    Returns:
        A hex-encoded signature
    """
    # Convert data to JSON string if it's not already a string
    if not isinstance(data, str):
        data = json.dumps(data, sort_keys=True)
    
    # Convert private key from hex to binary
    private_key_bytes = bytes.fromhex(private_key_hex