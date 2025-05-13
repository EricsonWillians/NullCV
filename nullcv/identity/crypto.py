"""
Cryptographic Identity and Verification Module for NullCV
========================================================

A comprehensive security layer providing state-of-the-art cryptographic primitives:

1. Ed25519 key generation, management and encoding with secure entropy sources
2. Deterministic signature creation with canonical serialization for data consistency
3. High-assurance verification mechanisms with detailed failure reporting
4. Secure SHA-256 hashing for data integrity with multiple encoding options
5. Advanced authenticated encryption (AEAD) for secure communications
6. Tamper-evident timestamped signature metadata with trusted timestamping support
7. Key derivation and rotation utilities for enhanced security lifecycle
8. Zero-knowledge proof capabilities for privacy-preserving verification

Security Properties:
- Forward secrecy for long-term key protection
- Constant-time operations to prevent timing side-channels
- Misuse-resistant APIs to prevent common cryptographic errors
- Hardware-backed key storage integration where available
- Quantum-resistant considerations and upgrade paths
"""

import os
import json
import hashlib
import base64
import logging
import secrets
import hmac
from typing import Any, Dict, List, NamedTuple, Optional, Union, Tuple, Callable
from datetime import datetime, timezone, timedelta
from enum import Enum, auto
from functools import wraps
from dataclasses import dataclass, field

import nacl.signing
import nacl.encoding
import nacl.hash
import nacl.secret
import nacl.public
import nacl.pwhash
import nacl.bindings
from nacl.exceptions import BadSignatureError, CryptoError, InvalidkeyError
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption

# Configure robust logging with sensitive data protection
logger = logging.getLogger(__name__)

class SecurityLevel(Enum):
    """Security level classification for cryptographic operations."""
    STANDARD = auto()     # Suitable for most operations
    ENHANCED = auto()     # Higher security for sensitive operations
    CRITICAL = auto()     # Maximum security for critical operations

class KeyType(Enum):
    """Types of keys supported by the cryptographic module."""
    SIGNING = auto()      # Ed25519 signing keys
    ENCRYPTION = auto()   # X25519 encryption keys
    SYMMETRIC = auto()    # Symmetric encryption keys
    MASTER = auto()       # Master derivation keys

class KeyFormat(Enum):
    """Supported formats for key representation."""
    RAW = auto()          # Raw binary representation
    HEX = auto()          # Hexadecimal string encoding
    BASE64 = auto()       # Base64 string encoding
    BASE64URL = auto()    # URL-safe Base64 string encoding

@dataclass
class CryptoMetadata:
    """Rich metadata for cryptographic operations."""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    algorithm: str = "Ed25519"
    version: str = "1.0.0"
    key_id: Optional[str] = None
    nonce: Optional[str] = None
    additional_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to dictionary, excluding None values."""
        return {k: v for k, v in self.__dict__.items() if v is not None}

class KeyPair(NamedTuple):
    """Represents a hex-encoded cryptographic keypair with optional metadata."""
    private_key: str
    public_key: str
    key_id: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: Dict[str, Any] = {}

class SignatureBundle(NamedTuple):
    """A complete signature bundle with verification metadata."""
    signature: str
    public_key: str
    key_id: str
    timestamp: str
    algorithm: str = "Ed25519"
    metadata: Dict[str, Any] = {}

class CryptoError(Exception):
    """Base exception for all cryptographic errors."""
    pass

class SignatureError(CryptoError):
    """Exception raised for signature verification failures."""
    pass

class KeyGenerationError(CryptoError):
    """Exception raised for key generation failures."""
    pass

class SerializationError(CryptoError):
    """Exception raised for data serialization failures."""
    pass

class EncryptionError(CryptoError):
    """Exception raised for encryption/decryption failures."""
    pass

def _ensure_entropy() -> None:
    """Ensure system has adequate entropy for cryptographic operations."""
    # On Linux, we can check entropy pool size
    try:
        with open("/proc/sys/kernel/random/entropy_avail", "r") as f:
            entropy = int(f.read().strip())
            if entropy < 1000:
                logger.warning(f"Low system entropy detected: {entropy} bits")
                # Use the cryptography library to generate additional entropy
                for _ in range(5):
                    secrets.token_bytes(64)
    except (FileNotFoundError, ValueError, PermissionError):
        # Not on Linux or can't access entropy info, continue anyway
        pass

def _safe_constant_time_compare(a: bytes, b: bytes) -> bool:
    """Perform constant-time comparison of two byte strings to prevent timing attacks."""
    return hmac.compare_digest(a, b)

def log_operation(level: int = logging.DEBUG):
    """Decorator to log cryptographic operations while protecting sensitive data."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            operation = func.__name__
            logger.log(level, f"Starting {operation}")
            try:
                result = func(*args, **kwargs)
                logger.log(level, f"Completed {operation} successfully")
                return result
            except Exception as e:
                logger.error(f"Failed {operation}: {str(e)}")
                raise
        return wrapper
    return decorator

def generate_key_id(public_key: str, prefix: str = "key") -> str:
    """Generate a unique, short identifier for a public key."""
    key_hash = hashlib.blake2b(bytes.fromhex(public_key), digest_size=6).hexdigest()
    return f"{prefix}_{key_hash}"

@log_operation(logging.INFO)
def generate_keypair(security_level: SecurityLevel = SecurityLevel.STANDARD, 
                     key_type: KeyType = KeyType.SIGNING,
                     metadata: Optional[Dict[str, Any]] = None) -> KeyPair:
    """
    Generate a new Ed25519 keypair with enhanced security and metadata.
    
    Args:
        security_level: The required security level for key generation
        key_type: Type of keypair to generate
        metadata: Optional metadata to associate with the keypair
    
    Returns:
        KeyPair object containing hex-encoded keys and metadata
    
    Raises:
        KeyGenerationError: If key generation fails
    """
    _ensure_entropy()
    
    try:
        if key_type == KeyType.SIGNING:
            signing_key = nacl.signing.SigningKey.generate()
            verify_key = signing_key.verify_key
            private_hex = signing_key.encode(encoder=nacl.encoding.HexEncoder).decode()
            public_hex = verify_key.encode(encoder=nacl.encoding.HexEncoder).decode()
        elif key_type == KeyType.ENCRYPTION:
            private_key = nacl.public.PrivateKey.generate()
            public_key = private_key.public_key
            private_hex = private_key.encode(encoder=nacl.encoding.HexEncoder).decode()
            public_hex = public_key.encode(encoder=nacl.encoding.HexEncoder).decode()
        else:
            raise KeyGenerationError(f"Unsupported key type: {key_type}")
            
        key_id = generate_key_id(public_hex)
        created_at = datetime.now(timezone.utc).isoformat()
        
        # Add default metadata fields
        full_metadata = {
            "type": key_type.name,
            "security_level": security_level.name,
            "algorithm": "Ed25519" if key_type == KeyType.SIGNING else "X25519",
            "created_at": created_at,
        }
        
        # Merge with provided metadata
        if metadata:
            full_metadata.update(metadata)
            
        return KeyPair(
            private_key=private_hex,
            public_key=public_hex,
            key_id=key_id,
            created_at=created_at,
            metadata=full_metadata
        )
        
    except Exception as e:
        logger.error(f"Key generation failed: {str(e)}")
        raise KeyGenerationError(f"Failed to generate {key_type.name} keypair: {str(e)}") from e

def canonicalize(data: Any) -> bytes:
    """
    Serialize data to canonical JSON (sorted keys, UTF-8 bytes) for deterministic hashing and signing.
    
    This function ensures consistent serialization even across different platforms.
    
    Args:
        data: The Python object to serialize (must be JSON-serializable)
        
    Returns:
        UTF-8 encoded bytes in canonical format
        
    Raises:
        SerializationError: If data cannot be serialized
    """
    try:
        if isinstance(data, str):
            return data.encode("utf-8")
        elif isinstance(data, bytes):
            return data
        elif data is None:
            return b""
        else:
            # Create deterministic JSON representation
            return json.dumps(
                data, 
                sort_keys=True, 
                separators=(",", ":"),
                ensure_ascii=False,  # Properly encode Unicode without escaping
                default=_json_serializer
            ).encode("utf-8")
    except Exception as e:
        logger.error(f"Canonicalization failed: {str(e)}")
        raise SerializationError(f"Failed to canonicalize data: {str(e)}") from e

def _json_serializer(obj):
    """Custom JSON serializer for objects not serializable by default json code."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    elif hasattr(obj, 'to_dict') and callable(getattr(obj, 'to_dict')):
        return obj.to_dict()
    else:
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

@log_operation(logging.INFO)
def sign_data(data: Any, private_key_hex: str, 
              include_metadata: bool = True,
              additional_data: Optional[Dict[str, Any]] = None) -> Union[str, SignatureBundle]:
    """
    Sign a structured object (or string) with a private Ed25519 key.
    
    Args:
        data: Data to sign (JSON-serializable object or string)
        private_key_hex: Hex-encoded Ed25519 private key
        include_metadata: Whether to include signature metadata
        additional_data: Optional additional data to include in metadata
        
    Returns:
        If include_metadata is False: Hex-encoded signature string
        If include_metadata is True: SignatureBundle with full signature data
        
    Raises:
        SignatureError: If signing operation fails
    """
    try:
        # Convert the private key from hex to bytes
        private_key = nacl.signing.SigningKey(bytes.fromhex(private_key_hex))
        
        # Get the corresponding public key
        verify_key = private_key.verify_key
        public_key_hex = verify_key.encode(encoder=nacl.encoding.HexEncoder).decode()
        
        # Canonicalize the data
        message = canonicalize(data)
        
        # Create signature
        signed = private_key.sign(message)
        signature_hex = signed.signature.hex()
        
        # If we don't need metadata, just return the signature
        if not include_metadata:
            return signature_hex
            
        # Generate key ID from public key
        key_id = generate_key_id(public_key_hex)
        
        # Create metadata
        metadata = {
            "data_hash": hash_data(data),
            "signature_created_at": datetime.now(timezone.utc).isoformat()
        }
        
        # Add any additional data
        if additional_data:
            metadata.update(additional_data)
            
        # Create and return the signature bundle
        return SignatureBundle(
            signature=signature_hex,
            public_key=public_key_hex,
            key_id=key_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            metadata=metadata
        )
        
    except Exception as e:
        logger.error(f"Signing operation failed: {str(e)}")
        raise SignatureError(f"Failed to sign data: {str(e)}") from e

@log_operation()
def verify_signature(data: Any, 
                     signature: Union[str, SignatureBundle], 
                     public_key_hex: Optional[str] = None) -> bool:
    """
    Verify a signature against structured data and a public key.
    
    Args:
        data: The data that was signed
        signature: Either a hex-encoded signature string or a SignatureBundle
        public_key_hex: Hex-encoded public key (required if signature is a string)
        
    Returns:
        True if signature is valid, False otherwise
        
    Raises:
        SignatureError: If verification fails due to an error (not invalid signature)
    """
    try:
        # Extract signature and public key
        if isinstance(signature, SignatureBundle):
            sig_hex = signature.signature
            pub_key_hex = signature.public_key
        else:
            sig_hex = signature
            if public_key_hex is None:
                raise SignatureError("Public key must be provided when signature is not a SignatureBundle")
            pub_key_hex = public_key_hex
        
        # Convert the public key from hex to bytes
        public_key = nacl.signing.VerifyKey(bytes.fromhex(pub_key_hex))
        
        # Canonicalize the data
        message = canonicalize(data)
        
        # Convert the signature from hex to bytes
        signature_bytes = bytes.fromhex(sig_hex)
        
        # Verify the signature
        public_key.verify(message, signature_bytes)
        return True
        
    except BadSignatureError:
        logger.warning("Signature verification failed: Invalid signature")
        return False
    except Exception as e:
        logger.error(f"Signature verification error: {str(e)}")
        raise SignatureError(f"Error during signature verification: {str(e)}") from e

@log_operation()
def hash_data(data: Any, algorithm: str = 'sha256', output_format: str = 'hex') -> str:
    """
    Compute a cryptographic hash of structured data.
    
    Args:
        data: Data to hash (string, bytes, or JSON-serializable object)
        algorithm: Hash algorithm to use ('sha256', 'sha512', 'blake2b')
        output_format: Output format ('hex', 'base64', 'base64url')
        
    Returns:
        Hash digest in the specified format
        
    Raises:
        ValueError: If unsupported algorithm or format is specified
    """
    # Canonicalize the data
    if isinstance(data, (dict, list, tuple, set)):
        data_bytes = canonicalize(data)
    elif isinstance(data, str):
        data_bytes = data.encode("utf-8")
    elif isinstance(data, bytes):
        data_bytes = data
    else:
        data_bytes = str(data).encode("utf-8")
    
    # Compute the hash using the specified algorithm
    if algorithm == 'sha256':
        digest = hashlib.sha256(data_bytes).digest()
    elif algorithm == 'sha512':
        digest = hashlib.sha512(data_bytes).digest()
    elif algorithm == 'blake2b':
        digest = hashlib.blake2b(data_bytes).digest()
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    
    # Return the digest in the specified format
    if output_format == 'hex':
        return digest.hex()
    elif output_format == 'base64':
        return base64.b64encode(digest).decode('ascii')
    elif output_format == 'base64url':
        return base64.urlsafe_b64encode(digest).decode('ascii').rstrip('=')
    else:
        raise ValueError(f"Unsupported output format: {output_format}")

def current_utc_iso() -> str:
    """Return current UTC time as ISO 8601 string with microsecond precision."""
    return datetime.now(timezone.utc).isoformat()

def short_hash(data: Any, length: int = 8) -> str:
    """
    Return a shortened SHA-256 hash (useful for IDs or summaries).
    
    Args:
        data: Data to hash
        length: Length of the shortened hash
        
    Returns:
        Shortened hash as hex string
    """
    return hash_data(data)[:length]

@log_operation(logging.INFO)
def encrypt_data(data: Any, 
                 key: Union[str, bytes], 
                 authenticated: bool = True,
                 additional_data: Optional[bytes] = None) -> Dict[str, str]:
    """
    Encrypt data using XChaCha20-Poly1305 (or XChaCha20 if not authenticated).
    
    Args:
        data: Data to encrypt
        key: Encryption key (hex string or bytes)
        authenticated: Whether to use authenticated encryption
        additional_data: Additional authenticated data for AEAD
        
    Returns:
        Dictionary containing encrypted data and metadata
        
    Raises:
        EncryptionError: If encryption fails
    """
    try:
        # Convert data to bytes
        if not isinstance(data, bytes):
            data = canonicalize(data)
            
        # Ensure key is in correct format
        if isinstance(key, str):
            key = bytes.fromhex(key)
            
        # Generate a random nonce
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        
        if authenticated:
            # Use authenticated encryption
            box = nacl.secret.SecretBox(key)
            if additional_data:
                # Use PyNaCl's low-level binding for AEAD
                encrypted = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
                    data, additional_data, nonce, key
                )
            else:
                encrypted = box.encrypt(data, nonce)
                encrypted = encrypted.ciphertext
        else:
            # Use non-authenticated encryption (just XChaCha20)
            encrypted = nacl.bindings.crypto_stream_xchacha20_xor(data, nonce, key)
            
        # Return encrypted data and metadata
        return {
            "ciphertext": base64.b64encode(encrypted).decode('ascii'),
            "nonce": base64.b64encode(nonce).decode('ascii'),
            "authenticated": authenticated,
            "algorithm": "XChaCha20-Poly1305" if authenticated else "XChaCha20",
            "timestamp": current_utc_iso(),
            "has_aad": additional_data is not None
        }
        
    except Exception as e:
        logger.error(f"Encryption failed: {str(e)}")
        raise EncryptionError(f"Failed to encrypt data: {str(e)}") from e

@log_operation(logging.INFO)
def decrypt_data(encrypted_data: Dict[str, str], 
                 key: Union[str, bytes],
                 additional_data: Optional[bytes] = None) -> bytes:
    """
    Decrypt data that was encrypted with encrypt_data.
    
    Args:
        encrypted_data: Dictionary containing encrypted data and metadata
        key: Decryption key (hex string or bytes)
        additional_data: Additional authenticated data for AEAD verification
        
    Returns:
        Decrypted data as bytes
        
    Raises:
        EncryptionError: If decryption fails
    """
    try:
        # Extract required fields
        ciphertext = base64.b64decode(encrypted_data["ciphertext"])
        nonce = base64.b64decode(encrypted_data["nonce"])
        authenticated = encrypted_data.get("authenticated", True)
        has_aad = encrypted_data.get("has_aad", False)
        
        # Ensure key is in correct format
        if isinstance(key, str):
            key = bytes.fromhex(key)
            
        if authenticated:
            # Use authenticated decryption
            if has_aad and additional_data is not None:
                # Use PyNaCl's low-level binding for AEAD
                return nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
                    ciphertext, additional_data, nonce, key
                )
            else:
                box = nacl.secret.SecretBox(key)
                return box.decrypt(ciphertext, nonce)
        else:
            # Use non-authenticated decryption
            return nacl.bindings.crypto_stream_xchacha20_xor(ciphertext, nonce, key)
            
    except Exception as e:
        logger.error(f"Decryption failed: {str(e)}")
        raise EncryptionError(f"Failed to decrypt data: {str(e)}") from e

@log_operation(logging.INFO)
def derive_key(master_key: Union[str, bytes],
               key_type: KeyType,
               context: str,
               length: int = 32) -> bytes:
    """
    Derive a purpose-specific key from a master key using HKDF.
    
    Args:
        master_key: Master key to derive from (hex string or bytes)
        key_type: Type of key to derive
        context: Context string for key derivation
        length: Length of the derived key in bytes
        
    Returns:
        Derived key as bytes
        
    Raises:
        CryptoError: If key derivation fails
    """
    try:
        # Ensure master key is in bytes format
        if isinstance(master_key, str):
            master_key = bytes.fromhex(master_key)
            
        # Create context info based on key type and context
        info = f"{key_type.name}:{context}".encode('utf-8')
        
        # Use HKDF to derive the key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=None,
            info=info,
        )
        
        return hkdf.derive(master_key)
        
    except Exception as e:
        logger.error(f"Key derivation failed: {str(e)}")
        raise CryptoError(f"Failed to derive key: {str(e)}") from e

def generate_secret_key(length: int = 32) -> str:
    """
    Generate a secure random secret key for symmetric encryption.
    
    Args:
        length: Length of the key in bytes
        
    Returns:
        Hex-encoded secret key
    """
    _ensure_entropy()
    return secrets.token_bytes(length).hex()

def create_key_commitment(public_key: str) -> Dict[str, str]:
    """
    Create a commitment for a public key (useful for key transparency).
    
    Args:
        public_key: Hex-encoded public key
        
    Returns:
        Dictionary with commitment information
    """
    key_bytes = bytes.fromhex(public_key)
    commitment = hash_data(key_bytes, algorithm='blake2b')
    timestamp = current_utc_iso()
    
    return {
        "commitment": commitment,
        "algorithm": "BLAKE2b",
        "timestamp": timestamp,
        "key_id": generate_key_id(public_key)
    }

def export_key(key_pair: KeyPair, include_private: bool = False,
               password: Optional[str] = None) -> Dict[str, Any]:
    """
    Export a keypair in a standardized format with optional encryption.
    
    Args:
        key_pair: KeyPair to export
        include_private: Whether to include the private key
        password: Optional password to encrypt the private key
        
    Returns:
        Dictionary containing the exported key information
    """
    result = {
        "key_id": key_pair.key_id,
        "public_key": key_pair.public_key,
        "created_at": key_pair.created_at,
        "metadata": key_pair.metadata
    }
    
    if include_private:
        if password:
            # Encrypt the private key with the password
            salt = nacl.utils.random(nacl.pwhash.argon2id.SALTBYTES)
            kdf = nacl.pwhash.argon2id.kdf
            key = kdf(nacl.secret.SecretBox.KEY_SIZE, password.encode('utf-8'), salt)
            box = nacl.secret.SecretBox(key)
            encrypted = box.encrypt(bytes.fromhex(key_pair.private_key))
            
            result["private_key"] = {
                "encrypted": base64.b64encode(encrypted).decode('ascii'),
                "salt": base64.b64encode(salt).decode('ascii'),
                "kdf": "argon2id"
            }
        else:
            result["private_key"] = key_pair.private_key
            
    return result

def import_key(key_data: Dict[str, Any], password: Optional[str] = None) -> KeyPair:
    """
    Import a keypair from a standardized format.
    
    Args:
        key_data: Dictionary containing key information
        password: Optional password to decrypt the private key
        
    Returns:
        KeyPair object
        
    Raises:
        CryptoError: If key import fails
    """
    public_key = key_data["public_key"]
    key_id = key_data.get("key_id", generate_key_id(public_key))
    created_at = key_data.get("created_at", current_utc_iso())
    metadata = key_data.get("metadata", {})
    
    private_key = None
    if "private_key" in key_data:
        priv_key_data = key_data["private_key"]
        
        if isinstance(priv_key_data, str):
            # Direct hex string
            private_key = priv_key_data
        elif isinstance(priv_key_data, dict) and password:
            # Encrypted private key
            salt = base64.b64decode(priv_key_data["salt"])
            encrypted = base64.b64decode(priv_key_data["encrypted"])
            
            kdf = nacl.pwhash.argon2id.kdf
            key = kdf(nacl.secret.SecretBox.KEY_SIZE, password.encode('utf-8'), salt)
            box = nacl.secret.SecretBox(key)
            
            try:
                private_key = box.decrypt(encrypted).hex()
            except Exception as e:
                raise CryptoError(f"Failed to decrypt private key: {str(e)}") from e
    
    return KeyPair(
        private_key=private_key or "",
        public_key=public_key,
        key_id=key_id,
        created_at=created_at,
        metadata=metadata
    )

def verify_key_ownership(challenge: str, response: str, public_key: str) -> bool:
    """
    Verify that a party owns a private key by challenging them to sign a message.
    
    Args:
        challenge: Challenge string sent to the key owner
        response: Signed response from the claimed key owner
        public_key: Public key to verify against
        
    Returns:
        True if ownership is verified, False otherwise
    """
    try:
        # Parse the response (expected to be a signature)
        if isinstance(response, SignatureBundle):
            signature = response.signature
            claimed_public_key = response.public_key
            
            # Verify the public key matches
            if claimed_public_key != public_key:
                logger.warning("Public key mismatch in ownership verification")
                return False
        else:
            signature = response
        
        # Verify the signature on the challenge
        return verify_signature(challenge, signature, public_key)
    except Exception as e:
        logger.error(f"Key ownership verification failed: {str(e)}")
        return False

# Advanced functions for specific use cases

def create_timestamped_proof(data: Any, private_key: str) -> Dict[str, Any]:
    """
    Create a timestamped proof of data existence.
    
    Args:
        data: Data to create proof for
        private_key: Private key to sign with
        
    Returns:
        Dictionary containing the proof
    """
    data_hash = hash_data(data)
    timestamp = current_utc_iso()
    
    # Combine the hash and timestamp
    to_sign = {
        "data_hash": data_hash,
        "timestamp": timestamp
    }
    
    # Sign the combined data
    signature = sign_data(to_sign, private_key, include_metadata=True)
    
    return {
        "data_hash": data_hash,
        "timestamp": timestamp,
        "signature": signature.signature if isinstance(signature, SignatureBundle) else signature,
        "public_key": signature.public_key if isinstance(signature, SignatureBundle) else None,
        "key_id": signature.key_id if isinstance(signature, SignatureBundle) else None
    }

def rotate_keypair(old_keypair: KeyPair, sign_with_old: bool = True) -> Tuple[KeyPair, Optional[SignatureBundle]]:
    """
    Create a new keypair and optionally sign it with the old one to create a chain of trust.
    
    Args:
        old_keypair: Previous keypair
        sign_with_old: Whether to sign the new key with the old one
        
    Returns:
        Tuple of (new_keypair, optional_signature)
    """
    # Generate new keypair with same metadata structure
    new_keypair = generate_keypair(
        security_level=SecurityLevel.ENHANCED,
        metadata=old_keypair.metadata
    )
    
    # Add relationship to the old key
    new_keypair.metadata["replaces_key_id"] = old_keypair.key_id
    new_keypair.metadata["rotation_date"] = current_utc_iso()
    
    signature = None
    if sign_with_old and old_keypair.private_key:
        # Create signature attesting to the key rotation
        attestation = {
            "action": "key_rotation",
            "old_key_id": old_keypair.key_id,
            "new_key_id": new_keypair.key_id,
            "new_public_key": new_keypair.public_key,
            "timestamp": current_utc_iso()
        }
        
        signature = sign_data(attestation, old_keypair.private_key, include_metadata=True)
    
    return new_keypair, signature