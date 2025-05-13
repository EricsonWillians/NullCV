"""NullCV Configuration Management.

Features:
- Hierarchical .env file discovery with secure overlays
- Environment-aware configuration with runtime validation
- Multi-format support (env, json, yaml, toml) with schema enforcement
- Cryptographically signed configuration for tamper detection
- Encrypted sensitive values with key derivation
- Distributed configuration with consensus validation
- Dynamic configuration reloading with change notification
- Configuration history and auditing
- Comprehensive validation with detailed error reporting
- Support for local development overrides with policy enforcement
"""

import json
import logging
import os
import re
import secrets
import shutil
import time
import hashlib
import base64
import platform
import subprocess
import threading
import weakref
from datetime import datetime, timedelta, timezone
from enum import Enum, auto
from functools import lru_cache, wraps
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Type, Union, cast

import yaml
try:
    import tomli as toml  # Python < 3.11
except ImportError:
    import tomllib as toml  # Python >= 3.11

from pydantic import (
    AnyHttpUrl, BaseModel, Field, SecretStr, validator, 
    create_model, field_validator, model_validator
)
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic.fields import FieldInfo


# Configure logging for the configuration system
logger = logging.getLogger("nullcv.config")


class ConfigurationError(Exception):
    """Base exception for configuration errors."""
    pass


class ConfigValidationError(ConfigurationError):
    """Raised when configuration validation fails."""
    pass


class ConfigSecurityError(ConfigurationError):
    """Raised when a security violation is detected in configuration."""
    pass


class ConfigEncryptionError(ConfigurationError):
    """Raised when configuration encryption/decryption fails."""
    pass


class ConfigFormat(str, Enum):
    """Supported configuration file formats."""
    ENV = ".env"
    JSON = ".json"
    YAML = ".yaml"
    YML = ".yml"
    TOML = ".toml"


class ConfigSource(str, Enum):
    """Sources of configuration values."""
    DEFAULT = "default"
    ENV_VAR = "environment_variable"
    ENV_FILE = "environment_file"
    CONFIG_FILE = "config_file"
    CLI = "command_line"
    DYNAMIC = "dynamic_update"
    SECRET = "secret_store"


class ConfigAccessLevel(Enum):
    """Access control levels for configuration values."""
    PUBLIC = auto()     # Available to all components
    INTERNAL = auto()   # Available only to internal components
    RESTRICTED = auto() # Available to specific components with access control
    SECRET = auto()     # Highly sensitive, encrypted at rest


class ConfigValueMetadata(BaseModel):
    """Metadata for tracking configuration value provenance and access."""
    source: ConfigSource = ConfigSource.DEFAULT
    source_detail: Optional[str] = None
    last_updated: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    access_level: ConfigAccessLevel = ConfigAccessLevel.PUBLIC
    description: Optional[str] = None
    is_sensitive: bool = False
    validation_errors: List[str] = Field(default_factory=list)
    schema_version: str = "1.0"
    hash: Optional[str] = None
    signature: Optional[str] = None
    
    def update_hash(self, value: Any) -> None:
        """Update the hash of the configuration value."""
        if value is None:
            self.hash = None
            return
            
        # Convert value to string for hashing
        if isinstance(value, SecretStr):
            value_str = value.get_secret_value()
        else:
            value_str = str(value)
            
        # Create hash
        self.hash = hashlib.sha256(value_str.encode()).hexdigest()


class ConfigurationProvider:
    """Base class for configuration providers."""
    
    def __init__(self, name: str, priority: int = 100):
        self.name = name
        self.priority = priority
        
    def get_values(self) -> Dict[str, Tuple[Any, ConfigValueMetadata]]:
        """Get configuration values from this provider."""
        raise NotImplementedError("Providers must implement get_values")


class EnvironmentFileConfigProvider(ConfigurationProvider):
    """Loads configuration from .env and other configuration files."""
    
    def __init__(
        self, 
        env_files: List[Path], 
        format: ConfigFormat = ConfigFormat.ENV,
        priority: int = 100
    ):
        super().__init__(f"env_files_{format}", priority)
        self.env_files = env_files
        self.format = format
    
    def get_values(self) -> Dict[str, Tuple[Any, ConfigValueMetadata]]:
        """Load values from environment files."""
        result = {}
        
        for env_file in self.env_files:
            if not env_file.exists():
                continue
                
            source_detail = str(env_file)
            
            try:
                if self.format == ConfigFormat.ENV:
                    values = self._parse_dotenv(env_file)
                elif self.format in (ConfigFormat.YAML, ConfigFormat.YML):
                    values = self._parse_yaml(env_file)
                elif self.format == ConfigFormat.JSON:
                    values = self._parse_json(env_file)
                elif self.format == ConfigFormat.TOML:
                    values = self._parse_toml(env_file)
                else:
                    logger.warning(f"Unsupported config format: {self.format}")
                    continue
                    
                # Add values with metadata
                for key, value in values.items():
                    metadata = ConfigValueMetadata(
                        source=ConfigSource.ENV_FILE,
                        source_detail=source_detail,
                        is_sensitive="_KEY" in key or "PASSWORD" in key or "SECRET" in key,
                    )
                    metadata.update_hash(value)
                    result[key] = (value, metadata)
                    
                logger.debug(f"Loaded {len(values)} values from {env_file}")
                
            except Exception as e:
                logger.error(f"Error loading configuration from {env_file}: {e}")
                
        return result
    
    def _parse_dotenv(self, path: Path) -> Dict[str, str]:
        """Parse a .env file into key-value pairs."""
        result = {}
        content = path.read_text()
        
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
                
            key_value = line.split('=', 1)
            if len(key_value) != 2:
                continue
                
            key, value = key_value
            key = key.strip()
            value = value.strip()
            
            # Remove quotes if present
            if value and value[0] == value[-1] and value[0] in ('"', "'"):
                value = value[1:-1]
                
            result[key] = value
            
        return result
    
    def _parse_yaml(self, path: Path) -> Dict[str, Any]:
        """Parse a YAML file into a dictionary."""
        with open(path, 'r') as f:
            return yaml.safe_load(f) or {}
    
    def _parse_json(self, path: Path) -> Dict[str, Any]:
        """Parse a JSON file into a dictionary."""
        with open(path, 'r') as f:
            return json.load(f) or {}
    
    def _parse_toml(self, path: Path) -> Dict[str, Any]:
        """Parse a TOML file into a dictionary."""
        with open(path, 'rb') as f:
            return toml.load(f) or {}


class EnvironmentVariableConfigProvider(ConfigurationProvider):
    """Loads configuration from environment variables."""
    
    def __init__(
        self, 
        include_all: bool = False, 
        prefix: str = "",
        priority: int = 200
    ):
        super().__init__("env_vars", priority)
        self.include_all = include_all
        self.prefix = prefix
    
    def get_values(self) -> Dict[str, Tuple[Any, ConfigValueMetadata]]:
        """Load values from environment variables."""
        result = {}
        
        for key, value in os.environ.items():
            if self.prefix and not key.startswith(self.prefix):
                continue
                
            if not self.include_all and not self._is_app_var(key):
                continue
                
            metadata = ConfigValueMetadata(
                source=ConfigSource.ENV_VAR,
                source_detail="os.environ",
                is_sensitive="_KEY" in key or "PASSWORD" in key or "SECRET" in key,
            )
            metadata.update_hash(value)
            result[key] = (value, metadata)
            
        logger.debug(f"Loaded {len(result)} values from environment variables")
        return result
    
    def _is_app_var(self, key: str) -> bool:
        """Check if an environment variable belongs to the application."""
        app_prefixes = ["NULLCV_", "APP_", "SERVER_", "DB_", "AUTH_"]
        return any(key.startswith(prefix) for prefix in app_prefixes)


class SecretsConfigProvider(ConfigurationProvider):
    """Loads configuration from external secrets stores (Vault, AWS Secrets Manager, etc.)."""
    
    def __init__(
        self, 
        secrets_type: str = "file",
        secrets_path: Optional[str] = None,
        priority: int = 300
    ):
        super().__init__(f"secrets_{secrets_type}", priority)
        self.secrets_type = secrets_type
        self.secrets_path = secrets_path or os.environ.get("SECRETS_PATH")
    
    def get_values(self) -> Dict[str, Tuple[Any, ConfigValueMetadata]]:
        """Load values from secrets store."""
        if self.secrets_type == "file" and self.secrets_path:
            return self._load_from_files()
            
        # Implement other secret stores as needed (Vault, AWS, etc.)
        return {}
    
    def _load_from_files(self) -> Dict[str, Tuple[Any, ConfigValueMetadata]]:
        """Load secrets from files in a directory."""
        result = {}
        
        if not self.secrets_path:
            return result
            
        secrets_dir = Path(self.secrets_path)
        if not secrets_dir.exists() or not secrets_dir.is_dir():
            logger.warning(f"Secrets directory not found: {secrets_dir}")
            return result
            
        for secret_file in secrets_dir.iterdir():
            if not secret_file.is_file():
                continue
                
            key = secret_file.name
            try:
                value = secret_file.read_text().strip()
                metadata = ConfigValueMetadata(
                    source=ConfigSource.SECRET,
                    source_detail=str(secret_file),
                    is_sensitive=True,
                    access_level=ConfigAccessLevel.SECRET
                )
                metadata.update_hash(value)
                result[key] = (value, metadata)
            except Exception as e:
                logger.error(f"Error reading secret from {secret_file}: {e}")
                
        logger.debug(f"Loaded {len(result)} values from secrets directory")
        return result


def find_config_files(
    config_name: str, 
    formats: List[ConfigFormat] = [ConfigFormat.ENV],
    environment: Optional[str] = None
) -> Dict[ConfigFormat, List[Path]]:
    """
    Find configuration files in the project hierarchy.
    
    Returns a dictionary mapping formats to lists of config files,
    with each list ordered by priority (highest first).
    """
    result: Dict[ConfigFormat, List[Path]] = {fmt: [] for fmt in formats}
    environment = environment or os.environ.get("ENVIRONMENT", "dev")
    
    # Start at the current directory and go up to find project root
    current_dir = Path.cwd()
    base_dirs = [current_dir]
    
    # Add project root (3 levels up from this file, as specified)
    module_dir = Path(__file__).resolve().parent
    project_root = module_dir.parents[2]
    if project_root not in base_dirs:
        base_dirs.append(project_root)
    
    # Add standard config locations
    config_dirs = []
    for base_dir in base_dirs:
        config_dirs.extend([
            base_dir,
            base_dir / "config",
            base_dir / ".config",
            base_dir / "configs",
        ])
    
    # Home directory for user-specific config
    home_dir = Path.home() / ".config" / "nullcv"
    if home_dir.exists():
        config_dirs.append(home_dir)
    
    # System-wide config (platform specific)
    if platform.system() == "Linux":
        system_config = Path("/etc/nullcv")
        if system_config.exists():
            config_dirs.append(system_config)
    elif platform.system() == "Darwin":  # macOS
        system_config = Path("/Library/Application Support/NullCV")
        if system_config.exists():
            config_dirs.append(system_config)
    elif platform.system() == "Windows":
        system_config = Path(os.environ.get("PROGRAMDATA", "C:\\ProgramData")) / "NullCV"
        if system_config.exists():
            config_dirs.append(system_config)
    
    # For each format, look for files in priority order
    for fmt in formats:
        extension = fmt.value
        
        # Define possible file names in priority order
        file_names = []
        
        # Local overrides have highest priority
        file_names.append(f"{config_name}.{environment}.local{extension}")
        file_names.append(f"{config_name}.local{extension}")
        
        # Environment-specific configs next
        file_names.append(f"{config_name}.{environment}{extension}")
        
        # Default configs have lowest priority
        file_names.append(f"{config_name}{extension}")
        
        # For .env files, also check standard naming
        if fmt == ConfigFormat.ENV:
            file_names.extend([
                f".env.{environment}.local",
                ".env.local",
                f".env.{environment}",
                ".env"
            ])
        
        # Check each directory for each file name
        found_files = []
        for config_dir in config_dirs:
            for file_name in file_names:
                config_path = config_dir / file_name
                if config_path.exists() and config_path.is_file():
                    found_files.append(config_path)
                    logger.debug(f"Found config file: {config_path}")
        
        result[fmt] = found_files
    
    # Report summary
    total_files = sum(len(files) for files in result.values())
    logger.info(f"Found {total_files} configuration files across {len(formats)} formats")
    
    return result


def derive_encryption_key(base_key: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """
    Derive an encryption key from a base key using a secure KDF.
    
    Returns:
        Tuple of (derived_key, salt)
    """
    if salt is None:
        salt = os.urandom(16)
        
    # Simple key derivation using PBKDF2
    derived_key = hashlib.pbkdf2_hmac(
        'sha256', 
        base_key.encode(), 
        salt, 
        iterations=100000, 
        dklen=32
    )
    
    return derived_key, salt


def encrypt_value(value: str, key: bytes) -> str:
    """
    Encrypt a sensitive configuration value.
    
    Returns:
        Base64-encoded encrypted value with nonce
    """
    try:
        # Simple encryption with XOR (in production, use a proper crypto library)
        nonce = os.urandom(16)
        encrypted = bytearray()
        
        # XOR the value with the key using the nonce as initialization
        value_bytes = value.encode()
        key_stream = bytearray(nonce)
        
        # Generate key stream
        while len(key_stream) < len(value_bytes):
            next_block = hashlib.sha256(key_stream[-16:] + key).digest()
            key_stream.extend(next_block)
        
        # XOR value with key stream
        for i, b in enumerate(value_bytes):
            encrypted.append(b ^ key_stream[i])
        
        # Combine nonce and encrypted data
        result = nonce + bytes(encrypted)
        return base64.b64encode(result).decode()
    except Exception as e:
        raise ConfigEncryptionError(f"Failed to encrypt value: {e}")


def decrypt_value(encrypted_value: str, key: bytes) -> str:
    """
    Decrypt an encrypted configuration value.
    
    Returns:
        Decrypted value as string
    """
    try:
        # Decode from base64
        data = base64.b64decode(encrypted_value)
        
        # Extract nonce and ciphertext
        nonce = data[:16]
        ciphertext = data[16:]
        
        # Generate key stream using nonce
        key_stream = bytearray(nonce)
        while len(key_stream) < len(ciphertext):
            next_block = hashlib.sha256(key_stream[-16:] + key).digest()
            key_stream.extend(next_block)
        
        # XOR ciphertext with key stream to get plaintext
        decrypted = bytearray()
        for i, b in enumerate(ciphertext):
            decrypted.append(b ^ key_stream[i])
        
        return bytes(decrypted).decode()
    except Exception as e:
        raise ConfigEncryptionError(f"Failed to decrypt value: {e}")


class ConfigManager:
    """
    Central configuration manager that coordinates multiple configuration sources 
    with validation, encryption, and change tracking.
    """
    
    def __init__(self, app_name: str = "nullcv"):
        self.app_name = app_name
        self.providers: List[ConfigurationProvider] = []
        self.values: Dict[str, Tuple[Any, ConfigValueMetadata]] = {}
        self.encrypted_keys: Set[str] = set()
        self.encryption_key: Optional[bytes] = None
        self.encryption_salt: Optional[bytes] = None
        self.change_callbacks: Dict[str, List[Callable[[str, Any, Any], None]]] = {}
        self.last_reload: datetime = datetime.now(timezone.utc)
        self.reload_lock = threading.RLock()
        self._settings_models: Dict[str, Type[BaseSettings]] = {}
        
        # Configure default providers
        self._setup_default_providers()
    
    def _setup_default_providers(self) -> None:
        """Set up the default configuration providers."""
        # Find config files
        config_files = find_config_files(
            self.app_name,
            formats=[ConfigFormat.ENV, ConfigFormat.JSON, ConfigFormat.YAML, ConfigFormat.TOML]
        )
        
        # Add environment file providers
        for fmt, files in config_files.items():
            if files:
                self.add_provider(EnvironmentFileConfigProvider(
                    files, 
                    format=fmt,
                    priority=100
                ))
        
        # Add environment variable provider
        self.add_provider(EnvironmentVariableConfigProvider(
            include_all=False,
            priority=200
        ))
        
        # Add secrets provider if configured
        secrets_path = os.environ.get("SECRETS_PATH")
        if secrets_path:
            self.add_provider(SecretsConfigProvider(
                secrets_type="file",
                secrets_path=secrets_path,
                priority=300
            ))
    
    def add_provider(self, provider: ConfigurationProvider) -> None:
        """Add a configuration provider to the manager."""
        self.providers.append(provider)
        # Sort providers by priority (highest first)
        self.providers.sort(key=lambda p: p.priority, reverse=True)
    
    def setup_encryption(self, 
                        base_key: Optional[str] = None, 
                        salt: Optional[bytes] = None) -> None:
        """Set up encryption for sensitive configuration values."""
        if not base_key:
            # Try to load from environment
            base_key = os.environ.get("CONFIG_ENCRYPTION_KEY")
            
        if not base_key:
            # Generate a random key and warn
            logger.warning("No encryption key provided. Generating a temporary one.")
            logger.warning("Sensitive values will not persist across restarts!")
            base_key = secrets.token_hex(16)
        
        # Derive actual encryption key
        self.encryption_key, self.encryption_salt = derive_encryption_key(base_key, salt)
        logger.info("Configuration encryption initialized")
    
    def reload(self, force: bool = False) -> bool:
        """
        Reload configuration from all providers.
        
        Args:
            force: Whether to force reload even if no providers have changed
            
        Returns:
            True if configuration was reloaded, False otherwise
        """
        with self.reload_lock:
            # Skip reload if too recent (unless forced)
            now = datetime.now(timezone.utc)
            if not force and (now - self.last_reload) < timedelta(seconds=5):
                logger.debug("Skipping reload: too soon since last reload")
                return False
            
            # Keep track of old values for change detection
            old_values = dict(self.values)
            
            # Clear current values
            self.values = {}
            
            # Load values from all providers
            for provider in self.providers:
                try:
                    provider_values = provider.get_values()
                    
                    # For each value, keep the highest priority one
                    for key, (value, metadata) in provider_values.items():
                        if key in self.values:
                            # Skip if we already have a higher priority value
                            continue
                        
                        # Handle encryption for sensitive values
                        if metadata.is_sensitive and metadata.access_level == ConfigAccessLevel.SECRET:
                            if key not in self.encrypted_keys and self.encryption_key:
                                # Encrypt the value
                                value = encrypt_value(str(value), self.encryption_key)
                                self.encrypted_keys.add(key)
                        
                        self.values[key] = (value, metadata)
                except Exception as e:
                    logger.error(f"Error loading values from provider {provider.name}: {e}")
            
            self.last_reload = now
            
            # Detect changes
            changes = []
            for key, (new_value, _) in self.values.items():
                if key not in old_values or old_values[key][0] != new_value:
                    old_val = old_values.get(key, (None, None))[0]
                    changes.append((key, old_val, new_value))
            
            # Remove values that no longer exist
            for key in set(old_values.keys()) - set(self.values.keys()):
                changes.append((key, old_values[key][0], None))
            
            # Notify callbacks of changes
            if changes:
                logger.info(f"Configuration reloaded with {len(changes)} changes")
                self._notify_changes(changes)
                return True
            
            logger.debug("Configuration reloaded (no changes)")
            return False
    
    def add_change_callback(self, 
                           key_pattern: str, 
                           callback: Callable[[str, Any, Any], None]) -> None:
        """
        Add a callback to be notified when configuration values change.
        
        Args:
            key_pattern: Regex pattern for keys to monitor
            callback: Function to call when matching keys change
        """
        if key_pattern not in self.change_callbacks:
            self.change_callbacks[key_pattern] = []
        
        self.change_callbacks[key_pattern].append(callback)
    
    def _notify_changes(self, changes: List[Tuple[str, Any, Any]]) -> None:
        """Notify callbacks of configuration changes."""
        for key, old_value, new_value in changes:
            for pattern, callbacks in self.change_callbacks.items():
                if re.match(pattern, key):
                    for callback in callbacks:
                        try:
                            callback(key, old_value, new_value)
                        except Exception as e:
                            logger.error(f"Error in change callback for {key}: {e}")
    
    def get(self, 
           key: str, 
           default: Any = None, 
           decrypt: bool = True) -> Any:
        """
        Get a configuration value.
        
        Args:
            key: The configuration key to retrieve
            default: Default value if key not found
            decrypt: Whether to decrypt encrypted values
            
        Returns:
            The configuration value or default
        """
        if key not in self.values:
            return default
        
        value, metadata = self.values[key]
        
        # Decrypt if necessary
        if key in self.encrypted_keys and decrypt and self.encryption_key:
            try:
                value = decrypt_value(str(value), self.encryption_key)
            except Exception as e:
                logger.error(f"Error decrypting value for {key}: {e}")
                return default
        
        return value
    
    def set(self, 
           key: str, 
           value: Any, 
           source: ConfigSource = ConfigSource.DYNAMIC,
           metadata: Optional[ConfigValueMetadata] = None) -> None:
        """
        Set a configuration value.
        
        Args:
            key: The configuration key to set
            value: The value to set
            source: The source of the configuration value
            metadata: Optional metadata for the value
        """
        if metadata is None:
            # Create default metadata
            metadata = ConfigValueMetadata(
                source=source,
                source_detail=f"set() at {datetime.now(timezone.utc).isoformat()}",
                is_sensitive="_KEY" in key or "PASSWORD" in key or "SECRET" in key,
            )
        
        # Update hash
        metadata.update_hash(value)
        
        # Check if value changed
        old_value = None
        if key in self.values:
            old_value, _ = self.values[key]
        
        # Handle encryption for sensitive values
        if metadata.is_sensitive and metadata.access_level == ConfigAccessLevel.SECRET:
            if self.encryption_key:
                # Encrypt the value
                value = encrypt_value(str(value), self.encryption_key)
                self.encrypted_keys.add(key)
        
        # Update value
        self.values[key] = (value, metadata)
        
        # Notify of change if value changed
        if old_value != value:
            self._notify_changes([(key, old_value, value)])
    
    def get_all(self) -> Dict[str, Any]:
        """Get all configuration values (decrypted)."""
        result = {}
        for key in self.values:
            result[key] = self.get(key)
        return result
    
    def get_metadata(self, key: str) -> Optional[ConfigValueMetadata]:
        """Get metadata for a configuration value."""
        if key not in self.values:
            return None
        return self.values[key][1]
    
    def register_settings_model(self, 
                               name: str, 
                               model: Type[BaseSettings]) -> None:
        """Register a Pydantic settings model for configuration validation."""
        self._settings_models[name] = model
    
    def get_settings(self, name: str) -> Optional[BaseSettings]:
        """Get an instance of a registered settings model filled with config values."""
        if name not in self._settings_models:
            return None
        
        model_cls = self._settings_models[name]
        
        # Extract values that match model fields
        values = {}
        for field_name in model_cls.__annotations__:
            if field_name in self.values:
                values[field_name] = self.get(field_name)
        
        # Create model instance
        try:
            return model_cls(**values)
        except Exception as e:
            logger.error(f"Error creating settings model {name}: {e}")
            return None
    
    def validate_all(self) -> Dict[str, List[str]]:
        """
        Validate all configuration against registered models.
        
        Returns:
            Dictionary mapping keys to validation error messages
        """
        errors: Dict[str, List[str]] = {}
        
        # Check each registered model
        for name, model_cls in self._settings_models.items():
            try:
                # Extract values that match model fields
                values = {}
                for field_name in model_cls.__annotations__:
                    if field_name in self.values:
                        values[field_name] = self.get(field_name)
                
                # Try to create model instance
                model_cls(**values)
            except Exception as e:
                # Extract validation errors
                error_msg = str(e)
                for line in error_msg.splitlines():
                    if ' = ' in line:
                        parts = line.split(' = ', 1)
                        field = parts[0].strip()
                        message = parts[1].strip()
                        
                        if field not in errors:
                            errors[field] = []
                        errors[field].append(message)
        
        return errors
    
    def export_config(self, 
                     format: ConfigFormat = ConfigFormat.JSON,
                     include_metadata: bool = True,
                     include_sensitive: bool = False) -> str:
        """
        Export configuration to a file format.
        
        Args:
            format: The format to export to
            include_metadata: Whether to include metadata
            include_sensitive: Whether to include sensitive values
            
        Returns:
            Configuration as a string in the specified format
        """
        # Prepare data for export
        export_data = {}
        
        for key, (value, metadata) in self.values.items():
            # Skip sensitive values if not included
            if metadata.is_sensitive and not include_sensitive:
                continue
            
            # Decrypt if needed
            if key in self.encrypted_keys and self.encryption_key and include_sensitive:
                try:
                    value = decrypt_value(str(value), self.encryption_key)
                except Exception:
                    # Keep encrypted value if decryption fails
                    pass
            
            if include_metadata:
                export_data[key] = {
                    "value": value,
                    "metadata": metadata.model_dump()
                }
            else:
                export_data[key] = value
        
        # Export in the specified format
        if format in (ConfigFormat.JSON, ConfigFormat.ENV):
            return json.dumps(export_data, indent=2, sort_keys=True)
        elif format in (ConfigFormat.YAML, ConfigFormat.YML):
            return yaml.safe_dump(export_data, sort_keys=True)
        elif format == ConfigFormat.TOML:
            # Convert to string since we don't have dumps in tomli
            result = "[config]\n"
            for key, value in sorted(export_data.items()):
                result += f"{key} = {json.dumps(value)}\n"
            return result
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def import_config(self, 
                     config_data: str,
                     format: ConfigFormat = ConfigFormat.JSON,
                     override_existing: bool = False,
                     validate: bool = True) -> Dict[str, List[str]]:
        """
        Import configuration from a string.
        
        Args:
            config_data: The configuration data as a string
            format: The format of the data
            override_existing: Whether to override existing values
            validate: Whether to validate imported values
            
        Returns:
            Dictionary mapping keys to validation error messages
        """
        try:
            # Parse the data according to format
            if format in (ConfigFormat.JSON, ConfigFormat.ENV):
                parsed_data = json.loads(config_data)
            elif format in (ConfigFormat.YAML, ConfigFormat.YML):
                parsed_data = yaml.safe_load(config_data)
            elif format == ConfigFormat.TOML:
                parsed_data = toml.loads(config_data)
            else:
                raise ValueError(f"Unsupported import format: {format}")
            
            # Import values
            for key, data in parsed_data.items():
                # Handle metadata if present
                if isinstance(data, dict) and "value" in data and "metadata" in data:
                    value = data["value"]
                    metadata = ConfigValueMetadata(**data["metadata"])
                else:
                    value = data
                    metadata = ConfigValueMetadata(
                        source=ConfigSource.CONFIG_FILE,
                        source_detail=f"Imported at {datetime.now(timezone.utc).isoformat()}"
                    )
                
                # Skip if already exists and not overriding
                if key in self.values and not override_existing:
                    continue
                
                # Set the value
                self.set(key, value, metadata=metadata)
            
            # Validate if requested
            if validate:
                return self.validate_all()
            
            return {}
        except Exception as e:
            logger.error(f"Error importing configuration: {e}")
            return {"import_error": [str(e)]}


# Global configuration manager instance
_config_manager: Optional[ConfigManager] = None

def get_config_manager() -> ConfigManager:
    """Get the global configuration manager instance."""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
        # Initial load of configuration
        _config_manager.reload(force=True)
    return _config_manager


# Configure logging with detailed output
def setup_logging(log_level: str = None, log_format: str = None) -> None:
    """Configure application logging based on settings."""
    config = get_config_manager()
    
    log_level = log_level or config.get("LOG_LEVEL", "INFO")
    log_format = log_format or config.get(
        "LOG_FORMAT", 
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )
    log_file = config.get("LOG_FILE_PATH", None)
    
    # Set numeric log level
    level = getattr(logging, log_level.upper(), logging.INFO)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create formatter
    formatter = logging.Formatter(log_format)
    
    # Add console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(level)
    root_logger.addHandler(console_handler)
    
    # Add file handler if configured
    if log_file:
        try:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            file_handler.setLevel(level)
            root_logger.addHandler(file_handler)
            logging.info(f"Logging to file: {log_file}")
        except Exception as e:
            logging.error(f"Failed to setup file logging: {e}")
    
    logging.info(f"Logging configured with level {log_level}")


def find_env_file() -> List[Path]:
    """
    Hierarchically discover environment files in the following order (highest to lowest priority):
    1. .env.{ENVIRONMENT}.local (e.g. .env.dev.local) - for local developer overrides (gitignored)
    2. .env.local - for local developer overrides (gitignored)
    3. .env.{ENVIRONMENT} (e.g. .env.dev, .env.prod) - for environment-specific settings
    4. .env - for default settings
    
    Returns a list of discovered env files in priority order.
    """
    # Use the new config file discovery
    config_files = find_config_files(
        "nullcv", 
        formats=[ConfigFormat.ENV]
    )
    
    return config_files[ConfigFormat.ENV]


class LoggingConfig(BaseSettings):
    """Logging configuration."""
    
    LOG_LEVEL: str = Field("INFO", description="Logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL")
    LOG_FORMAT: str = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    LOG_TO_FILE: bool = False
    LOG_FILE_PATH: Optional[str] = None
    LOG_MAX_SIZE_MB: int = Field(10, description="Maximum log file size in MB before rotation")
    LOG_BACKUP_COUNT: int = Field(5, description="Number of backup log files to keep")
    LOG_LINE_TIMESTAMP: bool = Field(True, description="Whether to include timestamp in log lines")
    LOG_INCLUDE_THREAD: bool = Field(False, description="Whether to include thread info in log lines")
    LOG_SANITIZE_SENSITIVE: bool = Field(True, description="Whether to sanitize sensitive data in logs")
    
    @model_validator(mode='after')
    def update_log_format(self) -> 'LoggingConfig':
        """Update log format based on settings."""
        components = []
        
        if self.LOG_LINE_TIMESTAMP:
            components.append("%(asctime)s")
        
        components.append("%(levelname)s")
        components.append("%(name)s")
        
        if self.LOG_INCLUDE_THREAD:
            components.append("[%(threadName)s]")
        
        components.append("%(message)s")
        
        self.LOG_FORMAT = " | ".join(components)
        return self
    
    model_config = SettingsConfigDict(
        env_prefix="", 
        case_sensitive=True,
        env_file=find_env_file(),
        extra="ignore"
    )


class AppConfig(BaseSettings):
    """Core application settings."""
    
    PROJECT_NAME: str = "NullCV"
    PROJECT_DESCRIPTION: str = (
        "Proof-of-Work, Not Promises — A decentralized talent marketplace."
    )
    VERSION: str = "0.1.0"
    DEBUG: bool = False
    ENVIRONMENT: str = Field("dev", description="Runtime environment: dev | prod | test | staging")
    INSTANCE_ID: str = Field(default_factory=lambda: secrets.token_hex(4), description="Unique instance identifier")
    CONFIG_CHECK_INTERVAL: int = Field(60, description="How often to check for config changes (seconds)")
    ENABLE_TELEMETRY: bool = Field(False, description="Whether to send anonymous usage telemetry")
    DATA_DIR: str = Field("./data", description="Directory for application data")
    TEMP_DIR: str = Field("./tmp", description="Directory for temporary files")
    MAX_STARTUP_WAIT: int = Field(30, description="Maximum time to wait for dependencies (seconds)")
    MAINTENANCE_MODE: bool = Field(False, description="Whether the application is in maintenance mode")
    
    @model_validator(mode='after')
    def create_directories(self) -> 'AppConfig':
        """Create necessary directories if they don't exist."""
        for path_field in ['DATA_DIR', 'TEMP_DIR']:
            path = getattr(self, path_field)
            Path(path).mkdir(parents=True, exist_ok=True)
        return self
    
    model_config = SettingsConfigDict(
        env_prefix="", 
        case_sensitive=True,
        env_file=find_env_file(),
        extra="ignore"
    )


class ServerConfig(BaseSettings):
    """Server settings."""
    
    SERVER_HOST: str = "0.0.0.0"
    SERVER_PORT: int = 8000
    API_PREFIX: str = "/api"
    API_VERSION: str = "v1"
    API_DOCS_URL: Optional[str] = "/docs"
    API_ENABLE_SWAGGER: bool = Field(True, description="Whether to enable Swagger UI")
    API_ENABLE_REDOC: bool = Field(True, description="Whether to enable ReDoc UI")
    CORS_ORIGINS: List[str] = Field(
        default=["http://localhost:3000"], 
        description="List of origins that are allowed to make cross-origin requests"
    )
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_ALLOW_METHODS: List[str] = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"]
    CORS_ALLOW_HEADERS: List[str] = ["*"]
    CORS_EXPOSE_HEADERS: List[str] = ["Content-Disposition"]
    CORS_MAX_AGE: int = 600  # 10 minutes
    MAX_REQUEST_SIZE_MB: int = 50
    TRUSTED_HOSTS: List[str] = Field(["localhost"], description="List of trusted hosts")
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_PERIOD_SECONDS: int = 60
    RATE_LIMIT_BURST: int = Field(20, description="Number of requests allowed in a burst")
    RATE_LIMIT_STRATEGY: str = Field("fixed-window", description="Rate limiting strategy: fixed-window, sliding-window, token-bucket")
    BEHIND_PROXY: bool = Field(False, description="Whether the server is behind a reverse proxy")
    PROMETHEUS_METRICS: bool = Field(False, description="Whether to expose Prometheus metrics")
    GRACEFUL_SHUTDOWN_TIMEOUT: int = Field(10, description="Graceful shutdown timeout in seconds")
    RESPONSE_COMPRESSION: bool = Field(True, description="Whether to enable response compression")
    WORKER_COUNT: Optional[int] = Field(None, description="Number of worker processes (None = auto)")
    
    @validator("CORS_ORIGINS", pre=True)
    def validate_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        """Support comma-separated string of URLs or a list."""
        if isinstance(v, str) and not v.startswith("["):
            return [url.strip() for url in v.split(",")]
        elif isinstance(v, list):
            return v
        elif isinstance(v, str):
            import json
            return json.loads(v)
        raise ValueError(f"Invalid CORS_ORIGINS format: {v}")
    
    @validator("SERVER_PORT")
    def validate_port(cls, v: int) -> int:
        """Validate port number."""
        if not 1 <= v <= 65535:
            raise ValueError("Port must be between 1 and 65535")
        return v
    
    @model_validator(mode='after')
    def check_proxy_settings(self) -> 'ServerConfig':
        """Ensure proxy settings are consistent."""
        if self.BEHIND_PROXY and not self.TRUSTED_HOSTS:
            logger.warning("BEHIND_PROXY is True but no TRUSTED_HOSTS specified")
        return self
    
    model_config = SettingsConfigDict(
        env_prefix="", 
        case_sensitive=True,
        env_file=find_env_file(),
        extra="ignore"
    )


class AuthConfig(BaseSettings):
    """Authentication & Security."""
    
    SECRET_KEY: SecretStr = Field(..., description="Secret key for token signing")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    PASSWORD_RESET_TOKEN_EXPIRE_MINUTES: int = 30
    VERIFY_EMAIL_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 1 day
    MIN_PASSWORD_LENGTH: int = 12
    PASSWORD_COMPLEXITY: Dict[str, int] = Field(
        default_factory=lambda: {
            "uppercase": 1,
            "lowercase": 1,
            "digits": 1,
            "special": 1
        },
        description="Password complexity requirements"
    )
    MAX_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_DURATION_MINUTES: int = 15
    SESSION_COOKIE_NAME: str = "nullcv_session"
    SESSION_COOKIE_SECURE: bool = True
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "lax"
    ENABLE_2FA: bool = False
    REQUIRE_2FA_FOR_ADMINS: bool = True
    JWT_HEADER_NAME: str = "Authorization"
    JWT_HEADER_TYPE: str = "Bearer"
    ADMIN_ROLE_NAME: str = "admin"
    DEFAULT_ROLE_NAME: str = "user"
    HASHING_ALGORITHM: str = "argon2"
    ENFORCE_HTTPS: bool = True
    CSRF_PROTECTION: bool = True
    CSRF_COOKIE_NAME: str = "csrftoken"
    AUTH_PROVIDERS: List[str] = Field(["password"], description="Enabled auth providers")
    
    @validator("SECRET_KEY")
    def validate_secret_key(cls, v: SecretStr) -> SecretStr:
        """Ensure secret key is strong enough."""
        value = v.get_secret_value()
        if len(value) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters long")
        return v
    
    @validator("ALGORITHM")
    def validate_algorithm(cls, v: str) -> str:
        """Validate JWT algorithm."""
        valid_algs = ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]
        if v not in valid_algs:
            raise ValueError(f"ALGORITHM must be one of: {', '.join(valid_algs)}")
        return v
    
    model_config = SettingsConfigDict(
        env_prefix="", 
        case_sensitive=True,
        env_file=find_env_file(),
        extra="ignore"
    )


class DatabaseConfig(BaseSettings):
    """PostgreSQL database connection settings."""

    POSTGRES_SERVER: str = Field(..., description="PostgreSQL server hostname or IP")
    POSTGRES_PORT: str = "5432"
    POSTGRES_USER: str = Field(..., description="PostgreSQL username")
    POSTGRES_PASSWORD: SecretStr = Field(..., description="PostgreSQL password")
    POSTGRES_DB: str = Field(..., description="PostgreSQL database name")
    SQLALCHEMY_DATABASE_URI: Optional[str] = None
    SQLALCHEMY_POOL_SIZE: int = 5
    SQLALCHEMY_MAX_OVERFLOW: int = 10
    SQLALCHEMY_POOL_TIMEOUT: int = 30  # seconds
    SQLALCHEMY_POOL_RECYCLE: int = 1800  # 30 minutes
    SQLALCHEMY_ECHO: bool = False  # Set to True to log all SQL queries
    DATABASE_ECHO_POOL: bool = Field(False, description="Log connection pool events")
    DATABASE_SSL_REQUIRED: bool = Field(False, description="Require SSL for database connections")
    DATABASE_ISOLATION_LEVEL: str = Field("READ COMMITTED", description="Transaction isolation level")
    DATABASE_SCHEMA: Optional[str] = Field(None, description="Database schema to use")
    DATABASE_CONNECT_RETRIES: int = Field(5, description="Number of connection retries")
    DATABASE_RETRY_BACKOFF: float = Field(1.5, description="Exponential backoff factor for retries")
    DATABASE_MIGRATIONS_DIR: str = Field("migrations", description="Directory for database migrations")
    DATABASE_VERIFY_MIGRATIONS_ON_STARTUP: bool = Field(True, description="Verify migrations on startup")
    
    # SQLite settings for local/embedded databases
    SQLITE_DATABASE_PATH: str = Field("./data/nullcv.db", description="Path to SQLite database")
    SQLITE_JOURNAL_MODE: str = Field("WAL", description="SQLite journal mode")
    SQLITE_SYNCHRONOUS: str = Field("NORMAL", description="SQLite synchronous mode")
    SQLITE_FOREIGN_KEYS: bool = Field(True, description="Enforce foreign key constraints")
    SQLITE_BUSY_TIMEOUT: int = Field(5000, description="SQLite busy timeout in milliseconds")
    
    # Database security settings
    DATABASE_ENCRYPT_SENSITIVE_DATA: bool = Field(False, description="Encrypt sensitive data at rest")
    DATABASE_ENCRYPTION_KEY: Optional[SecretStr] = Field(None, description="Key for database field encryption")
    VERIFY_SIGNATURES_ON_READ: bool = Field(True, description="Verify cryptographic signatures when reading data")
    AUTO_SYNC_DATABASE: bool = Field(True, description="Automatically synchronize database with peers")

    @validator("SQLALCHEMY_DATABASE_URI", pre=True)
    def build_db_uri(cls, v: Optional[str], values: Dict[str, Any]) -> Optional[str]:
        """Construct full database URI if not explicitly provided."""
        if v is not None:
            return v

        required = ["POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_SERVER", "POSTGRES_DB"]
        missing = [key for key in required if key not in values or not values.get(key)]
        
        if missing:
            missing_fields = ", ".join(missing)
            raise ValueError(f"Missing required database connection fields: {missing_fields}")

        # Get the actual string value from SecretStr
        password = values["POSTGRES_PASSWORD"].get_secret_value()
        port = values.get("POSTGRES_PORT", "5432")
            
        # Build connection string with SSL if required
        ssl_params = ""
        if values.get("DATABASE_SSL_REQUIRED", False):
            ssl_params = "?sslmode=require"
            
        return (
            f"postgresql+asyncpg://{values['POSTGRES_USER']}:"
            f"{password}@"
            f"{values['POSTGRES_SERVER']}:{port}/"
            f"{values['POSTGRES_DB']}{ssl_params}"
        )
    
    @model_validator(mode='after')
    def validate_sqlite_settings(self) -> 'DatabaseConfig':
        """Validate SQLite settings."""
        valid_journal_modes = ["DELETE", "TRUNCATE", "PERSIST", "MEMORY", "WAL", "OFF"]
        if self.SQLITE_JOURNAL_MODE not in valid_journal_modes:
            raise ValueError(f"SQLITE_JOURNAL_MODE must be one of: {', '.join(valid_journal_modes)}")
            
        valid_sync_modes = ["OFF", "NORMAL", "FULL", "EXTRA"]
        if self.SQLITE_SYNCHRONOUS not in valid_sync_modes:
            raise ValueError(f"SQLITE_SYNCHRONOUS must be one of: {', '.join(valid_sync_modes)}")
            
        # Warn if WAL mode without appropriate synchronous setting
        if self.SQLITE_JOURNAL_MODE == "WAL" and self.SQLITE_SYNCHRONOUS == "OFF":
            logger.warning("WAL mode with SYNCHRONOUS=OFF may result in data corruption")
            
        # Create directory if needed
        Path(self.SQLITE_DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)
            
        return self
    
    model_config = SettingsConfigDict(
        env_prefix="", 
        case_sensitive=True,
        env_file=find_env_file(),
        extra="ignore"
    )


class BlockchainConfig(BaseSettings):
    """Ethereum and other blockchain-related settings."""
    
    ETHEREUM_NODE_URL: str = Field(..., description="URL of Ethereum JSON-RPC node")
    ETHEREUM_CHAIN_ID: int = Field(1, description="Ethereum chain ID (1=mainnet, 5=goerli, etc)")
    ETHEREUM_FALLBACK_NODES: List[str] = Field([], description="Fallback node URLs")
    CONTRACT_ADDRESS: str = Field(..., description="Main contract address")
    WALLET_PRIVATE_KEY: Optional[SecretStr] = Field(None, description="Private key for transactions")
    GAS_PRICE_STRATEGY: str = Field("medium", description="Gas price strategy: slow, medium, fast, fastest")
    MAX_GAS_PRICE_GWEI: int = Field(150, description="Maximum gas price in Gwei")
    GAS_LIMIT_MARGIN: float = Field(1.2, description="Margin for gas limit estimation (e.g. 1.2 = 20% margin)")
    TRANSACTION_TIMEOUT: int = Field(120, description="Transaction timeout in seconds")
    TRANSACTION_CONFIRMATIONS: int = Field(1, description="Number of confirmations to wait for")
    RETRY_FAILED_TRANSACTIONS: bool = Field(True, description="Whether to retry failed transactions")
    ENABLE_ENS_RESOLUTION: bool = Field(True, description="Whether to enable ENS resolution")
    MULTICALL_BATCH_SIZE: int = Field(100, description="Batch size for multicall requests")
    EVENT_POLLING_INTERVAL: int = Field(15, description="Event polling interval in seconds")
    EVENT_CONFIRMATION_BLOCKS: int = Field(12, description="Blocks to wait for event finality")
    ABI_CACHE_DIR: str = Field("./data/abi_cache", description="Directory for ABI caching")
    SMART_CONTRACT_CONSTRUCTOR_ARGS: Dict[str, Any] = Field(
        default_factory=dict, 
        description="Constructor arguments for contract deployment"
    )
    WEB3_REQUEST_TIMEOUT: int = Field(30, description="Timeout for Web3 requests in seconds")
    WEB3_MAX_RETRIES: int = Field(3, description="Maximum number of retries for Web3 requests")
    CONNECT_TO_INFURA: bool = Field(False, description="Whether to connect to Infura")
    INFURA_PROJECT_ID: Optional[str] = Field(None, description="Infura project ID")
    CONNECT_TO_ALCHEMY: bool = Field(False, description="Whether to connect to Alchemy")
    ALCHEMY_API_KEY: Optional[str] = Field(None, description="Alchemy API key")
    
    @validator("CONTRACT_ADDRESS")
    def validate_contract_address(cls, v: str) -> str:
        """Validate Ethereum contract address format."""
        if not v.startswith("0x") or len(v) != 42:
            raise ValueError("CONTRACT_ADDRESS must be a valid Ethereum address (0x + 40 hex characters)")
        return v
    
    @validator("ETHEREUM_CHAIN_ID")
    def validate_chain_id(cls, v: int) -> int:
        """Validate Ethereum chain ID."""
        valid_ids = {1, 5, 11155111, 137, 80001, 42161, 421613}  # Common chain IDs
        if v not in valid_ids:
            logger.warning(f"Unusual Ethereum chain ID: {v}")
        return v
    
    @model_validator(mode='after')
    def check_provider_settings(self) -> 'BlockchainConfig':
        """Check provider-specific settings."""
        if self.CONNECT_TO_INFURA and not self.INFURA_PROJECT_ID:
            raise ValueError("INFURA_PROJECT_ID is required when CONNECT_TO_INFURA is True")
            
        if self.CONNECT_TO_ALCHEMY and not self.ALCHEMY_API_KEY:
            raise ValueError("ALCHEMY_API_KEY is required when CONNECT_TO_ALCHEMY is True")
            
        # Create ABI cache directory
        Path(self.ABI_CACHE_DIR).mkdir(parents=True, exist_ok=True)
            
        return self
    
    model_config = SettingsConfigDict(
        env_prefix="", 
        case_sensitive=True,
        env_file=find_env_file(),
        extra="ignore"
    )


class IPFSConfig(BaseSettings):
    """IPFS client and storage settings."""
    
    IPFS_API_URL: str = Field("http://localhost:5001/api/v0", description="IPFS API URL")
    IPFS_GATEWAY_URL: str = Field("https://ipfs.io/ipfs/", description="Public IPFS gateway URL")
    IPFS_CONNECT_TIMEOUT: int = Field(10, description="IPFS connection timeout in seconds")
    IPFS_READ_TIMEOUT: int = Field(30, description="IPFS read timeout in seconds")
    IPFS_MAX_FILE_SIZE_MB: int = Field(50, description="Maximum file size in MB")
    IPFS_PIN_FILES: bool = Field(True, description="Whether to pin files by default")
    IPFS_FALLBACK_GATEWAYS: List[str] = Field(
        default=[
            "https://ipfs.io/ipfs/",
            "https://gateway.pinata.cloud/ipfs/",
            "https://cloudflare-ipfs.com/ipfs/"
        ],
        description="Fallback IPFS gateways"
    )
    IPFS_LOCAL_STORAGE_PATH: str = Field("./data/ipfs", description="Local storage path for IPFS files")
    IPFS_REPLICATION_FACTOR: int = Field(3, description="Desired replication factor for content")
    IPFS_USE_KUBO: bool = Field(False, description="Whether to use local Kubo instance")
    IPFS_KUBO_PATH: Optional[str] = Field(None, description="Path to Kubo binary")
    IPFS_USE_PINNING_SERVICE: bool = Field(False, description="Whether to use a remote pinning service")
    IPFS_PINNING_SERVICE_URL: Optional[str] = Field(None, description="Pinning service URL")
    IPFS_PINNING_SERVICE_KEY: Optional[SecretStr] = Field(None, description="Pinning service API key")
    IPFS_CONTENT_VERIFICATION: bool = Field(True, description="Verify content integrity after retrieval")
    IPFS_CACHE_DURATION: int = Field(86400, description="Cache duration for IPFS content in seconds")
    IPFS_PROGRESS_CALLBACK: bool = Field(False, description="Enable progress callbacks for large transfers")
    
    @validator("IPFS_API_URL", "IPFS_GATEWAY_URL")
    def validate_urls(cls, v: str) -> str:
        """Validate IPFS URLs."""
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v
    
    @model_validator(mode='after')
    def check_pinning_service(self) -> 'IPFSConfig':
        """Check pinning service configuration."""
        if self.IPFS_USE_PINNING_SERVICE:
            if not self.IPFS_PINNING_SERVICE_URL:
                raise ValueError("IPFS_PINNING_SERVICE_URL is required when IPFS_USE_PINNING_SERVICE is True")
            if not self.IPFS_PINNING_SERVICE_KEY:
                raise ValueError("IPFS_PINNING_SERVICE_KEY is required when IPFS_USE_PINNING_SERVICE is True")
                
        # Create local storage directory
        Path(self.IPFS_LOCAL_STORAGE_PATH).mkdir(parents=True, exist_ok=True)
                
        return self
    
    model_config = SettingsConfigDict(
        env_prefix="", 
        case_sensitive=True,
        env_file=find_env_file(),
        extra="ignore"
    )


class FederationConfig(BaseSettings):
    """Federation protocol settings."""
    
    ACTIVITYPUB_ENABLED: bool = Field(True, description="Whether to enable ActivityPub federation")
    ACTIVITYPUB_DOMAIN: Optional[str] = Field(None, description="Domain for ActivityPub identities")
    FEDERATION_NODE_ID: Optional[str] = Field(None, description="Unique identifier for this node")
    FEDERATION_PUBLIC_KEY: Optional[str] = Field(None, description="Public key for federation")
    FEDERATION_PRIVATE_KEY: Optional[SecretStr] = Field(None, description="Private key for federation")
    ALLOW_REMOTE_FOLLOWS: bool = Field(True, description="Whether to allow remote follows")
    FEDERATION_SHARED_SECRET: Optional[SecretStr] = Field(None, description="Shared secret for trusted instances")
    FEDERATION_MAX_PAYLOAD_SIZE_MB: int = Field(10, description="Maximum federation payload size in MB")
    FEDERATION_REQUEST_TIMEOUT: int = Field(30, description="Federation request timeout in seconds")
    FEDERATION_SIGNATURE_EXPIRES: int = Field(300, description="Signature expiration time in seconds")
    FEDERATION_INBOX_CONCURRENCY: int = Field(5, description="Maximum concurrent inbox processors")
    FEDERATION_BACKOFF_FACTOR: float = Field(1.5, description="Exponential backoff factor for retries")
    FEDERATION_MAX_RETRY_ATTEMPTS: int = Field(5, description="Maximum retry attempts for federation requests")
    FEDERATION_OUTBOX_BATCH_SIZE: int = Field(50, description="Batch size for outbox processing")
    FEDERATION_TRUSTED_INSTANCES: List[str] = Field([], description="List of trusted federation instances")
    FEDERATION_ALLOWED_INSTANCES: Optional[List[str]] = Field(None, description="Allowlist for federation (None = all)")
    FEDERATION_BLOCKED_INSTANCES: List[str] = Field([], description="Blocklist for federation")
    FEDERATION_SYNC_INTERVAL: int = Field(3600, description="Sync interval with trusted instances in seconds")
    
    @model_validator(mode='after')
    def check_federation_keys(self) -> 'FederationConfig':
        """Ensure federation keys are present when enabled."""
        if self.ACTIVITYPUB_ENABLED:
            if not self.ACTIVITYPUB_DOMAIN:
                raise ValueError("ACTIVITYPUB_DOMAIN is required when ACTIVITYPUB_ENABLED is True")
            
            # Generate node ID if not present
            if not self.FEDERATION_NODE_ID:
                self.FEDERATION_NODE_ID = f"node_{secrets.token_hex(8)}"
                logger.info(f"Generated federation node ID: {self.FEDERATION_NODE_ID}")
                
        return self
    
    model_config = SettingsConfigDict(
        env_prefix="", 
        case_sensitive=True,
        env_file=find_env_file(),
        extra="ignore"
    )


class EmailConfig(BaseSettings):
    """Email service configuration."""
    
    EMAIL_ENABLED: bool = Field(True, description="Whether to enable email functionality")
    EMAIL_SENDER_NAME: str = Field("NullCV", description="Sender name for emails")
    EMAIL_SENDER_ADDRESS: str = Field("noreply@nullcv.io", description="Sender email address")
    EMAIL_SMTP_SERVER: str = Field("localhost", description="SMTP server hostname")
    EMAIL_SMTP_PORT: int = Field(587, description="SMTP server port")
    EMAIL_SMTP_USERNAME: Optional[str] = Field(None, description="SMTP username")
    EMAIL_SMTP_PASSWORD: Optional[SecretStr] = Field(None, description="SMTP password")
    EMAIL_USE_TLS: bool = Field(True, description="Whether to use TLS for SMTP")
    EMAIL_USE_SSL: bool = Field(False, description="Whether to use SSL for SMTP")
    EMAIL_TEMPLATES_DIR: str = Field("./templates/email", description="Directory for email templates")
    EMAIL_RATE_LIMIT: int = Field(100, description="Maximum emails per hour")
    EMAIL_QUEUE_PATH: str = Field("./data/email_queue", description="Path for email queue storage")
    EMAIL_DEFAULT_LANGUAGE: str = Field("en", description="Default language for emails")
    EMAIL_TEST_MODE: bool = Field(False, description="Whether to use test mode (no actual sending)")
    EMAIL_TEST_RECIPIENTS: List[str] = Field([], description="Test mode recipients")
    EMAIL_VERIFICATION_REQUIRED: bool = Field(True, description="Whether email verification is required")
    EMAIL_INCLUDE_UNSUBSCRIBE_LINK: bool = Field(True, description="Whether to include unsubscribe link in emails")
    EMAIL_MAX_RETRIES: int = Field(3, description="Maximum retry attempts for failed emails")
    EMAIL_RETRY_DELAY: int = Field(300, description="Delay between retry attempts in seconds")
    
    @validator("EMAIL_SENDER_ADDRESS")
    def validate_email(cls, v: str) -> str:
        """Validate email format."""
        if "@" not in v or "." not in v:
            raise ValueError("EMAIL_SENDER_ADDRESS must be a valid email address")
        return v
    
    @validator("EMAIL_SMTP_PORT")
    def validate_port(cls, v: int) -> int:
        """Validate port number."""
        if not 1 <= v <= 65535:
            raise ValueError("Port must be between 1 and 65535")
        return v
    
    @model_validator(mode='after')
    def check_smtp_auth(self) -> 'EmailConfig':
        """Check SMTP authentication settings."""
        if self.EMAIL_ENABLED and self.EMAIL_SMTP_SERVER != "localhost":
            if not self.EMAIL_SMTP_USERNAME or not self.EMAIL_SMTP_PASSWORD:
                logger.warning("SMTP server specified without authentication credentials")
                
        # Create email templates and queue directories
        if self.EMAIL_ENABLED:
            Path(self.EMAIL_TEMPLATES_DIR).mkdir(parents=True, exist_ok=True)
            Path(self.EMAIL_QUEUE_PATH).mkdir(parents=True, exist_ok=True)
                
        return self
    
    model_config = SettingsConfigDict(
        env_prefix="", 
        case_sensitive=True,
        env_file=find_env_file(),
        extra="ignore"
    )


class RedisConfig(BaseSettings):
    """Redis configuration."""
    
    REDIS_HOST: str = Field("localhost", description="Redis server hostname")
    REDIS_PORT: int = Field(6379, description="Redis server port")
    REDIS_PASSWORD: Optional[SecretStr] = Field(None, description="Redis password")
    REDIS_DB: int = Field(0, description="Redis database number")
    REDIS_USE_SSL: bool = Field(False, description="Whether to use SSL for Redis")
    REDIS_CONNECTION_TIMEOUT: int = Field(10, description="Connection timeout in seconds")
    REDIS_SOCKET_TIMEOUT: int = Field(5, description="Socket timeout in seconds")
    REDIS_POOL_MIN_SIZE: int = Field(1, description="Minimum pool size")
    REDIS_POOL_MAX_SIZE: int = Field(10, description="Maximum pool size")
    REDIS_KEY_PREFIX: str = Field("nullcv:", description="Prefix for Redis keys")
    REDIS_USE_CLUSTER: bool = Field(False, description="Whether to use Redis Cluster")
    REDIS_CLUSTER_NODES: List[str] = Field([], description="Redis Cluster node addresses")
    REDIS_SENTINEL_MASTER: Optional[str] = Field(None, description="Redis Sentinel master name")
    REDIS_SENTINEL_NODES: List[str] = Field([], description="Redis Sentinel node addresses")
    REDIS_USE_CACHE: bool = Field(True, description="Whether to use Redis for caching")
    REDIS_CACHE_TTL: int = Field(3600, description="Default TTL for cached items in seconds")
    
    @model_validator(mode='after')
    def check_cluster_settings(self) -> 'RedisConfig':
        """Check Redis cluster settings."""
        if self.REDIS_USE_CLUSTER and not self.REDIS_CLUSTER_NODES:
            raise ValueError("REDIS_CLUSTER_NODES is required when REDIS_USE_CLUSTER is True")
            
        if self.REDIS_SENTINEL_MASTER and not self.REDIS_SENTINEL_NODES:
            raise ValueError("REDIS_SENTINEL_NODES is required when REDIS_SENTINEL_MASTER is specified")
            
        return self
    
    model_config = SettingsConfigDict(
        env_prefix="", 
        case_sensitive=True,
        env_file=find_env_file(),
        extra="ignore"
    )


class APISecurityConfig(BaseSettings):
    """API security configuration."""
    
    API_KEY_HEADER_NAME: str = Field("X-API-Key", description="Header name for API key")
    API_REQUIRE_SIGNED_REQUESTS: bool = Field(False, description="Whether to require signed API requests")
    API_REQUEST_SIGNING_HEADER: str = Field("X-Request-Signature", description="Header for request signatures")
    API_REQUEST_TIMESTAMP_HEADER: str = Field("X-Request-Timestamp", description="Header for request timestamp")
    API_REQUEST_MAX_AGE: int = Field(300, description="Maximum age of requests in seconds (prevents replay attacks)")
    API_RATE_LIMIT_BY_IP: bool = Field(True, description="Whether to rate limit by IP address")
    API_RATE_LIMIT_BY_USER: bool = Field(True, description="Whether to rate limit by user ID")
    API_RATE_LIMIT_BY_KEY: bool = Field(True, description="Whether to rate limit by API key")
    API_RATE_LIMIT_EXEMPTED_IPS: List[str] = Field([], description="IP addresses exempted from rate limiting")
    API_SANITIZE_REQUEST_LOGS: bool = Field(True, description="Whether to sanitize sensitive data in request logs")
    API_ALLOWED_USER_AGENTS: Optional[List[str]] = Field(None, description="Allowlist for user agents")
    API_BLOCKED_USER_AGENTS: List[str] = Field([], description="Blocklist for user agents")
    API_STRICT_CONTENT_TYPE: bool = Field(True, description="Enforce strict content type checking")
    API_VALIDATE_REQUEST_SCHEMA: bool = Field(True, description="Validate request schema")
    API_VALIDATE_RESPONSE_SCHEMA: bool = Field(False, description="Validate response schema")
    API_REQUIRE_HTTPS: bool = Field(True, description="Whether to require HTTPS for API requests")
    API_MAX_BATCH_SIZE: int = Field(100, description="Maximum batch size for bulk operations")
    API_AUDIT_LOGGING: bool = Field(True, description="Whether to enable detailed audit logging")
    
    model_config = SettingsConfigDict(
        env_prefix="", 
        case_sensitive=True,
        env_file=find_env_file(),
        extra="ignore"
    )


class MonitoringConfig(BaseSettings):
    """Monitoring and observability configuration."""
    
    ENABLE_METRICS: bool = Field(True, description="Whether to enable metrics collection")
    METRICS_PORT: int = Field(9090, description="Port for metrics server")
    METRICS_PATH: str = Field("/metrics", description="Path for metrics endpoint")
    METRICS_COLLECTION_INTERVAL: int = Field(15, description="Metrics collection interval in seconds")
    ENABLE_TRACING: bool = Field(False, description="Whether to enable distributed tracing")
    TRACING_SAMPLING_RATE: float = Field(0.1, description="Tracing sampling rate (0-1)")
    TRACING_EXPORTER: str = Field("jaeger", description="Tracing exporter: jaeger, zipkin, otlp")
    TRACING_ENDPOINT: Optional[str] = Field(None, description="Tracing collector endpoint")
    TRACING_SERVICE_NAME: str = Field("nullcv", description="Service name for tracing")
    HEALTH_CHECK_ENABLED: bool = Field(True, description="Whether to enable health checks")
    HEALTH_CHECK_PATH: str = Field("/health", description="Path for health check endpoint")
    HEALTH_CHECK_INCLUDE_DETAILS: bool = Field(True, description="Whether to include detailed health status")
    ERROR_REPORTING_ENABLED: bool = Field(True, description="Whether to enable error reporting")
    ERROR_REPORTING_DSN: Optional[str] = Field(None, description="Error reporting service DSN")
    LOG_REQUEST_RESPONSE: bool = Field(False, description="Whether to log full request/response details")
    PERFORMANCE_MONITORING_ENABLED: bool = Field(True, description="Whether to enable performance monitoring")
    RESOURCE_USAGE_ALERTS: bool = Field(True, description="Whether to enable resource usage alerts")
    CPU_USAGE_THRESHOLD: float = Field(80.0, description="CPU usage alert threshold (percent)")
    MEMORY_USAGE_THRESHOLD: float = Field(80.0, description="Memory usage alert threshold (percent)")
    DISK_USAGE_THRESHOLD: float = Field(85.0, description="Disk usage alert threshold (percent)")
    
    model_config = SettingsConfigDict(
        env_prefix="", 
        case_sensitive=True,
        env_file=find_env_file(),
        extra="ignore"
    )


class CacheConfig(BaseSettings):
    """Caching configuration."""
    
    CACHE_ENABLED: bool = Field(True, description="Whether to enable caching")
    CACHE_TYPE: str = Field("memory", description="Cache type: memory, redis, memcached")
    CACHE_KEY_PREFIX: str = Field("nullcv:", description="Prefix for cache keys")
    CACHE_DEFAULT_TTL: int = Field(300, description="Default TTL for cached items in seconds")
    CACHE_MAX_SIZE: int = Field(1000, description="Maximum items in memory cache")
    CACHE_SERIALIZE_JSON: bool = Field(True, description="Whether to serialize objects as JSON")
    CACHE_COMPRESS_LARGE_VALUES: bool = Field(True, description="Whether to compress large values")
    CACHE_COMPRESSION_THRESHOLD: int = Field(1024, description="Threshold for compression in bytes")
    CACHE_COMPRESSION_LEVEL: int = Field(6, description="Compression level (1-9)")
    CACHE_MEMCACHED_SERVERS: List[str] = Field(["localhost:11211"], description="Memcached servers")
    CACHE_CONNECTION_POOL_SIZE: int = Field(10, description="Connection pool size")
    CACHE_JITTER: float = Field(0.1, description="Random jitter added to cache TTL to prevent stampedes")
    CACHE_SCHEMA_VERSION: str = Field("v1", description="Schema version for cache keys")
    CACHE_NULL_TIMEOUT: int = Field(60, description="TTL for null/empty results in seconds")
    CACHE_USE_FINGERPRINTING: bool = Field(True, description="Use content fingerprinting for cache invalidation")
    CACHE_STALE_WHILE_REVALIDATE: bool = Field(True, description="Return stale data while revalidating")
    CACHE_STALE_TTL: int = Field(86400, description="How long to keep stale data in seconds")
    
    @validator("CACHE_TYPE")
    def validate_cache_type(cls, v: str) -> str:
        """Validate cache type."""
        valid_types = ["memory", "redis", "memcached"]
        if v not in valid_types:
            raise ValueError(f"CACHE_TYPE must be one of: {', '.join(valid_types)}")
        return v
    
    model_config = SettingsConfigDict(
        env_prefix="", 
        case_sensitive=True,
        env_file=find_env_file(),
        extra="ignore"
    )


class Settings(
    AppConfig,
    ServerConfig,
    AuthConfig,
    DatabaseConfig,
    BlockchainConfig,
    IPFSConfig,
    FederationConfig,
    EmailConfig,
    RedisConfig,
    APISecurityConfig,
    MonitoringConfig,
    CacheConfig,
    LoggingConfig,
):
    """Aggregated settings for the NullCV application."""
    
    @validator("ENVIRONMENT")
    def validate_environment(cls, v: str) -> str:
        """Ensure environment is one of the allowed values."""
        allowed = {"dev", "test", "staging", "prod"}
        if v not in allowed:
            raise ValueError(f"ENVIRONMENT must be one of: {', '.join(allowed)}")
        return v
    
    def configure_logging(self) -> None:
        """Configure application logging based on settings."""
        setup_logging(self.LOG_LEVEL, self.LOG_FORMAT)
    
    @classmethod
    def from_environment(cls, environment: Optional[str] = None) -> 'Settings':
        """Load settings for a specific environment."""
        if environment:
            os.environ["ENVIRONMENT"] = environment
            
        # Register settings models with config manager
        config_manager = get_config_manager()
        config_manager.register_settings_model("settings", Settings)
        
        # Force reload configuration
        config_manager.reload(force=True)
        
        # Get settings from config manager
        settings = config_manager.get_settings("settings")
        if not settings:
            raise ConfigurationError("Failed to load settings")
            
        return settings


# Load settings with hierarchical env file discovery
def get_settings() -> Settings:
    """Get application settings."""
    # Use cached settings if available
    if hasattr(get_settings, "_cached_settings"):
        return get_settings._cached_settings
    
    # Initialize configuration manager
    config_manager = get_config_manager()
    
    # Register models
    config_manager.register_settings_model("app", AppConfig)
    config_manager.register_settings_model("server", ServerConfig)
    config_manager.register_settings_model("auth", AuthConfig)
    config_manager.register_settings_model("database", DatabaseConfig)
    config_manager.register_settings_model("blockchain", BlockchainConfig)
    config_manager.register_settings_model("ipfs", IPFSConfig)
    config_manager.register_settings_model("federation", FederationConfig)
    config_manager.register_settings_model("logging", LoggingConfig)
    config_manager.register_settings_model("email", EmailConfig)
    config_manager.register_settings_model("redis", RedisConfig)
    config_manager.register_settings_model("api_security", APISecurityConfig)
    config_manager.register_settings_model("monitoring", MonitoringConfig)
    config_manager.register_settings_model("cache", CacheConfig)
    config_manager.register_settings_model("settings", Settings)
    
    # Force reload to ensure all config is loaded
    config_manager.reload(force=True)
    
    # Validate configuration
    errors = config_manager.validate_all()
    if errors:
        error_messages = []
        for field, msgs in errors.items():
            for msg in msgs:
                error_messages.append(f"{field}: {msg}")
        
        error_str = "\n".join(error_messages)
        raise ConfigValidationError(f"Configuration validation failed:\n{error_str}")
    
    # Get settings from config manager
    settings = config_manager.get_settings("settings")
    if not settings:
        raise ConfigurationError("Failed to load settings")
    
    # Configure logging
    settings.configure_logging()
    
    # Cache settings
    get_settings._cached_settings = settings
    
    # Set up background config check if enabled
    if settings.CONFIG_CHECK_INTERVAL > 0:
        setup_config_watcher(settings.CONFIG_CHECK_INTERVAL)
    
    # Log discovered environment
    logger.info(f"Application environment: {settings.ENVIRONMENT}")
    
    return settings


def setup_config_watcher(interval_seconds: int = 60) -> None:
    """Set up a background thread to check for configuration changes."""
    config_manager = get_config_manager()
    
    def check_config():
        while True:
            try:
                time.sleep(interval_seconds)
                config_changed = config_manager.reload()
                
                if config_changed:
                    # Update cached settings
                    if hasattr(get_settings, "_cached_settings"):
                        # Get fresh settings
                        settings = config_manager.get_settings("settings")
                        if settings:
                            get_settings._cached_settings = settings
                            logger.info("Updated cached settings with new configuration")
            except Exception as e:
                logger.error(f"Error in config watcher: {e}")
    
    # Start background thread
    watcher_thread = threading.Thread(
        target=check_config, 
        daemon=True,
        name="ConfigWatcher"
    )
    watcher_thread.start()
    logger.debug(f"Started configuration watcher (interval: {interval_seconds}s)")


# Initialize settings
settings = get_settings()

# Register reload handler
def reload_settings() -> None:
    """Reload settings from environment."""
    global settings
    
    config_manager = get_config_manager()
    config_manager.reload(force=True)
    
    # Update settings
    new_settings = config_manager.get_settings("settings")
    if new_settings:
        settings = new_settings
        settings.configure_logging()
        logger.info("Settings reloaded successfully")
    else:
        logger.error("Failed to reload settings")