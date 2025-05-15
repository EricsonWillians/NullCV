"""
Config providers (env-file, env-vars, secret dir, ...).
No Pydantic imports – pure data collection.
"""

from __future__ import annotations
import os, json, yaml
from pathlib import Path
from typing import Any, Dict, List, Tuple
import logging
from enum import Enum, auto

logger = logging.getLogger("nullcv.config.providers")

class ConfigSource(Enum):
    ENV_FILE = auto()
    ENV_VAR = auto()
    SECRET  = auto()

ConfigPayload = Dict[str, Tuple[Any, ConfigSource, str]]  # value, source, source_detail


class EnvFileProvider:
    def __init__(self, paths: List[Path], *, priority: int = 100):
        """
        Initializes the provider with a list of environment file paths and an optional priority.
        
        Args:
            paths: List of file paths to environment files.
            priority: Determines the precedence of this provider (default is 100).
        """
        self.paths, self.priority = paths, priority

    def load(self) -> ConfigPayload:
        """
        Loads configuration key-value pairs from specified environment files.
        
        Reads each file in the provider's path list, parsing lines in KEY=VALUE format and ignoring comments or malformed lines. Returns a dictionary mapping keys to tuples containing the value, the source as ENV_FILE, and the file path.
        """
        payload: ConfigPayload = {}
        for path in self.paths:
            if not path.exists():
                continue
            for line in path.read_text().splitlines():
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = (s.strip() for s in line.split("=", 1))
                payload.setdefault(k, (v, ConfigSource.ENV_FILE, str(path)))
        return payload


class EnvVarProvider:
    def __init__(self, prefix: str = "", *, priority: int = 200):
        """
        Initializes the provider for loading environment variables with an optional prefix and priority.
        
        Args:
            prefix: Only environment variables starting with this prefix will be included.
            priority: Determines the precedence of this provider relative to others.
        """
        self.prefix, self.priority = prefix, priority

    def load(self) -> ConfigPayload:
        """
        Loads environment variables into a configuration payload, optionally filtering by prefix.
        
        Returns:
            A dictionary mapping environment variable names to tuples containing the value,
            the source as ENV_VAR, and the source detail as "os.environ".
        """
        payload: ConfigPayload = {}
        for k, v in os.environ.items():
            if self.prefix and not k.startswith(self.prefix):
                continue
            payload.setdefault(k, (v, ConfigSource.ENV_VAR, "os.environ"))
        return payload


class SecretDirProvider:
    def __init__(self, secrets_path: Path, *, priority: int = 300):
        """
        Initializes a SecretDirProvider with the specified secrets directory and priority.
        
        Args:
        	secrets_path: Path to the directory containing secret files.
        	priority: Determines the provider's precedence when merging configurations. Defaults to 300.
        """
        self.secrets_path = secrets_path
        self.priority = priority

    def load(self) -> ConfigPayload:
        """
        Loads secrets from files in the specified directory.
        
        Each file's name is used as the configuration key and its trimmed content as the value. Returns a dictionary mapping keys to tuples containing the value, the source as SECRET, and the file path as the source detail.
        """
        payload: ConfigPayload = {}
        if not self.secrets_path.is_dir():
            return payload
        for p in self.secrets_path.iterdir():
            if p.is_file():
                payload[p.name] = (p.read_text().strip(), ConfigSource.SECRET, str(p))
        return payload
