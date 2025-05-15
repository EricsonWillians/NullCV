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
        self.paths, self.priority = paths, priority

    def load(self) -> ConfigPayload:
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
        self.prefix, self.priority = prefix, priority

    def load(self) -> ConfigPayload:
        payload: ConfigPayload = {}
        for k, v in os.environ.items():
            if self.prefix and not k.startswith(self.prefix):
                continue
            payload.setdefault(k, (v, ConfigSource.ENV_VAR, "os.environ"))
        return payload


class SecretDirProvider:
    def __init__(self, secrets_path: Path, *, priority: int = 300):
        self.secrets_path = secrets_path
        self.priority = priority

    def load(self) -> ConfigPayload:
        payload: ConfigPayload = {}
        if not self.secrets_path.is_dir():
            return payload
        for p in self.secrets_path.iterdir():
            if p.is_file():
                payload[p.name] = (p.read_text().strip(), ConfigSource.SECRET, str(p))
        return payload
