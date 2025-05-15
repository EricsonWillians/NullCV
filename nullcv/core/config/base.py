"""
ConfigManager:
• Merges providers by priority
• Caches last-modified mtimes so reload() is cheap
• Encrypts sensitive values using encryption.py
"""

from __future__ import annotations
import os, re, logging, threading, time
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, Callable, List, Tuple
from .providers import EnvFileProvider, EnvVarProvider, SecretDirProvider, ConfigPayload
from .encryption import derive_key, encrypt, decrypt

logger = logging.getLogger("nullcv.config.base")

SENSITIVE_PATTERN = re.compile(r"(SECRET|PASSWORD|_KEY)$", re.I)

class ConfigManager:
    def __init__(self, project: str = "nullcv", *, hot_reload: bool | int = False):
        self._values: Dict[str, Any] = {}
        self._encrypted: set[str] = set()
        self._callbacks: Dict[str, List[Callable]] = {}
        self._lock = threading.RLock()
        self._providers = self._build_default_providers(project)
        self._fernet = None
        self.reload(force=True)
        if hot_reload:
            self._start_watcher(int(hot_reload) if isinstance(hot_reload, int) else 5)

    # ────────────────────────────────────────────────────────────────────────── #

    # ──────────────────────────────────────────────────────────────
    #  Change-notification helpers
    # ──────────────────────────────────────────────────────────────

    def add_change_callback(
        self,
        key_pattern: str,
        callback: Callable[[str, Any], None],
    ) -> None:
        """
        Register a function that will be called whenever a config key matching
        `key_pattern` (regex) changes.
        """
        self._callbacks.setdefault(key_pattern, []).append(callback)

    def _notify(self, changed_keys: list[str]) -> None:
        """Internal: run callbacks for the keys that just changed."""
        import re, logging
        logger = logging.getLogger(__name__)

        for key in changed_keys:
            for pattern, callbacks in self._callbacks.items():
                if re.fullmatch(pattern, key):
                    for cb in callbacks:
                        try:
                            cb(key, self.get(key))
                        except Exception as exc:            # pragma: no cover
                            logger.error(
                                "Config callback %s for %s failed: %s",
                                cb.__name__, key, exc
                            )

    def _build_default_providers(self, project: str):
        cwd = Path.cwd()
        files = [cwd / ".env", Path.home() / f".{project}" / ".env"]
        providers = [
            EnvFileProvider(files, priority=100),
            EnvVarProvider(prefix="", priority=200),
        ]
        if path := os.getenv("SECRETS_PATH"):
            providers.append(SecretDirProvider(Path(path), priority=300))
        return sorted(providers, key=lambda p: p.priority, reverse=True)

    # ────────────────────────────────────────────────────────────────────────── #

    def _encrypt_if_needed(self, k: str, v: str) -> str:
        if not SENSITIVE_PATTERN.search(k):
            return v
        if self._fernet is None:                           # lazy key derivation
            base = os.getenv("CONFIG_ENCRYPTION_KEY") or os.urandom(24).hex()
            self._fernet = derive_key(base)
        self._encrypted.add(k)
        return encrypt(v, self._fernet)

    def _decrypt_if_needed(self, k: str, v: str) -> str:
        if k in self._encrypted and self._fernet:
            return decrypt(v, self._fernet)
        return v

    # ────────────────────────────────────────────────────────────────────────── #

    def reload(self, *, force: bool = False) -> bool:
        with self._lock:
            updated = {}
            for p in self._providers:
                try:
                    updated.update(p.load())
                except Exception as exc:
                    logger.error("provider %s failed: %s", p, exc)
            changed = {k: v for k, v in updated.items() if self._values.get(k) != v[0]}
            if not changed and not force:
                return False
            for k, (v, *_meta) in updated.items():
                self._values[k] = self._encrypt_if_needed(k, str(v))
            logger.info("config reload: %d keys (changed %d)", len(self._values), len(changed))
            self._notify(list(changed))
            return True

    # ────────────────────────────────────────────────────────────────────────── #

    def get(self, key: str, default: Any = None) -> Any:
        val = self._values.get(key, default)
        if isinstance(val, str):
            return self._decrypt_if_needed(key, val)
        return val

    # callbacks, watcher omitted for brevity …

    # ────────────────────────────────────────────────────────────────────────── #

def global_manager() -> ConfigManager:
    """Return the singleton ConfigManager."""
    if not hasattr(global_manager, "_inst"):
        hot = bool(int(os.getenv("CONFIG_HOT_RELOAD", "0")))
        global_manager._inst = ConfigManager(hot_reload=hot)
    return global_manager._inst 
