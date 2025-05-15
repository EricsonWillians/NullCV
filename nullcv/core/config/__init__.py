"""
Public façade for the configuration subsystem.

    from nullcv.core.config import settings

`settings` exposes namespaced domain objects:
    settings.app.PROJECT_NAME
    settings.server.SERVER_PORT
    ...
"""

import logging
from .base import global_manager        # singleton ConfigManager
from .models import (                   # domain singletons
    app, server, auth, db, blockchain,
    ipfs, federation, email, redis,
    api_sec, monitoring, cache,
)

logger = logging.getLogger(__name__)

class _Settings:                # lightweight proxy; no heavy work at import time
    @property
    def app(self):         return app
    @property
    def server(self):      return server
    @property
    def auth(self):        return auth
    @property
    def db(self):          return db
    @property
    def blockchain(self):  return blockchain
    @property
    def ipfs(self):        return ipfs
    @property
    def federation(self):  return federation
    @property
    def email(self):       return email
    @property
    def redis(self):       return redis
    @property
    def api_sec(self):     return api_sec
    @property
    def monitoring(self):  return monitoring
    @property
    def cache(self):       return cache

    # Convenience: hot-reload config at runtime
    def reload(self, force: bool = False):
        return global_manager().reload(force=force)

# 👇 **THIS LINE is what `python -m nullcv` expects**
settings = _Settings()

# tiny console logger so early errors are visible
logging.basicConfig(level=logging.INFO,
                    format="%(levelname)s | %(name)s | %(message)s")
