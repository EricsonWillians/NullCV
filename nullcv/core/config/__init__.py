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
    def app(self):         """
Returns the application configuration singleton.

Provides access to application-level settings such as project name, version, and related metadata.
"""
return app
    @property
    def server(self):      """
Returns the server configuration singleton.

This property provides access to server-related configuration settings.
"""
return server
    @property
    def auth(self):        """
Returns the authentication configuration singleton.

Provides access to authentication-related settings for the application.
"""
return auth
    @property
    def db(self):          """
Returns the database configuration singleton.

Provides access to database-related configuration settings.
"""
return db
    @property
    def blockchain(self):  """
Returns the singleton configuration object for blockchain-related settings.
"""
return blockchain
    @property
    def ipfs(self):        """
Returns the singleton configuration object for the IPFS domain.
"""
return ipfs
    @property
    def federation(self):  """
Returns the singleton configuration object for federation settings.
"""
return federation
    @property
    def email(self):       """
Returns the singleton configuration object for the email domain.
"""
return email
    @property
    def redis(self):       """
Returns the singleton configuration object for the Redis domain.
"""
return redis
    @property
    def api_sec(self):     """
Returns the API security configuration singleton.
"""
return api_sec
    @property
    def monitoring(self):  """
Returns the monitoring configuration singleton object.
"""
return monitoring
    @property
    def cache(self):       """
Returns the singleton configuration object for the cache domain.
"""
return cache

    # Convenience: hot-reload config at runtime
    def reload(self, force: bool = False):
        """
        Reloads all configuration domains at runtime.
        
        Args:
            force: If True, forces a reload even if no changes are detected.
        
        Returns:
            The result of the global configuration manager's reload operation.
        """
        return global_manager().reload(force=force)

# 👇 **THIS LINE is what `python -m nullcv` expects**
settings = _Settings()

# tiny console logger so early errors are visible
logging.basicConfig(level=logging.INFO,
                    format="%(levelname)s | %(name)s | %(message)s")
