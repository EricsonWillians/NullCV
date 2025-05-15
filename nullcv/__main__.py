"""Command-line entry for NullCV."""
import uvicorn
from nullcv.core.config import settings

if __name__ == "__main__":
    uvicorn.run(
        "nullcv.api.main:app",
        host=settings.server.SERVER_HOST,
        port=settings.server.SERVER_PORT,
        reload=settings.app.DEBUG,
        log_level="debug" if settings.app.DEBUG else "info",
    )
