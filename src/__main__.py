"""Command-line execution for NullCV."""
import uvicorn
from nullcv.core.config import settings

if __name__ == "__main__":
    uvicorn.run(
        "nullcv.api.main:app",
        host=settings.SERVER_HOST,
        port=settings.SERVER_PORT,
        reload=settings.DEBUG,
        log_level="debug" if settings.DEBUG else "info",
    )
