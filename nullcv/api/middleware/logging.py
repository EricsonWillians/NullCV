# nullcv/api/middleware/logging.py

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
import logging
import time

logger = logging.getLogger("nullcv")

class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        response = await call_next(request)
        process_time = (time.time() - start_time) * 1000

        logger.info(
            f"{request.method} {request.url.path} "
            f"→ {response.status_code} [{process_time:.2f}ms]"
        )
        return response
