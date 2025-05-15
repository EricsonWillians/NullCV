from typing import Optional
from pydantic import BaseSettings, Field

from ..base import global_manager


class MonitoringConfig(BaseSettings):
    ENABLE_METRICS: bool = True
    METRICS_PORT: int = 9090
    ENABLE_TRACING: bool = False
    TRACING_EXPORTER: str = "jaeger"
    TRACING_ENDPOINT: Optional[str] = None
    ERROR_REPORTING_ENABLED: bool = True
    ERROR_REPORTING_DSN: Optional[str] = None

    class Config:
        frozen = True
        case_sensitive = True


monitoring = MonitoringConfig(_env_override=global_manager().get)  # type: ignore
