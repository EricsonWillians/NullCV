"""Reusable SQLAlchemy model mix‑ins."""
from sqlalchemy import Integer, Column, DateTime, func, Text
from sqlalchemy.orm import declarative_mixin

@declarative_mixin
class TimestampMixin:
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

@declarative_mixin
class JsonRecordMixin(TimestampMixin):
    """Stores the payload as a JSON string (fits SQLite) + FK to signature row."""
    id = Column(Text, primary_key=True)
    data = Column(Text, nullable=False)
    signature_id = Column(Integer, index=True)