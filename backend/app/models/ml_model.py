from __future__ import annotations

from typing import Any

from sqlalchemy import Boolean, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, JSONType, TimestampMixin, UUIDPrimaryKeyMixin


class MlModelVersion(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "ml_model_versions"

    model_name: Mapped[str] = mapped_column(String(128), nullable=False)
    model_version: Mapped[str] = mapped_column(String(64), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(128), nullable=False)
    dataset_reference: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    metrics: Mapped[dict[str, Any] | None] = mapped_column(JSONType, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
