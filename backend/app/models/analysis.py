from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import DateTime, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, JSONType, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.attachment import Attachment
    from app.models.finding import SecurityFinding
    from app.models.module_result import AnalysisModule


class Analysis(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "analyses"
    __table_args__ = (
        Index("ix_analyses_created_at", "created_at"),
    )

    original_filename: Mapped[str] = mapped_column(String(512), nullable=False)
    stored_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    file_size: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    raw_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)

    sender: Mapped[str | None] = mapped_column(String(512), nullable=True)
    subject: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    classification: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    status: Mapped[str] = mapped_column(
        String(16), default="PENDING", nullable=False, index=True
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    report: Mapped[dict[str, Any] | None] = mapped_column(JSONType, nullable=True)

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    modules: Mapped[list[AnalysisModule]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan", lazy="selectin"
    )
    findings: Mapped[list[SecurityFinding]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan", lazy="selectin"
    )
    attachments: Mapped[list[Attachment]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan", lazy="selectin"
    )
