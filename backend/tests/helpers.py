from __future__ import annotations

from app.core.config import settings
from app.modules.base import AnalysisContext
from app.schemas.analysis import EmailAttachment, EmailObject


def make_email(**overrides) -> EmailObject:
    defaults = dict(
        sender="sender@example.com",
        recipients=["user@example.org"],
        subject="Test message",
        body_text="Hello there.",
        headers={"from": ["sender@example.com"]},
    )
    defaults.update(overrides)
    return EmailObject(**defaults)


def context() -> AnalysisContext:
    return AnalysisContext(analysis_id="test-analysis", settings=settings)


def attachment(filename: str, payload: bytes = b"data", mime: str = "application/octet-stream") -> EmailAttachment:
    import hashlib

    return EmailAttachment(
        filename=filename,
        mime_type=mime,
        size=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
        payload=payload,
    )
