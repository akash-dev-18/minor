from __future__ import annotations

import hashlib
import os
import uuid
from pathlib import Path

from app.core.config import settings


def store_email(raw: bytes) -> tuple[Path, str]:
    settings.upload_path.mkdir(parents=True, exist_ok=True)
    target = settings.upload_path / f"{uuid.uuid4().hex}.eml"
    temporary = target.with_suffix(".eml.tmp")

    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
        temporary.replace(target)
    finally:
        if temporary.exists():
            temporary.unlink(missing_ok=True)

    return target, hashlib.sha256(raw).hexdigest()


def delete_stored_file(path: str | None) -> None:
    if not path:
        return
    stored = Path(path)
    try:
        if stored.is_file() and stored.resolve().is_relative_to(settings.upload_path.resolve()):
            stored.unlink()
    except OSError:
        pass
