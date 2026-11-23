from __future__ import annotations

import re

import magic

from app.core.config import settings
from app.core.errors import APIError

HEADER_LINE_RE = re.compile(rb"(?m)^[A-Za-z][A-Za-z0-9-]{0,63}:[ \t]?")
BLOCKED_MIME_PREFIXES = (
    "application/x-dosexec",
    "application/x-executable",
    "application/x-sharedlib",
    "application/x-mach-binary",
    "application/zip",
    "application/x-7z-compressed",
    "application/x-rar",
    "application/pdf",
    "image/",
    "audio/",
    "video/",
)


def validate_upload(raw: bytes, filename: str | None) -> None:
    if not filename or not filename.lower().endswith(".eml"):
        raise APIError(415, "unsupported_file_type", "Only .eml files are accepted")

    if not raw:
        raise APIError(422, "empty_file", "The uploaded file is empty")

    if len(raw) > settings.max_upload_bytes:
        raise APIError(
            413,
            "file_too_large",
            f"File exceeds the {settings.max_upload_bytes} byte limit",
        )

    head = raw[:8192]
    if b"\x00" in head:
        raise APIError(415, "unsupported_file_type", "File does not look like an email")

    try:
        detected = magic.from_buffer(head, mime=True) or ""
    except Exception:  # noqa: BLE001
        detected = ""

    if detected.startswith(BLOCKED_MIME_PREFIXES):
        raise APIError(
            415,
            "unsupported_file_type",
            f"File content is not a supported email type ({detected})",
        )

    if not HEADER_LINE_RE.search(head):
        raise APIError(415, "unsupported_file_type", "File does not contain email headers")
