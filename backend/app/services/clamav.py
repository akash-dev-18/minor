from __future__ import annotations

import asyncio
import logging
import socket

from app.core.config import Settings

logger = logging.getLogger(__name__)

CHUNK_SIZE = 2048


def _scan_sync(host: str, port: int, payload: bytes) -> tuple[str, str | None]:
    with socket.create_connection((host, port), timeout=5.0) as connection:
        connection.sendall(b"zINSTREAM\0")
        for offset in range(0, len(payload), CHUNK_SIZE):
            chunk = payload[offset : offset + CHUNK_SIZE]
            connection.sendall(len(chunk).to_bytes(4, "big") + chunk)
        connection.sendall(b"\x00\x00\x00\x00")
        response = b""
        while True:
            data = connection.recv(4096)
            if not data:
                break
            response += data
            if b"\0" in data or b"\n" in data:
                break
    text = response.decode("utf-8", "replace").strip("\0\n ")
    if "FOUND" in text:
        return "MALICIOUS", text
    if text.startswith("OK"):
        return "CLEAN", None
    return "FAILED", text or "Unexpected ClamAV response"


async def scan_payload(payload: bytes, settings: Settings) -> tuple[str, str | None]:
    if not settings.clamav_enabled:
        return "UNAVAILABLE", "ClamAV scanning is not configured"
    if not payload:
        return "SKIPPED", "No attachment payload available for scanning"
    try:
        return await asyncio.to_thread(
            _scan_sync, settings.clamav_host, settings.clamav_port, payload
        )
    except OSError as exc:
        logger.warning("ClamAV scan failed: %s", exc)
        return "UNAVAILABLE", f"ClamAV could not be reached: {type(exc).__name__}"
