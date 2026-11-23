from __future__ import annotations

import hashlib
import logging
import re
from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from typing import Any

from app.core.config import settings
from app.schemas.analysis import EmailAttachment, EmailObject

logger = logging.getLogger(__name__)

URL_RE = re.compile(r"https?://[^\s<>\"'\]\)\}]+", re.IGNORECASE)
URL_TRAILING = ".,;:!?)]}'\""
MAX_HEADER_VALUE = 4096
MAX_BODY_CHARS = 2_000_000


class _HtmlLinkCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for name, value in attrs:
            if not value:
                continue
            lowered = name.lower()
            if lowered in {"href", "src", "action", "formaction"}:
                self.links.append(value)


def _clean_url(value: str) -> str | None:
    candidate = value.strip()
    if not candidate:
        return None
    lowered = candidate.lower()
    if not (lowered.startswith("http://") or lowered.startswith("https://")):
        return None
    candidate = candidate.rstrip(URL_TRAILING)
    if len(candidate) > 4096:
        return None
    return candidate


def extract_urls(text: str, html: str | None = None) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        cleaned = _clean_url(value)
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            found.append(cleaned)

    for match in URL_RE.finditer(text or ""):
        add(match.group(0))

    if html:
        collector = _HtmlLinkCollector()
        try:
            collector.feed(html)
            collector.close()
        except Exception as exc:  # noqa: BLE001
            logger.debug("HTML link collection failed: %s", exc)
        for link in collector.links:
            add(link)

    return found


def _header_value(message: Message, name: str) -> str | None:
    try:
        values = message.get_all(name)
    except Exception:  # noqa: BLE001
        return None
    if not values:
        return None
    raw = str(values[0]).strip()
    return raw[:MAX_HEADER_VALUE] if raw else None


def _collect_headers(message: Message) -> dict[str, list[str]]:
    headers: dict[str, list[str]] = {}
    for key, value in message.items():
        name = str(key).lower()
        try:
            text = str(value)
        except Exception:  # noqa: BLE001
            continue
        headers.setdefault(name, []).append(text[:MAX_HEADER_VALUE])
    return headers


def _addresses(message: Message, *fields: str) -> list[str]:
    raw: list[str] = []
    for field in fields:
        try:
            for value in message.get_all(field, []):
                text = str(value)
                if text:
                    raw.append(text)
        except Exception:  # noqa: BLE001
            continue
    return [addr for _name, addr in getaddresses(raw) if addr]


def _safe_decode(payload: bytes, charset: str | None) -> str:
    try:
        return payload.decode(charset or "utf-8", errors="replace")
    except (LookupError, TypeError):
        return payload.decode("utf-8", errors="replace")


def _decode_text(part: Message) -> str:
    try:
        content = part.get_content()
        if isinstance(content, str):
            return content
        if isinstance(content, bytes):
            return _safe_decode(content, part.get_content_charset())
    except Exception as exc:  # noqa: BLE001
        logger.debug("Falling back to raw payload for text part: %s", exc)
    payload = part.get_payload(decode=True)
    if isinstance(payload, bytes):
        return _safe_decode(payload, part.get_content_charset())
    return ""


def _attachment_filename(part: Message) -> str | None:
    try:
        name = part.get_filename()
    except Exception:  # noqa: BLE001
        return None
    if not name:
        return None
    return name.replace("\\", "_").replace("/", "_")[:255]


def _build_attachment(part: Message, filename: str) -> EmailAttachment:
    payload = part.get_payload(decode=True)
    if not isinstance(payload, bytes):
        payload = b""
    size = len(payload)
    digest = hashlib.sha256(payload).hexdigest() if payload else None
    oversized = size > settings.max_attachment_bytes
    return EmailAttachment(
        filename=filename,
        mime_type=part.get_content_type(),
        size=size,
        sha256=digest,
        oversized=oversized,
        payload=None if oversized else payload,
    )


def parse_email(raw: bytes) -> EmailObject:
    """Parse an RFC 822 message into a normalized EmailObject.

    Never raises for malformed input: unrecoverable defects are reported in
    ``parse_defects`` and the parser returns whatever could be extracted.
    """
    defects: list[str] = []
    message: Message
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Unparseable email: %s", exc)
        text = raw.decode("utf-8", errors="replace")
        return EmailObject(
            subject="",
            body_text=text[:MAX_BODY_CHARS],
            urls=extract_urls(text),
            raw_size=len(raw),
            parse_defects=[f"message_parse_failed:{type(exc).__name__}"],
        )

    for defect in getattr(message, "defects", []) or []:
        defects.append(type(defect).__name__)

    sender_header = _header_value(message, "From")
    sender_name, sender_addr = parseaddr(sender_header or "")
    reply_recipients = _addresses(message, "Reply-To")
    recipients = _addresses(message, "To", "Cc", "Bcc")

    body_text_parts: list[str] = []
    body_html_parts: list[str] = []
    attachments: list[EmailAttachment] = []

    for part in message.walk():
        if part.is_multipart():
            continue
        content_type = part.get_content_type()
        disposition = part.get_content_disposition()
        filename = _attachment_filename(part)

        if filename or disposition == "attachment":
            attachments.append(_build_attachment(part, filename or "attachment"))
            continue
        if content_type == "text/plain" and disposition != "inline":
            body_text_parts.append(_decode_text(part))
        elif content_type == "text/html":
            body_html_parts.append(_decode_text(part))
        elif content_type == "text/plain":
            body_text_parts.append(_decode_text(part))
        elif content_type.startswith("text/"):
            body_text_parts.append(_decode_text(part))

    body_text = "\n".join(part for part in body_text_parts if part)[:MAX_BODY_CHARS]
    body_html = "\n".join(part for part in body_html_parts if part)[:MAX_BODY_CHARS] or None

    urls = extract_urls(body_text, body_html)

    return EmailObject(
        sender=sender_addr or None,
        sender_name=sender_name or None,
        reply_to=reply_recipients[0] if reply_recipients else None,
        return_path=_header_value(message, "Return-Path"),
        recipients=recipients,
        subject=_header_value(message, "Subject") or "",
        body_text=body_text,
        body_html=body_html,
        headers=_collect_headers(message),
        urls=urls,
        attachments=attachments,
        raw_size=len(raw),
        parse_defects=defects,
    )


def summarize(email: EmailObject) -> dict[str, Any]:
    return {
        "sender": email.sender,
        "sender_name": email.sender_name,
        "reply_to": email.reply_to,
        "return_path": email.return_path,
        "recipients": email.recipients,
        "subject": email.subject,
        "body_text_length": len(email.body_text),
        "has_html": bool(email.body_html),
        "url_count": len(email.urls),
        "urls": email.urls[:100],
        "attachment_count": len(email.attachments),
        "attachments": [
            {
                "filename": attachment.filename,
                "mime_type": attachment.mime_type,
                "size": attachment.size,
                "sha256": attachment.sha256,
                "oversized": attachment.oversized,
            }
            for attachment in email.attachments
        ],
        "header_count": len(email.headers),
        "parse_defects": email.parse_defects,
        "raw_size": email.raw_size,
    }
