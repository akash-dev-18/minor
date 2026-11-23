from __future__ import annotations

from pathlib import Path

import pytest

from app.modules.email_parser.parser import extract_urls, parse_email, summarize

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "emails"


def load(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def test_parse_simple_email():
    email = parse_email(load("simple.eml"))

    assert email.sender == "alice@example.com"
    assert email.sender_name == "Alice Example"
    assert "bob@example.org" in email.recipients
    assert "carol@example.net" in email.recipients
    assert email.subject == "Quarterly report"
    assert "report" in email.body_text
    assert "https://example.com/report?id=42" in email.urls
    assert "https://example.org/mirror" in email.urls
    assert email.parse_defects == []


def test_parse_html_extracts_links_and_forms():
    email = parse_email(load("phishing_html.eml"))

    assert email.body_html is not None
    assert "http://192.168.10.25/login" in email.urls
    assert "https://www.paypal.com/secure" in email.urls
    assert "http://evil.example/collect" in email.urls
    assert email.urls.count("http://192.168.10.25/login") == 1


def test_parse_attachment_metadata():
    email = parse_email(load("attachment.eml"))

    assert len(email.attachments) == 1
    attachment = email.attachments[0]
    assert attachment.filename == "invoice.pdf"
    assert attachment.mime_type == "application/pdf"
    assert attachment.size > 0
    assert attachment.sha256 is not None and len(attachment.sha256) == 64
    assert attachment.payload is not None
    assert attachment.oversized is False


def test_encoded_subject_is_decoded():
    email = parse_email(load("encoded_subject.eml"))

    assert email.subject == "Verificación de cuenta"
    assert email.sender_name == "Seguridad Bancaria"
    assert email.sender == "alertas@banco.example"


def test_malformed_email_does_not_raise():
    email = parse_email(load("malformed.eml"))

    assert email.sender == "broken@example.com"
    assert email.subject == "Truncated message"
    assert isinstance(email.parse_defects, list)


def test_binary_garbage_is_handled():
    email = parse_email(b"\x00\x01\x02 not an email \xff\xfe")

    assert email.raw_size == 19
    assert isinstance(email.parse_defects, list)


def test_extract_urls_normalizes_and_deduplicates():
    urls = extract_urls(
        "See https://example.com/a. Also HTTPS://EXAMPLE.com/b, "
        "and https://example.com/a again.",
        html='<a href="https://example.com/c">x</a><img src="javascript:alert(1)">',
    )

    assert "https://example.com/a" in urls
    assert "https://example.com/c" in urls
    assert len(urls) == len(set(urls))
    assert all(url.lower().startswith("http") for url in urls)


def test_summarize_excludes_body_content():
    email = parse_email(load("simple.eml"))
    summary = summarize(email)

    assert summary["sender"] == "alice@example.com"
    assert summary["url_count"] == len(email.urls)
    assert "body_text" not in summary
    assert summary["attachments"] == []
