from __future__ import annotations

from app.modules.attachment_analysis.analyzer import analyze
from app.schemas.enums import AnalysisStatus, ScanStatus
from tests.helpers import attachment, context, make_email


def types(result) -> set[str]:
    return {item.type for item in result.findings}


async def test_double_extension_is_flagged():
    email = make_email(
        body_text="See invoice",
        attachments=[attachment("invoice.pdf.exe", b"MZ fake executable", "application/pdf")],
    )
    result = await analyze(email, context())

    assert result.status == AnalysisStatus.COMPLETED
    found = types(result)
    assert "double_extension" in found
    assert "dangerous_attachment_executable" in found


async def test_macro_document_is_flagged():
    result = await analyze(
        make_email(attachments=[attachment("report.docm", b"macros", "application/msword")]),
        context(),
    )
    assert "dangerous_attachment_macro" in types(result)


async def test_oversized_attachment_is_flagged():
    oversized = attachment("backup.zip", b"PK", "application/zip")
    oversized.oversized = True
    oversized.payload = None

    result = await analyze(make_email(attachments=[oversized]), context())
    assert "attachment_oversized" in types(result)


async def test_clamav_unavailable_is_reported_honestly():
    result = await analyze(
        make_email(attachments=[attachment("report.pdf", b"%PDF-1.4 data", "application/pdf")]),
        context(),
    )
    record = result.data["attachments"][0]
    assert record["clamav"]["status"] == ScanStatus.UNAVAILABLE.value
    assert "malware_detected" not in types(result)


async def test_no_attachments_is_clean():
    result = await analyze(make_email(attachments=[]), context())
    assert result.findings == []
    assert result.data["attachments_analyzed"] == 0
