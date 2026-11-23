from __future__ import annotations

import logging
import time

import magic

from app.modules.attachment_analysis.data import (
    ARCHIVE_MIME_PREFIXES,
    DANGEROUS_EXTENSIONS,
    DOCUMENT_EXTENSIONS,
    EXECUTABLE_MIME_PREFIXES,
)
from app.modules.base import AnalysisContext, build_result, finding
from app.schemas.analysis import EmailAttachment, EmailObject, Finding, ModuleResult
from app.schemas.enums import ModuleName, ScanStatus, Severity
from app.services.clamav import scan_payload
from app.services.threat_intelligence import get_threat_intelligence

logger = logging.getLogger(__name__)

MODULE = ModuleName.ATTACHMENT_ANALYSIS
RECOMMENDATION = "Do not open this attachment. Verify the sender and request the file through a trusted channel."


def _extension(filename: str) -> str | None:
    if "." not in filename:
        return None
    return filename.rsplit(".", 1)[-1].lower()


def _detect_mime(payload: bytes) -> str | None:
    try:
        return magic.from_buffer(payload[:2048], mime=True)
    except Exception as exc:  # noqa: BLE001
        logger.debug("Magic detection failed: %s", exc)
        return None


def _is_blocked_mime(mime: str | None) -> bool:
    if not mime:
        return False
    return mime.startswith(EXECUTABLE_MIME_PREFIXES) or mime.startswith(ARCHIVE_MIME_PREFIXES)


async def _analyze_attachment(
    attachment: EmailAttachment, context: AnalysisContext, findings: list[Finding]
) -> dict:
    settings = context.settings
    extension = _extension(attachment.filename)
    record: dict = {
        "filename": attachment.filename,
        "mime_type": attachment.mime_type,
        "size": attachment.size,
        "sha256": attachment.sha256,
        "extension": extension,
    }

    if extension is None:
        findings.append(
            finding(
                MODULE,
                "attachment_without_extension",
                "Attachment has no file extension",
                Severity.LOW,
                "Files without extensions can bypass naive filtering and hide their true type.",
                evidence=attachment.filename,
                recommendation=RECOMMENDATION,
                confidence=0.4,
            )
        )

    parts = attachment.filename.lower().split(".")
    if extension and len(parts) >= 3 and extension in DANGEROUS_EXTENSIONS:
        previous = parts[-2]
        if previous in DOCUMENT_EXTENSIONS:
            findings.append(
                finding(
                    MODULE,
                    "double_extension",
                    "Attachment uses a deceptive double extension",
                    Severity.HIGH,
                    f"The file appears to be a benign .{previous} document but actually ends "
                    f"in .{extension}, a common malware disguise.",
                    evidence=attachment.filename,
                    recommendation=RECOMMENDATION,
                    confidence=0.85,
                )
            )

    if extension and extension in DANGEROUS_EXTENSIONS:
        severity, category, description = DANGEROUS_EXTENSIONS[extension]
        findings.append(
            finding(
                MODULE,
                f"dangerous_attachment_{category}",
                f"Attachment is a {category.replace('_', ' ')} file",
                Severity(severity),
                f"The attachment {description.lower()} (.{extension}) can execute code or "
                "deliver a payload when opened.",
                evidence=attachment.filename,
                recommendation=RECOMMENDATION,
                confidence=0.8,
            )
        )

    if attachment.oversized:
        findings.append(
            finding(
                MODULE,
                "attachment_oversized",
                "Attachment exceeds the inspection limit",
                Severity.MEDIUM,
                "The file is too large to inspect fully, so its contents could not be verified.",
                evidence=f"{attachment.filename} ({attachment.size} bytes)",
                recommendation=RECOMMENDATION,
                confidence=0.5,
            )
        )

    detected_mime = _detect_mime(attachment.payload or b"")
    record["detected_mime"] = detected_mime
    if detected_mime:
        declared = (attachment.mime_type or "").lower()
        if _is_blocked_mime(detected_mime) and not declared.startswith(
            EXECUTABLE_MIME_PREFIXES + ARCHIVE_MIME_PREFIXES
        ):
            findings.append(
                finding(
                    MODULE,
                    "content_type_mismatch",
                    "Attachment content does not match its declared type",
                    Severity.HIGH,
                    f"The file declares {declared or 'no type'} but its content is "
                    f"{detected_mime}. This is consistent with a disguised payload.",
                    evidence=attachment.filename,
                    recommendation=RECOMMENDATION,
                    confidence=0.75,
                )
            )
        elif (
            extension
            and declared
            and detected_mime != declared
            and extension in {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png"}
        ):
            record["type_mismatch"] = True

    scan_status, scan_result = await scan_payload(attachment.payload or b"", settings)
    record["clamav"] = {"status": scan_status, "result": scan_result}
    attachment.scan_status = ScanStatus(scan_status)
    attachment.scan_result = scan_result

    if scan_status == "MALICIOUS":
        findings.append(
            finding(
                MODULE,
                "malware_detected",
                "ClamAV detected malware in the attachment",
                Severity.CRITICAL,
                "The attachment was positively identified as malicious by the antivirus engine.",
                evidence=f"{attachment.filename}: {scan_result}",
                recommendation="Quarantine the attachment and do not open it under any circumstances.",
                confidence=0.95,
                metadata={"source": "clamav"},
            )
        )

    ti = get_threat_intelligence(settings)
    if attachment.sha256 and ti.virustotal_enabled:
        vt = await ti.virustotal_hash(attachment.sha256)
        record["virustotal"] = vt.to_dict()
        stats = vt.data.get("stats") if vt.available else None
        malicious = int(stats.get("malicious", 0)) if isinstance(stats, dict) else 0
        if malicious > 0:
            findings.append(
                finding(
                    MODULE,
                    "malicious_attachment_hash",
                    "Attachment hash is flagged by VirusTotal",
                    Severity.CRITICAL,
                    f"VirusTotal reports {malicious} engine(s) flagging this file hash.",
                    evidence=f"{attachment.filename} sha256={attachment.sha256}",
                    recommendation="Quarantine the attachment immediately.",
                    confidence=0.9,
                    metadata={"engine_detections": malicious, "source": "virustotal"},
                )
            )

    record["scan_status"] = scan_status
    return record


async def analyze(email: EmailObject, context: AnalysisContext) -> ModuleResult:
    started = time.monotonic()
    findings: list[Finding] = []
    records: list[dict] = []

    for attachment in email.attachments[:50]:
        try:
            records.append(await _analyze_attachment(attachment, context, findings))
        except Exception as exc:  # noqa: BLE001
            logger.exception("Attachment analysis failed for %s", attachment.filename)
            records.append(
                {"filename": attachment.filename, "error": type(exc).__name__}
            )

    return build_result(
        MODULE,
        started_at=started,
        findings=findings,
        data={
            "attachments_analyzed": len(records),
            "attachments": records,
            "clamav_enabled": context.settings.clamav_enabled,
        },
    )
