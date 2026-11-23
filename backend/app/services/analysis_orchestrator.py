from __future__ import annotations

import asyncio
import importlib
import logging
import time
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import delete, select

from app.database.session import SessionLocal
from app.models.analysis import Analysis
from app.models.attachment import Attachment
from app.models.finding import SecurityFinding
from app.models.module_result import AnalysisModule
from app.modules.base import AnalysisContext, build_result, failed
from app.modules.email_parser.parser import parse_email, summarize
from app.schemas.analysis import EmailObject, ModuleResult
from app.schemas.enums import AnalysisStatus, ModuleName
from app.services.risk_scoring import assess

logger = logging.getLogger(__name__)

MODULE_ENTRYPOINTS: tuple[tuple[ModuleName, str], ...] = (
    (ModuleName.URL_ANALYSIS, "app.modules.url_analysis.analyzer"),
    (ModuleName.DOMAIN_REPUTATION, "app.modules.domain_reputation.analyzer"),
    (ModuleName.HEADER_ANALYSIS, "app.modules.header_analysis.analyzer"),
    (ModuleName.CONTENT_ANALYSIS, "app.modules.content_analysis.analyzer"),
    (ModuleName.ATTACHMENT_ANALYSIS, "app.modules.attachment_analysis.analyzer"),
    (ModuleName.ML_CLASSIFICATION, "app.modules.ml_classification.classifier"),
)


async def _mark_failed(analysis_id: str, message: str) -> None:
    async with SessionLocal() as session:
        analysis = await session.get(Analysis, analysis_id)
        if analysis is None:
            return
        analysis.status = AnalysisStatus.FAILED.value
        analysis.error_message = message[:2000]
        analysis.completed_at = datetime.now(timezone.utc)
        await session.commit()


async def _save_module(session, analysis_id: str, result: ModuleResult) -> None:
    existing = await session.scalar(
        select(AnalysisModule).where(
            AnalysisModule.analysis_id == analysis_id,
            AnalysisModule.module_name == result.module.value,
        )
    )
    payload = result.model_dump(mode="json")
    if existing is None:
        session.add(
            AnalysisModule(
                analysis_id=analysis_id,
                module_name=result.module.value,
                execution_status=result.status.value,
                execution_duration=result.duration_ms,
                error_message=result.error,
                result=payload,
            )
        )
    else:
        existing.execution_status = result.status.value
        existing.execution_duration = result.duration_ms
        existing.error_message = result.error
        existing.result = payload


async def _run_module(
    name: ModuleName,
    entrypoint: str,
    email: EmailObject,
    context: AnalysisContext,
    timeout: float,
) -> ModuleResult:
    started = time.monotonic()
    try:
        module = importlib.import_module(entrypoint)
        analyze = getattr(module, "analyze")
        return await asyncio.wait_for(analyze(email, context), timeout=timeout)
    except TimeoutError:
        logger.warning("Module %s timed out after %.1fs", name.value, timeout)
        return failed(name, f"Module exceeded the {timeout:.0f}s timeout", started)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Module %s failed", name.value)
        return failed(name, f"Module crashed: {type(exc).__name__}", started)


async def run_analysis(analysis_id: str) -> None:
    async with SessionLocal() as session:
        analysis = await session.get(Analysis, analysis_id)
        if analysis is None:
            logger.warning("Analysis %s not found", analysis_id)
            return
        if not analysis.stored_path:
            await _mark_failed(analysis_id, "Stored email file is missing")
            return
        analysis.status = AnalysisStatus.RUNNING.value
        stored_path = analysis.stored_path
        await session.commit()

    try:
        raw = await asyncio.to_thread(Path(stored_path).read_bytes)
    except OSError as exc:
        logger.warning("Could not read stored email %s: %s", stored_path, exc)
        await _mark_failed(analysis_id, "Stored email file could not be read")
        return

    started_at = time.monotonic()
    try:
        email = parse_email(raw)
        parser_result = build_result(
            ModuleName.EMAIL_PARSER,
            started_at=started_at,
            data=summarize(email),
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("Email parsing crashed for %s", analysis_id)
        await _mark_failed(analysis_id, f"Email parsing failed: {type(exc).__name__}")
        return

    from app.core.config import settings

    context = AnalysisContext(analysis_id=analysis_id)
    module_results = await asyncio.gather(
        *[
            _run_module(name, entrypoint, email, context, settings.module_timeout_seconds)
            for name, entrypoint in MODULE_ENTRYPOINTS
        ]
    )
    all_results = [parser_result, *module_results]
    assessment = assess(module_results, email)

    try:
        async with SessionLocal() as session:
            analysis = await session.get(Analysis, analysis_id)
            if analysis is None:
                return
            analysis.sender = email.sender
            analysis.subject = email.subject or None
            analysis.error_message = None
            analysis.status = AnalysisStatus.COMPLETED.value
            analysis.completed_at = datetime.now(timezone.utc)
            analysis.classification = assessment.classification.value
            analysis.risk_score = assessment.risk_score
            analysis.risk_level = assessment.risk_level.value
            analysis.report = assessment.report

            for result in all_results:
                await _save_module(session, analysis_id, result)

            await session.execute(
                delete(SecurityFinding).where(SecurityFinding.analysis_id == analysis_id)
            )
            contribution_index = 0
            for result in module_results:
                for item in result.findings:
                    contribution = (
                        assessment.finding_contributions[contribution_index]
                        if contribution_index < len(assessment.finding_contributions)
                        else 0
                    )
                    contribution_index += 1
                    session.add(
                        SecurityFinding(
                            analysis_id=analysis_id,
                            module_name=item.source_module.value,
                            finding_type=item.type,
                            title=item.title,
                            severity=item.severity.value,
                            confidence=item.confidence,
                            evidence=item.evidence,
                            description=item.description,
                            recommendation=item.recommendation,
                            risk_contribution=contribution,
                            metadata_json=item.metadata,
                        )
                    )

            await session.execute(
                delete(Attachment).where(Attachment.analysis_id == analysis_id)
            )
            for index, attachment in enumerate(email.attachments):
                session.add(
                    Attachment(
                        analysis_id=analysis_id,
                        filename=attachment.filename,
                        mime_type=attachment.mime_type,
                        file_size=attachment.size,
                        sha256_hash=attachment.sha256,
                        scan_status=attachment.scan_status.value,
                        scan_result=(
                            {"detail": attachment.scan_result} if attachment.scan_result else None
                        ),
                    )
                )

            await session.commit()
    except Exception as exc:  # noqa: BLE001
        logger.exception("Persisting analysis %s failed", analysis_id)
        await _mark_failed(analysis_id, f"Persisting analysis failed: {type(exc).__name__}")
        return

    logger.info("Analysis %s completed", analysis_id)


async def reconcile_interrupted_analyses() -> None:
    async with SessionLocal() as session:
        result = await session.execute(
            select(Analysis).where(
                Analysis.status.in_(
                    [AnalysisStatus.PENDING.value, AnalysisStatus.RUNNING.value]
                )
            )
        )
        interrupted = result.scalars().all()
        if not interrupted:
            return
        for analysis in interrupted:
            analysis.status = AnalysisStatus.FAILED.value
            analysis.error_message = "Interrupted by application restart"
            analysis.completed_at = datetime.now(timezone.utc)
        await session.commit()
        logger.info("Reconciled %s interrupted analyses", len(interrupted))
