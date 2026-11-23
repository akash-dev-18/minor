from __future__ import annotations

import asyncio
import logging
import math
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, File, Query, Request, Response, UploadFile, status
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.errors import APIError
from app.database.session import get_session
from app.models.analysis import Analysis
from app.models.finding import SecurityFinding
from app.models.module_result import AnalysisModule
from app.schemas.analysis import (
    AnalysisDetail,
    AnalysisStats,
    AnalysisModuleRead,
    AnalysisSubmission,
    AnalysisSummary,
    AuthenticationResults,
    Finding,
    PaginatedAnalyses,
)
from app.schemas.enums import AnalysisStatus, Classification, RiskLevel
from app.services.storage import store_email
from app.services.upload_validation import validate_upload

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/analyses", tags=["analyses"])


def _to_finding(model: SecurityFinding) -> Finding:
    return Finding(
        type=model.finding_type,
        title=model.title,
        severity=model.severity,  # type: ignore[arg-type]
        description=model.description,
        evidence=model.evidence,
        recommendation=model.recommendation,
        confidence=model.confidence,
        risk_contribution=model.risk_contribution,
        source_module=model.module_name,  # type: ignore[arg-type]
        metadata=model.metadata_json or {},
    )


def _authentication(analysis: Analysis) -> AuthenticationResults | None:
    for module in analysis.modules:
        if module.module_name != "header_analysis" or not module.result:
            continue
        auth = module.result.get("authentication")
        if auth is None and isinstance(module.result.get("data"), dict):
            auth = module.result["data"].get("authentication")
        if isinstance(auth, dict):
            try:
                return AuthenticationResults(**auth)
            except Exception:  # noqa: BLE001
                return None
    return None


def _to_detail(analysis: Analysis) -> AnalysisDetail:
    report: dict[str, Any] = analysis.report or {}
    return AnalysisDetail(
        id=UUID(analysis.id),
        original_filename=analysis.original_filename,
        sender=analysis.sender,
        subject=analysis.subject,
        classification=analysis.classification,
        risk_score=analysis.risk_score,
        risk_level=analysis.risk_level,
        status=analysis.status,
        created_at=analysis.created_at,
        completed_at=analysis.completed_at,
        error_message=analysis.error_message,
        modules=[
            AnalysisModuleRead(
                id=UUID(module.id),
                module_name=module.module_name,
                execution_status=module.execution_status,
                execution_duration=module.execution_duration,
                error_message=module.error_message,
                result=module.result,
            )
            for module in analysis.modules
        ],
        findings=[_to_finding(finding) for finding in analysis.findings],
        authentication=_authentication(analysis),
        recommendations=list(report.get("recommendations") or []),
        explanation=report.get("explanation"),
        positives=list(report.get("positives") or []),
        unknowns=list(report.get("unknowns") or []),
        contributions=list(report.get("contributions") or []),
        ml_prediction=report.get("ml_prediction"),
        assessment_confidence=report.get("assessment_confidence"),
    )


@router.get("", response_model=PaginatedAnalyses)
async def list_analyses(
    session: Annotated[AsyncSession, Depends(get_session)],
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
    q: Annotated[str | None, Query(max_length=200)] = None,
    classification: Annotated[Classification | None, Query()] = None,
    risk_level: Annotated[RiskLevel | None, Query()] = None,
    sort: Annotated[str, Query(pattern="^(created_at|risk_score)$")] = "created_at",
    order: Annotated[str, Query(pattern="^(asc|desc)$")] = "desc",
) -> PaginatedAnalyses:
    filters = []
    if q:
        pattern = f"%{q.lower()}%"
        filters.append(
            or_(
                func.lower(Analysis.sender).like(pattern),
                func.lower(Analysis.subject).like(pattern),
            )
        )
    if classification:
        filters.append(Analysis.classification == classification.value)
    if risk_level:
        filters.append(Analysis.risk_level == risk_level.value)

    count_stmt = select(func.count()).select_from(Analysis).where(*filters)
    total = int((await session.execute(count_stmt)).scalar_one())

    sort_column = Analysis.created_at if sort == "created_at" else Analysis.risk_score
    sort_column = sort_column.desc() if order == "desc" else sort_column.asc()

    stmt = (
        select(Analysis)
        .where(*filters)
        .order_by(sort_column)
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    result = await session.execute(stmt)
    analyses = result.scalars().all()

    return PaginatedAnalyses(
        items=[AnalysisSummary.model_validate(a) for a in analyses],
        total=total,
        page=page,
        page_size=page_size,
        pages=max(1, math.ceil(total / page_size)),
    )


@router.post("", response_model=AnalysisSubmission, status_code=status.HTTP_202_ACCEPTED)
async def submit_analysis(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
    file: Annotated[UploadFile, File()],
) -> AnalysisSubmission:
    filename = Path(file.filename or "").name

    chunks: list[bytes] = []
    total = 0
    try:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > settings.max_upload_bytes:
                raise APIError(
                    413,
                    "file_too_large",
                    f"File exceeds the {settings.max_upload_bytes} byte limit",
                )
            chunks.append(chunk)
    finally:
        await file.close()

    raw = b"".join(chunks)
    validate_upload(raw, filename)

    stored_path, digest = await asyncio.to_thread(store_email, raw)

    analysis = Analysis(
        original_filename=filename,
        stored_path=str(stored_path),
        file_size=len(raw),
        raw_sha256=digest,
        status=AnalysisStatus.PENDING.value,
    )
    session.add(analysis)
    await session.commit()
    await session.refresh(analysis)

    runner = getattr(request.app.state, "runner", None)
    if runner is None:
        analysis.status = AnalysisStatus.FAILED.value
        analysis.error_message = "Analysis runner is not available"
        await session.commit()
        raise APIError(503, "runner_unavailable", "Analysis runner is not available")

    try:
        runner.submit(analysis.id)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Could not enqueue analysis %s", analysis.id)
        analysis.status = AnalysisStatus.FAILED.value
        analysis.error_message = "Could not enqueue analysis"
        await session.commit()
        raise APIError(503, "enqueue_failed", "Analysis could not be started") from exc

    return AnalysisSubmission(
        analysis_id=UUID(analysis.id),
        status=AnalysisStatus.PENDING,
        message="Email submitted for security analysis",
    )


@router.get("/stats", response_model=AnalysisStats)
async def get_analysis_stats(
    session: Annotated[AsyncSession, Depends(get_session)],
) -> AnalysisStats:
    total = int((await session.execute(select(func.count()).select_from(Analysis))).scalar_one())

    classification_rows = await session.execute(
        select(Analysis.classification, func.count()).group_by(Analysis.classification)
    )
    by_classification = {value: 0 for value in Classification}
    for label, count in classification_rows.all():
        if label:
            by_classification[label] = int(count)

    risk_rows = await session.execute(
        select(Analysis.risk_level, func.count()).group_by(Analysis.risk_level)
    )
    by_risk_level = {value: 0 for value in RiskLevel}
    for label, count in risk_rows.all():
        if label:
            by_risk_level[label] = int(count)

    average = (
        await session.execute(
            select(func.avg(Analysis.risk_score)).where(Analysis.risk_score.is_not(None))
        )
    ).scalar_one()
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    last_24_hours = int(
        (
            await session.execute(
                select(func.count()).select_from(Analysis).where(Analysis.created_at >= since)
            )
        ).scalar_one()
    )

    return AnalysisStats(
        total=total,
        threats=by_classification.get(Classification.PHISHING.value, 0),
        last_24_hours=last_24_hours,
        average_risk_score=round(float(average), 1) if average is not None else None,
        by_classification=by_classification,
        by_risk_level=by_risk_level,
    )


@router.get("/{analysis_id}", response_model=AnalysisDetail)
async def get_analysis(
    analysis_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> AnalysisDetail:
    analysis = await session.get(Analysis, str(analysis_id))
    if analysis is None:
        raise APIError(status.HTTP_404_NOT_FOUND, "not_found", "Analysis not found")
    return _to_detail(analysis)


@router.delete(
    "/{analysis_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
)
async def delete_analysis(
    analysis_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Response:
    analysis = await session.get(Analysis, str(analysis_id))
    if analysis is None:
        raise APIError(status.HTTP_404_NOT_FOUND, "not_found", "Analysis not found")

    if analysis.stored_path:
        stored = Path(analysis.stored_path)
        try:
            if stored.is_file() and stored.resolve().is_relative_to(settings.upload_path.resolve()):
                stored.unlink()
        except OSError as exc:
            logger.warning("Could not delete stored email %s: %s", stored, exc)

    await session.delete(analysis)
    await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
