from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

from app.core.config import Settings, settings
from app.schemas.analysis import Finding, ModuleResult
from app.schemas.enums import AnalysisStatus, ModuleName, Severity

logger = logging.getLogger(__name__)

SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFORMATIONAL: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def finding(
    module: ModuleName,
    finding_type: str,
    title: str,
    severity: Severity,
    description: str,
    *,
    evidence: str | None = None,
    recommendation: str | None = None,
    confidence: float | None = None,
    metadata: dict[str, Any] | None = None,
) -> Finding:
    return Finding(
        type=finding_type,
        title=title,
        severity=severity,
        description=description,
        evidence=evidence[:2000] if evidence else None,
        recommendation=recommendation,
        confidence=confidence,
        source_module=module,
        metadata=metadata or {},
    )


@dataclass(frozen=True)
class AnalysisContext:
    analysis_id: str
    settings: Settings = field(default_factory=lambda: settings)


def build_result(
    module: ModuleName,
    *,
    status: AnalysisStatus = AnalysisStatus.COMPLETED,
    started_at: float | None = None,
    findings: list[Finding] | None = None,
    data: dict[str, Any] | None = None,
    error: str | None = None,
) -> ModuleResult:
    duration_ms = int((time.monotonic() - started_at) * 1000) if started_at else 0
    return ModuleResult(
        module=module,
        status=status,
        duration_ms=duration_ms,
        findings=findings or [],
        data=data or {},
        error=error,
    )


def unavailable(module: ModuleName, reason: str) -> ModuleResult:
    return ModuleResult(
        module=module,
        status=AnalysisStatus.UNAVAILABLE,
        error=reason,
    )


def failed(module: ModuleName, reason: str, started_at: float | None = None) -> ModuleResult:
    return build_result(
        module,
        status=AnalysisStatus.FAILED,
        error=reason[:2000],
        started_at=started_at,
    )
