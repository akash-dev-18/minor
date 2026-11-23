from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.enums import (
    AnalysisStatus,
    AuthStatus,
    Classification,
    ModuleName,
    RiskLevel,
    ScanStatus,
    Severity,
)


class Finding(BaseModel):
    type: str
    title: str
    severity: Severity
    description: str
    evidence: str | None = None
    recommendation: str | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    risk_contribution: int | None = Field(default=None, ge=0, le=100)
    source_module: ModuleName
    metadata: dict[str, Any] = Field(default_factory=dict)


class ModuleResult(BaseModel):
    module: ModuleName
    status: AnalysisStatus
    duration_ms: int = 0
    error: str | None = None
    findings: list[Finding] = Field(default_factory=list)
    data: dict[str, Any] = Field(default_factory=dict)


class EmailAttachment(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    filename: str
    mime_type: str
    size: int
    sha256: str | None = None
    scan_status: ScanStatus = ScanStatus.SKIPPED
    scan_result: str | None = None
    oversized: bool = False
    payload: bytes | None = Field(default=None, exclude=True, repr=False)


class EmailObject(BaseModel):
    sender: str | None = None
    sender_name: str | None = None
    reply_to: str | None = None
    return_path: str | None = None
    recipients: list[str] = Field(default_factory=list)
    subject: str = ""
    body_text: str = ""
    body_html: str | None = None
    headers: dict[str, list[str]] = Field(default_factory=dict)
    urls: list[str] = Field(default_factory=list)
    attachments: list[EmailAttachment] = Field(default_factory=list)
    raw_size: int = 0
    parse_defects: list[str] = Field(default_factory=list)


class AuthenticationResults(BaseModel):
    spf: AuthStatus = AuthStatus.NOT_VERIFIED
    dkim: AuthStatus = AuthStatus.NOT_VERIFIED
    dmarc: AuthStatus = AuthStatus.NOT_VERIFIED


class AnalysisModuleRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    module_name: ModuleName
    execution_status: AnalysisStatus
    execution_duration: int | None = None
    error_message: str | None = None
    result: dict[str, Any] | None = None


class AnalysisSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    original_filename: str
    sender: str | None = None
    subject: str | None = None
    classification: Classification | None = None
    risk_score: int | None = None
    risk_level: RiskLevel | None = None
    status: AnalysisStatus
    created_at: datetime
    completed_at: datetime | None = None


class AnalysisDetail(AnalysisSummary):
    modules: list[AnalysisModuleRead] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    authentication: AuthenticationResults | None = None
    recommendations: list[str] = Field(default_factory=list)
    explanation: str | None = None
    positives: list[str] = Field(default_factory=list)
    unknowns: list[dict[str, str]] = Field(default_factory=list)
    contributions: list[dict[str, Any]] = Field(default_factory=list)
    ml_prediction: dict[str, Any] | None = None
    assessment_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    error_message: str | None = None


class AnalysisStats(BaseModel):
    total: int = 0
    threats: int = 0
    last_24_hours: int = 0
    average_risk_score: float | None = None
    by_classification: dict[str, int] = Field(default_factory=dict)
    by_risk_level: dict[str, int] = Field(default_factory=dict)


class PaginatedAnalyses(BaseModel):
    items: list[AnalysisSummary]
    total: int
    page: int
    page_size: int
    pages: int


class AnalysisSubmission(BaseModel):
    analysis_id: UUID
    status: AnalysisStatus
    message: str


class IntegrationAvailability(BaseModel):
    url_fetch: bool
    dns_lookups: bool
    rdap: bool
    virustotal: bool
    safe_browsing: bool
    abuseipdb: bool
    clamav: bool


class ConfigResponse(BaseModel):
    app_name: str
    app_env: str
    version: str
    max_upload_bytes: int
    max_attachment_bytes: int
    retention_days: int
    module_timeout_seconds: float
    ml_available: bool
    integrations: IntegrationAvailability


class ModuleInfo(BaseModel):
    name: ModuleName
    title: str
    description: str
    available: bool
    reason: str | None = None


class HealthResponse(BaseModel):
    status: str
    version: str
    database: str
    timestamp: datetime


class ReadinessResponse(BaseModel):
    ready: bool
    checks: dict[str, bool]


class ApiErrorDetail(BaseModel):
    code: str
    message: str
    details: dict[str, Any] | None = None


class ApiError(BaseModel):
    error: ApiErrorDetail
