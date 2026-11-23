from __future__ import annotations

from enum import StrEnum


class AnalysisStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    UNAVAILABLE = "UNAVAILABLE"


class Classification(StrEnum):
    LEGITIMATE = "LEGITIMATE"
    SPAM = "SPAM"
    PHISHING = "PHISHING"


class RiskLevel(StrEnum):
    LOW = "LOW"
    GUARDED = "GUARDED"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AuthStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    NEUTRAL = "neutral"
    NONE = "none"
    UNKNOWN = "unknown"
    NOT_VERIFIED = "not_verified"


class ModuleName(StrEnum):
    EMAIL_PARSER = "email_parser"
    URL_ANALYSIS = "url_analysis"
    DOMAIN_REPUTATION = "domain_reputation"
    HEADER_ANALYSIS = "header_analysis"
    CONTENT_ANALYSIS = "content_analysis"
    ATTACHMENT_ANALYSIS = "attachment_analysis"
    ML_CLASSIFICATION = "ml_classification"


class ScanStatus(StrEnum):
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    FAILED = "FAILED"
    UNAVAILABLE = "UNAVAILABLE"
    SKIPPED = "SKIPPED"
