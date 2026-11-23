from __future__ import annotations

import importlib.util
from dataclasses import dataclass

from app.core.config import settings
from app.schemas.enums import ModuleName


@dataclass(frozen=True)
class ModuleCatalogEntry:
    name: ModuleName
    title: str
    description: str
    entrypoint: str
    requires_ml_artifact: bool = False


MODULE_CATALOG: tuple[ModuleCatalogEntry, ...] = (
    ModuleCatalogEntry(
        name=ModuleName.EMAIL_PARSER,
        title="Email Parser",
        description="Parses MIME emails and extracts normalized message data.",
        entrypoint="app.modules.email_parser.parser",
    ),
    ModuleCatalogEntry(
        name=ModuleName.URL_ANALYSIS,
        title="URL Analysis",
        description="Detects suspicious and malicious URLs, redirects and obfuscation.",
        entrypoint="app.modules.url_analysis.analyzer",
    ),
    ModuleCatalogEntry(
        name=ModuleName.DOMAIN_REPUTATION,
        title="Domain Reputation",
        description="Inspects sender domains: DNS, registration, lookalikes and SPF records.",
        entrypoint="app.modules.domain_reputation.analyzer",
    ),
    ModuleCatalogEntry(
        name=ModuleName.HEADER_ANALYSIS,
        title="Header Analysis",
        description="Examines routing metadata and interprets SPF, DKIM and DMARC claims.",
        entrypoint="app.modules.header_analysis.analyzer",
    ),
    ModuleCatalogEntry(
        name=ModuleName.CONTENT_ANALYSIS,
        title="Content Analysis",
        description="Identifies social engineering language and suspicious HTML patterns.",
        entrypoint="app.modules.content_analysis.analyzer",
    ),
    ModuleCatalogEntry(
        name=ModuleName.ATTACHMENT_ANALYSIS,
        title="Attachment Analysis",
        description="Identifies dangerous attachments, extension mismatches and hashes files.",
        entrypoint="app.modules.attachment_analysis.analyzer",
    ),
    ModuleCatalogEntry(
        name=ModuleName.ML_CLASSIFICATION,
        title="ML Classification",
        description="Classifies emails as legitimate, spam or phishing using a trained model.",
        entrypoint="app.modules.ml_classification.classifier",
        requires_ml_artifact=True,
    ),
)


def ml_artifact_available() -> bool:
    root = settings.ml_artifact_path
    if settings.ml_active_version:
        return (root / settings.ml_active_version / "pipeline.joblib").is_file()
    return any((p / "pipeline.joblib").is_file() for p in root.glob("*") if p.is_dir())


def module_availability(entry: ModuleCatalogEntry) -> tuple[bool, str | None]:
    try:
        if importlib.util.find_spec(entry.entrypoint) is None:
            return False, "Module is not implemented yet"
    except ModuleNotFoundError:
        return False, "Module is not implemented yet"
    if entry.requires_ml_artifact and not ml_artifact_available():
        return False, "No trained model artifact is available"
    return True, None
