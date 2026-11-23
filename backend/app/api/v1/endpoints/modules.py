from __future__ import annotations

from fastapi import APIRouter

from app.core.config import settings
from app.core.version import __version__
from app.modules.registry import MODULE_CATALOG, ml_artifact_available, module_availability
from app.schemas.analysis import ConfigResponse, IntegrationAvailability, ModuleInfo

router = APIRouter(tags=["modules"])


@router.get("/modules", response_model=list[ModuleInfo])
async def list_modules() -> list[ModuleInfo]:
    modules: list[ModuleInfo] = []
    for entry in MODULE_CATALOG:
        available, reason = module_availability(entry)
        modules.append(
            ModuleInfo(
                name=entry.name,
                title=entry.title,
                description=entry.description,
                available=available,
                reason=reason,
            )
        )
    return modules


@router.get("/config", response_model=ConfigResponse)
async def get_config() -> ConfigResponse:
    return ConfigResponse(
        app_name=settings.app_name,
        app_env=settings.app_env,
        version=__version__,
        max_upload_bytes=settings.max_upload_bytes,
        max_attachment_bytes=settings.max_attachment_bytes,
        retention_days=settings.retention_days,
        module_timeout_seconds=settings.module_timeout_seconds,
        ml_available=ml_artifact_available(),
        integrations=IntegrationAvailability(
            url_fetch=settings.url_fetch_enabled,
            dns_lookups=settings.dns_lookups_enabled,
            rdap=settings.rdap_enabled,
            virustotal=bool(settings.virustotal_api_key),
            safe_browsing=bool(settings.google_safe_browsing_api_key),
            abuseipdb=bool(settings.abuseipdb_api_key),
            clamav=settings.clamav_enabled,
        ),
    )
