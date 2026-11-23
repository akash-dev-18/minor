from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends

from app.core.version import __version__
from app.database.session import check_database
from app.schemas.analysis import HealthResponse

logger = logging.getLogger(__name__)
router = APIRouter(tags=["system"])


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    try:
        await check_database()
        database = "ok"
    except Exception as exc:  # noqa: BLE001
        logger.warning("Database health check failed: %s", exc)
        database = "unavailable"

    return HealthResponse(
        status="ok" if database == "ok" else "degraded",
        version=__version__,
        database=database,
        timestamp=datetime.now(timezone.utc),
    )
