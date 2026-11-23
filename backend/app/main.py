from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import router as api_router
from app.core.config import settings
from app.core.errors import register_exception_handlers
from app.core.version import __version__
from app.database.session import engine
from app.services.analysis_orchestrator import (
    reconcile_interrupted_analyses,
    run_analysis,
)
from app.services.model_registry import sync_ml_model_versions
from app.services.runner import InProcessRunner

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncIterator[None]:
    settings.upload_path.mkdir(parents=True, exist_ok=True)
    settings.ml_artifact_path.mkdir(parents=True, exist_ok=True)
    logger.info("%s %s starting (env=%s)", settings.app_name, __version__, settings.app_env)
    await reconcile_interrupted_analyses()
    await sync_ml_model_versions()
    yield
    await application.state.runner.shutdown()
    await engine.dispose()
    logger.info("%s stopped", settings.app_name)


def create_app() -> FastAPI:
    application = FastAPI(
        title="Sentinel API",
        description="Intelligent email spam and phishing detection platform",
        version=__version__,
        lifespan=lifespan,
    )

    application.state.runner = InProcessRunner(run_analysis)

    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=False,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )

    register_exception_handlers(application)
    application.include_router(api_router, prefix=settings.api_prefix)

    @application.get("/", include_in_schema=False)
    async def root() -> dict[str, str]:
        return {
            "name": settings.app_name,
            "version": __version__,
            "docs": "/docs",
            "api": settings.api_prefix,
        }

    return application


app = create_app()
