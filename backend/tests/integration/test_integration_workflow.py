from __future__ import annotations

import asyncio
from pathlib import Path

from sqlalchemy import func, select

from app.core.config import settings
from app.database.session import SessionLocal
from app.models.analysis import Analysis
from app.models.attachment import Attachment
from app.models.finding import SecurityFinding
from app.models.module_result import AnalysisModule
from tests.integration.test_analysis_upload import load, submit, wait_for_completion


async def test_module_timeout_yields_partial_report(client, monkeypatch):
    from app.modules.url_analysis import analyzer

    original = analyzer.analyze

    async def slow(*args, **kwargs):
        await asyncio.sleep(2)
        return await original(*args, **kwargs)

    monkeypatch.setattr(analyzer, "analyze", slow)
    monkeypatch.setattr(settings, "module_timeout_seconds", 0.25)

    response = await submit(client, load("simple.eml"))
    detail = await wait_for_completion(client, response.json()["analysis_id"], timeout=8)

    assert detail["status"] == "COMPLETED"
    modules = {module["module_name"]: module for module in detail["modules"]}
    assert modules["url_analysis"]["execution_status"] == "FAILED"
    assert "timeout" in (modules["url_analysis"]["error_message"] or "").lower()
    assert modules["content_analysis"]["execution_status"] == "COMPLETED"
    assert modules["email_parser"]["execution_status"] == "COMPLETED"

    unknowns = {item["module"]: item["status"] for item in detail["unknowns"]}
    assert unknowns["url_analysis"] == "FAILED"
    assert detail["risk_score"] is not None
    assert "unknown" in detail["explanation"].lower()


async def test_delete_removes_file_and_dependent_rows(client):
    response = await submit(client, load("phishing_html.eml"))
    analysis_id = response.json()["analysis_id"]
    await wait_for_completion(client, analysis_id)

    async with SessionLocal() as session:
        analysis = await session.get(Analysis, analysis_id)
        assert analysis is not None and analysis.stored_path
        stored = Path(analysis.stored_path)
        assert stored.is_file()

    deleted = await client.delete(f"/api/v1/analyses/{analysis_id}")
    assert deleted.status_code == 204
    assert not stored.exists()

    assert (await client.get(f"/api/v1/analyses/{analysis_id}")).status_code == 404

    async with SessionLocal() as session:
        assert await session.get(Analysis, analysis_id) is None
        for model in (AnalysisModule, SecurityFinding, Attachment):
            count = await session.scalar(
                select(func.count())
                .select_from(model)
                .where(model.analysis_id == analysis_id)
            )
            assert count == 0


async def test_stats_match_database_contents(client):
    response = await client.get("/api/v1/analyses/stats")
    assert response.status_code == 200
    stats = response.json()

    async with SessionLocal() as session:
        total = await session.scalar(select(func.count()).select_from(Analysis))
        phishing = await session.scalar(
            select(func.count())
            .select_from(Analysis)
            .where(Analysis.classification == "PHISHING")
        )
        assert stats["total"] == total
        assert stats["threats"] == phishing
        assert sum(stats["by_classification"].values()) <= total
        assert sum(stats["by_risk_level"].values()) <= total
