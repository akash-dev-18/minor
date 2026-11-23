from __future__ import annotations

from app.modules.base import AnalysisContext
from app.schemas.enums import AnalysisStatus, ModuleName
from app.services.analysis_orchestrator import _run_module
from tests.helpers import make_email


async def test_module_crash_is_contained():
    result = await _run_module(
        ModuleName.URL_ANALYSIS,
        "app.modules.url_analysis.does_not_exist",
        make_email(),
        AnalysisContext(analysis_id="x"),
        5.0,
    )

    assert result.status == AnalysisStatus.FAILED
    assert result.module == ModuleName.URL_ANALYSIS
    assert result.error
