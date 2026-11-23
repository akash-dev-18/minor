from __future__ import annotations

from app.modules.ml_classification.classifier import analyze
from app.schemas.enums import AnalysisStatus
from tests.helpers import context, make_email


async def test_missing_model_reports_unavailable_not_a_prediction():
    result = await analyze(make_email(), context())

    assert result.status == AnalysisStatus.UNAVAILABLE
    assert result.error and "model" in result.error.lower()
    assert result.data == {}
    assert result.findings == []
