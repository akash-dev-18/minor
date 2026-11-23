from __future__ import annotations

import asyncio
from pathlib import Path

from sqlalchemy import select

from app.core.config import settings
from app.database.session import SessionLocal
from app.models.analysis import Analysis

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "emails"


def load(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


async def wait_for_completion(client, analysis_id: str, timeout: float = 5.0) -> dict:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        response = await client.get(f"/api/v1/analyses/{analysis_id}")
        assert response.status_code == 200
        body = response.json()
        if body["status"] in {"COMPLETED", "FAILED"}:
            return body
        await asyncio.sleep(0.02)
    raise AssertionError(f"Analysis {analysis_id} did not finish in time")


async def submit(client, content: bytes, filename: str = "sample.eml"):
    return await client.post(
        "/api/v1/analyses",
        files={"file": (filename, content, "message/rfc822")},
    )


async def test_upload_and_analysis_flow(client):
    response = await submit(client, load("simple.eml"))
    assert response.status_code == 202
    submission = response.json()
    assert submission["status"] == "PENDING"

    detail = await wait_for_completion(client, submission["analysis_id"])
    assert detail["status"] == "COMPLETED"
    assert detail["sender"] == "alice@example.com"
    assert detail["subject"] == "Quarterly report"
    assert detail["classification"] in {"PHISHING", "SPAM", "LEGITIMATE"}
    assert 0 <= detail["risk_score"] <= 100
    assert detail["risk_level"] in {"LOW", "GUARDED", "MEDIUM", "HIGH", "CRITICAL"}
    assert detail["explanation"]

    modules = {module["module_name"]: module for module in detail["modules"]}
    assert modules["email_parser"]["execution_status"] == "COMPLETED"
    parser_data = modules["email_parser"]["result"]["data"]
    assert parser_data["url_count"] == 2
    assert "body_text" not in parser_data

    async with SessionLocal() as session:
        stored = await session.scalar(
            select(Analysis).where(Analysis.id == submission["analysis_id"])
        )
        stored_path = Path(stored.stored_path)
    assert stored_path.is_file()

    deleted = await client.delete(f"/api/v1/analyses/{submission['analysis_id']}")
    assert deleted.status_code == 204
    assert not stored_path.exists()

    missing = await client.get(f"/api/v1/analyses/{submission['analysis_id']}")
    assert missing.status_code == 404


async def test_upload_with_attachment_records_metadata(client):
    response = await submit(client, load("attachment.eml"))
    assert response.status_code == 202
    detail = await wait_for_completion(client, response.json()["analysis_id"])

    assert detail["status"] == "COMPLETED"
    assert detail["modules"][0]["result"]["data"]["attachment_count"] == 1


async def test_malformed_email_is_accepted_and_parsed(client):
    response = await submit(client, load("malformed.eml"))
    assert response.status_code == 202
    detail = await wait_for_completion(client, response.json()["analysis_id"])

    assert detail["status"] == "COMPLETED"
    assert detail["sender"] == "broken@example.com"


async def test_rejects_non_eml_extension(client):
    response = await submit(client, b"hello", filename="notes.txt")
    assert response.status_code == 415
    assert response.json()["error"]["code"] == "unsupported_file_type"


async def test_rejects_binary_content(client):
    response = await submit(client, b"\x00\x01\x02binary payload", filename="fake.eml")
    assert response.status_code == 415
    assert response.json()["error"]["code"] == "unsupported_file_type"


async def test_rejects_empty_file(client):
    response = await submit(client, b"", filename="empty.eml")
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "empty_file"


async def test_rejects_oversized_file(client, monkeypatch):
    monkeypatch.setattr(settings, "max_upload_bytes", 200)
    response = await submit(client, load("simple.eml"))
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "file_too_large"


async def test_phishing_email_produces_findings_from_modules(client):
    response = await submit(client, load("phishing_html.eml"))
    assert response.status_code == 202
    detail = await wait_for_completion(client, response.json()["analysis_id"])

    assert detail["status"] == "COMPLETED"
    module_status = {m["module_name"]: m["execution_status"] for m in detail["modules"]}
    assert module_status["url_analysis"] == "COMPLETED"
    assert module_status["domain_reputation"] == "COMPLETED"
    assert module_status["header_analysis"] == "COMPLETED"
    assert module_status["content_analysis"] == "COMPLETED"
    assert module_status["attachment_analysis"] == "COMPLETED"
    assert module_status["ml_classification"] == "UNAVAILABLE"

    finding_types = {finding["type"] for finding in detail["findings"]}
    assert "ip_address_url" in finding_types
    assert "password_form" in finding_types
    assert "display_name_impersonation" in finding_types
    assert detail["recommendations"]

    assert detail["classification"] == "PHISHING"
    assert detail["risk_score"] >= 40
    assert detail["contributions"]
    assert detail["positives"]


async def test_stats_reflect_completed_analyses(client):
    response = await submit(client, load("phishing_html.eml"))
    await wait_for_completion(client, response.json()["analysis_id"])

    stats = (await client.get("/api/v1/analyses/stats")).json()
    assert stats["total"] >= 1
    assert stats["threats"] >= 1
    assert stats["by_classification"]["PHISHING"] >= 1
    assert set(stats["by_risk_level"]) == {"LOW", "GUARDED", "MEDIUM", "HIGH", "CRITICAL"}
    assert stats["average_risk_score"] is not None
