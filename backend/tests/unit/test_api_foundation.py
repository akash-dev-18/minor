from __future__ import annotations

import uuid

import pytest


async def test_health_reports_database(client):
    response = await client.get("/api/v1/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["database"] == "ok"
    assert body["version"]


async def test_ready(client):
    response = await client.get("/api/v1/ready")
    assert response.status_code == 200
    assert response.json()["ready"] is True


async def test_modules_catalog(client):
    response = await client.get("/api/v1/modules")
    assert response.status_code == 200
    modules = {item["name"]: item for item in response.json()}
    assert "email_parser" in modules
    assert "ml_classification" in modules
    assert modules["ml_classification"]["available"] is False
    assert modules["ml_classification"]["reason"]


async def test_analysis_history_pagination_shape(client):
    response = await client.get("/api/v1/analyses?page=1&page_size=2")
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body["items"], list)
    assert len(body["items"]) <= 2
    assert body["page"] == 1
    assert body["page_size"] == 2
    assert body["pages"] >= 1
    assert body["total"] >= len(body["items"])


async def test_missing_analysis_returns_structured_error(client):
    response = await client.get(f"/api/v1/analyses/{uuid.uuid4()}")
    assert response.status_code == 404
    body = response.json()
    assert body["error"]["code"] == "not_found"


async def test_delete_missing_analysis(client):
    response = await client.delete(f"/api/v1/analyses/{uuid.uuid4()}")
    assert response.status_code == 404


async def test_invalid_analysis_id(client):
    response = await client.get("/api/v1/analyses/not-a-uuid")
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


async def test_ml_status_is_honest(client):
    response = await client.get("/api/v1/ml/status")
    assert response.status_code == 200
    body = response.json()
    assert body["available"] is False
    assert body["reason"]
    assert body["model_version"] is None


async def test_ml_metrics_unavailable(client):
    response = await client.get("/api/v1/ml/metrics")
    assert response.status_code == 404
    assert response.json()["error"]["code"] in {"model_unavailable", "metrics_unavailable"}


async def test_config_exposes_safe_runtime_limits(client):
    response = await client.get("/api/v1/config")
    assert response.status_code == 200
    body = response.json()
    assert body["max_upload_bytes"] > 0
    assert body["retention_days"] > 0
    assert isinstance(body["ml_available"], bool)
    assert set(body["integrations"]) == {
        "url_fetch",
        "dns_lookups",
        "rdap",
        "virustotal",
        "safe_browsing",
        "abuseipdb",
        "clamav",
    }
    assert not any("key" in name for name in body)
