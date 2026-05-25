"""Тесты эндпоинта /api/v1/internal/ingest."""
import pytest
from httpx import AsyncClient

from app.core.config import settings


INGEST_URL = "/api/v1/internal/ingest"
HEADERS = {"Authorization": f"Bearer {settings.INTERNAL_API_SECRET}"}


def _event_payload(**kwargs) -> dict:
    base = {
        "event_type": "subdomain",
        "severity": "info",
        "source_type": "subfinder",
        "source_name": "subfinder-v2.6",
        "target_domain": "example.com",
        "payload": {"subdomain": "api.example.com", "ip": "1.2.3.4"},
    }
    base.update(kwargs)
    return base


@pytest.mark.asyncio
async def test_ingest_accepts_valid_event(client: AsyncClient):
    resp = await client.post(INGEST_URL, json=_event_payload(), headers=HEADERS)
    assert resp.status_code == 202
    data = resp.json()
    assert data["status"] == "accepted"
    assert "event_id" in data


@pytest.mark.asyncio
async def test_ingest_deduplicates_identical_event(client: AsyncClient):
    payload = _event_payload(target_domain="dup.example.com")
    r1 = await client.post(INGEST_URL, json=payload, headers=HEADERS)
    r2 = await client.post(INGEST_URL, json=payload, headers=HEADERS)
    assert r1.status_code == 202
    assert r2.status_code == 202
    assert r1.json()["status"] == "accepted"
    assert r2.json()["status"] == "duplicate"


@pytest.mark.asyncio
async def test_ingest_rejects_wrong_secret(client: AsyncClient):
    resp = await client.post(
        INGEST_URL,
        json=_event_payload(),
        headers={"Authorization": "Bearer wrong-secret"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_ingest_rejects_missing_auth(client: AsyncClient):
    resp = await client.post(INGEST_URL, json=_event_payload())
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_ingest_rejects_invalid_severity(client: AsyncClient):
    resp = await client.post(
        INGEST_URL,
        json=_event_payload(severity="EXTREME"),
        headers=HEADERS,
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_ingest_rejects_empty_domain(client: AsyncClient):
    resp = await client.post(
        INGEST_URL,
        json=_event_payload(target_domain=""),
        headers=HEADERS,
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_ingest_different_payloads_not_deduplicated(client: AsyncClient):
    r1 = await client.post(
        INGEST_URL,
        json=_event_payload(payload={"subdomain": "a.example.com"}),
        headers=HEADERS,
    )
    r2 = await client.post(
        INGEST_URL,
        json=_event_payload(payload={"subdomain": "b.example.com"}),
        headers=HEADERS,
    )
    assert r1.json()["status"] == "accepted"
    assert r2.json()["status"] == "accepted"
