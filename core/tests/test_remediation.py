"""
Тесты Phase 11.D — Remediation Hints.

Покрывает:
- Функции модуля workers/tasks/remediation_hints.py
- GET /api/v1/events/{id}/hints
- PATCH /api/v1/events/{id}/resolve
- Проверка авторизации
"""
import sys
import uuid
from pathlib import Path

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.asset import Asset
from app.models.event import Event
from app.models.organization import Organization, OrgPlan
from app.models.user import User

# Добавляем workers/ в sys.path для импорта remediation_hints
_workers_path = str(Path(__file__).parents[3] / "workers")
if _workers_path not in sys.path:
    sys.path.insert(0, _workers_path)

from tasks.remediation_hints import DEFAULT_HINTS, get_hints, enrich_event_with_hints

INGEST_URL = "/api/v1/internal/ingest"
INGEST_HEADERS = {"Authorization": f"Bearer {settings.INTERNAL_API_SECRET}"}


# ─── Фикстуры ────────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def org_and_asset(db_session: AsyncSession, superuser: User):
    """Организация + актив test.com, superuser привязан к организации."""
    uid = uuid.uuid4().hex[:8]
    org = Organization(
        name=f"Remediation Org {uid}",
        slug=f"remediation-org-{uid}",
        plan=OrgPlan.professional.value,
    )
    db_session.add(org)
    await db_session.flush()

    superuser.organization_id = org.id
    await db_session.flush()

    asset = Asset(
        domain=f"remediation-{uid}.com",
        description=f"Remediation Asset {uid}",
        organization_id=org.id,
        is_active=True,
    )
    db_session.add(asset)
    await db_session.commit()
    await db_session.refresh(asset)
    return org, asset


@pytest_asyncio.fixture
async def event_via_ingest(
    client: AsyncClient,
    superuser_token: str,
    org_and_asset,
):
    """Создаёт событие port_scan через ingest эндпоинт."""
    _, asset = org_and_asset
    domain = asset.domain

    resp = await client.post(
        INGEST_URL,
        json={
            "event_type": "port_scan",
            "severity": "high",
            "source_type": "scanner",
            "source_name": "nmap",
            "target_domain": domain,
            "payload": {"port": 22, "service": "SSH"},
        },
        headers=INGEST_HEADERS,
    )
    assert resp.status_code == 202, f"Ingest вернул {resp.status_code}: {resp.text}"
    data = resp.json()
    assert data["status"] == "accepted"
    return data


@pytest_asyncio.fixture
async def event_in_db(db_session: AsyncSession, org_and_asset):
    """Создаёт событие напрямую в БД для тестов resolve."""
    _, asset = org_and_asset
    ev = Event(
        event_type="port_scan",
        severity="high",
        source_type="scanner",
        source_name="nmap",
        target_domain=asset.domain,
        payload={"port": 22, "service": "SSH"},
        asset_id=asset.id,
    )
    db_session.add(ev)
    await db_session.commit()
    await db_session.refresh(ev)
    return ev


# ─── Unit-тесты модуля remediation_hints ─────────────────────────────────────

def test_get_hints_for_port_scan():
    """get_hints("port_scan") возвращает непустой список."""
    hints = get_hints("port_scan")
    assert isinstance(hints, list)
    assert len(hints) > 0


def test_get_hints_for_unknown_type():
    """get_hints с неизвестным типом возвращает DEFAULT_HINTS."""
    hints = get_hints("totally_unknown_event_type_xyz")
    assert hints == DEFAULT_HINTS
    assert len(hints) > 0


def test_enrich_event_with_hints():
    """enrich_event_with_hints добавляет поле remediation_hints."""
    original = {"event_type": "port_scan", "severity": "high", "id": "test-123"}
    enriched = enrich_event_with_hints(original)

    # Поле добавлено
    assert "remediation_hints" in enriched
    assert isinstance(enriched["remediation_hints"], list)
    assert len(enriched["remediation_hints"]) > 0

    # Оригинал не мутирован
    assert "remediation_hints" not in original

    # Остальные поля сохранены
    assert enriched["event_type"] == "port_scan"
    assert enriched["severity"] == "high"
    assert enriched["id"] == "test-123"


def test_enrich_event_with_hints_unknown_type():
    """enrich_event_with_hints с неизвестным типом использует DEFAULT_HINTS."""
    original = {"event_type": "unknown_type", "id": "abc"}
    enriched = enrich_event_with_hints(original)
    assert enriched["remediation_hints"] == DEFAULT_HINTS


# ─── API-тесты: GET /events/{id}/hints ───────────────────────────────────────

@pytest.mark.asyncio
async def test_hints_endpoint_returns_hints(
    client: AsyncClient,
    superuser_token: str,
    event_in_db: Event,
):
    """GET /api/v1/events/{id}/hints возвращает 200 с непустым списком hints."""
    resp = await client.get(
        f"/api/v1/events/{event_in_db.id}/hints",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 200, f"Ответ: {resp.text}"
    data = resp.json()
    assert data["event_type"] == "port_scan"
    assert "hints" in data
    assert isinstance(data["hints"], list)
    assert len(data["hints"]) > 0


@pytest.mark.asyncio
async def test_hints_endpoint_requires_auth(
    client: AsyncClient,
    event_in_db: Event,
):
    """GET /api/v1/events/{id}/hints без токена возвращает 401."""
    resp = await client.get(f"/api/v1/events/{event_in_db.id}/hints")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_hints_endpoint_not_found(
    client: AsyncClient,
    superuser_token: str,
    org_and_asset,
):
    """GET /api/v1/events/{id}/hints с несуществующим id возвращает 404."""
    resp = await client.get(
        "/api/v1/events/nonexistent-event-id-12345/hints",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 404


# ─── API-тесты: PATCH /events/{id}/resolve ───────────────────────────────────

@pytest.mark.asyncio
async def test_resolve_event(
    client: AsyncClient,
    superuser_token: str,
    superuser: User,
    event_in_db: Event,
):
    """PATCH /api/v1/events/{id}/resolve устанавливает resolved=True."""
    resp = await client.patch(
        f"/api/v1/events/{event_in_db.id}/resolve",
        json={},
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 200, f"Ответ: {resp.text}"
    data = resp.json()
    assert data["resolved"] is True


@pytest.mark.asyncio
async def test_resolve_requires_auth(
    client: AsyncClient,
    event_in_db: Event,
):
    """PATCH /api/v1/events/{id}/resolve без токена возвращает 401."""
    resp = await client.patch(
        f"/api/v1/events/{event_in_db.id}/resolve",
        json={},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_resolved_event_has_timestamp(
    client: AsyncClient,
    superuser_token: str,
    event_in_db: Event,
):
    """После resolve: resolved_at заполнен, resolved_by содержит email."""
    resp = await client.patch(
        f"/api/v1/events/{event_in_db.id}/resolve",
        json={},
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 200, f"Ответ: {resp.text}"
    data = resp.json()
    assert data["resolved"] is True
    assert data["resolved_at"] is not None
    assert data["resolved_by"] is not None
    assert "@" in data["resolved_by"]  # email пользователя


@pytest.mark.asyncio
async def test_resolve_not_found(
    client: AsyncClient,
    superuser_token: str,
    org_and_asset,
):
    """PATCH /api/v1/events/{id}/resolve с несуществующим id возвращает 404."""
    resp = await client.patch(
        "/api/v1/events/nonexistent-event-id-12345/resolve",
        json={},
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 404
