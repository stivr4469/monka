"""
Тесты Phase 13.H — Automated Remediation Playbooks: Jira/ServiceNow ticketing.

Покрывает:
- _build_description из workers/tasks/ticketing.py
- create_jira_ticket (без env → None, с env + мок → тикет создан)
- create_snow_incident (без env → None)
- create_ticket_for_event (приоритет Jira > ServiceNow, fallback)
- POST /api/v1/events/{id}/ticket (503 без конфига, 200 с моком, 401 без токена)
- GET  /api/v1/events/{id}/ticket (статус тикета)
"""
import sys
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

# Добавляем workers/ в sys.path для импорта ticketing
_workers_path = str(Path(__file__).parents[3] / "workers")
if _workers_path not in sys.path:
    sys.path.insert(0, _workers_path)

from tasks.ticketing import _build_description, create_jira_ticket, create_snow_incident

from app.core.config import settings
from app.models.asset import Asset
from app.models.event import Event
from app.models.organization import Organization, OrgPlan
from app.models.user import User


# ─── Фикстуры ────────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def org_and_asset(db_session: AsyncSession, superuser: User):
    """Организация + актив, superuser привязан к ней."""
    uid = uuid.uuid4().hex[:8]
    org = Organization(
        name=f"Ticketing Org {uid}",
        slug=f"ticketing-org-{uid}",
        plan=OrgPlan.professional.value,
    )
    db_session.add(org)
    await db_session.flush()

    superuser.organization_id = org.id
    await db_session.flush()

    asset = Asset(
        domain=f"ticketing-{uid}.com",
        description=f"Ticketing Asset {uid}",
        organization_id=org.id,
        is_active=True,
    )
    db_session.add(asset)
    await db_session.commit()
    await db_session.refresh(asset)
    return org, asset


@pytest_asyncio.fixture
async def event_in_db(db_session: AsyncSession, org_and_asset):
    """Создаёт событие stealer_log напрямую в БД."""
    _, asset = org_and_asset
    ev = Event(
        event_type="stealer_log",
        severity="critical",
        source_type="stealer",
        source_name="test-stealer",
        target_domain=asset.domain,
        payload={"login": "user@example.com", "url": "https://example.com"},
        asset_id=asset.id,
    )
    db_session.add(ev)
    await db_session.commit()
    await db_session.refresh(ev)
    return ev


# ─── Unit-тесты: _build_description ─────────────────────────────────────────

def test_build_description_contains_event_type():
    """_build_description включает тип события и severity."""
    event = {
        "event_type": "stealer_log",
        "severity": "critical",
        "target_domain": "example.com",
        "payload": {"login": "user@example.com"},
        "created_at": "2026-01-01T00:00:00Z",
    }
    hints = ["Сбрось пароль", "Включи MFA"]
    desc = _build_description(event, hints)

    assert "stealer_log" in desc
    assert "critical" in desc
    assert "example.com" in desc
    assert "Сбрось пароль" in desc
    assert "Включи MFA" in desc
    assert "Remediation Steps" in desc


def test_build_description_truncates_long_payload():
    """_build_description обрезает payload до 500 символов."""
    long_payload = {"data": "x" * 1000}
    event = {
        "event_type": "port_scan",
        "severity": "low",
        "target_domain": "example.com",
        "payload": long_payload,
    }
    desc = _build_description(event, [])
    # Длина строки с payload ограничена [:500]
    assert len(desc) < 2000


def test_build_description_empty_hints():
    """_build_description работает корректно с пустым списком hints."""
    event = {
        "event_type": "port_scan",
        "severity": "low",
        "target_domain": "example.com",
        "payload": {},
    }
    desc = _build_description(event, [])
    assert "Remediation Steps" in desc


# ─── Unit-тесты: create_jira_ticket ─────────────────────────────────────────

def test_jira_ticket_not_available_without_env():
    """Без JIRA_URL env-переменных create_jira_ticket возвращает None."""
    event = {
        "event_type": "stealer_log",
        "severity": "critical",
        "target_domain": "example.com",
        "payload": {},
    }
    with patch("tasks.ticketing._JIRA_AVAILABLE", False):
        result = create_jira_ticket(event, ["hint"])
    assert result is None


def test_create_jira_ticket_calls_api():
    """create_jira_ticket вызывает httpx.post с правильными параметрами и парсит ответ."""
    event = {
        "event_type": "stealer_log",
        "severity": "critical",
        "target_domain": "example.com",
        "payload": {},
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 201
    mock_resp.json.return_value = {"id": "10001", "key": "SEC-1"}

    with patch("tasks.ticketing._JIRA_AVAILABLE", True), \
         patch("tasks.ticketing._JIRA_URL", "https://test.atlassian.net"), \
         patch("tasks.ticketing._JIRA_USER", "test@test.com"), \
         patch("tasks.ticketing._JIRA_TOKEN", "token123"), \
         patch("tasks.ticketing._JIRA_PROJECT", "SEC"), \
         patch("httpx.post", return_value=mock_resp) as mock_post:
        result = create_jira_ticket(event, ["Fix it"])

    assert result is not None
    assert result["ticket_id"] == "SEC-1"
    assert mock_post.called
    # Проверяем URL вызова
    call_url = mock_post.call_args[0][0]
    assert "rest/api/3/issue" in call_url


def test_create_jira_parses_response():
    """create_jira_ticket корректно парсит ответ {"id": "10001", "key": "SEC-1"}."""
    event = {
        "event_type": "port_scan",
        "severity": "high",
        "target_domain": "example.com",
        "payload": {},
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 201
    mock_resp.json.return_value = {"id": "10001", "key": "SEC-1"}

    with patch("tasks.ticketing._JIRA_AVAILABLE", True), \
         patch("tasks.ticketing._JIRA_URL", "https://test.atlassian.net"), \
         patch("tasks.ticketing._JIRA_USER", "u"), \
         patch("tasks.ticketing._JIRA_TOKEN", "t"), \
         patch("tasks.ticketing._JIRA_PROJECT", "SEC"), \
         patch("httpx.post", return_value=mock_resp):
        result = create_jira_ticket(event, [])

    assert result is not None
    assert result["ticket_id"] == "SEC-1"
    assert result["internal_id"] == "10001"
    assert result["platform"] == "jira"
    assert "browse/SEC-1" in result["url"]


def test_create_jira_returns_none_on_api_error():
    """create_jira_ticket возвращает None если API вернул не 2xx."""
    event = {
        "event_type": "port_scan",
        "severity": "low",
        "target_domain": "example.com",
        "payload": {},
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 403
    mock_resp.text = "Forbidden"

    with patch("tasks.ticketing._JIRA_AVAILABLE", True), \
         patch("tasks.ticketing._JIRA_URL", "https://test.atlassian.net"), \
         patch("tasks.ticketing._JIRA_USER", "u"), \
         patch("tasks.ticketing._JIRA_TOKEN", "t"), \
         patch("tasks.ticketing._JIRA_PROJECT", "SEC"), \
         patch("httpx.post", return_value=mock_resp):
        result = create_jira_ticket(event, [])

    assert result is None


# ─── Unit-тесты: create_snow_incident ────────────────────────────────────────

def test_snow_not_available_without_env():
    """Без SERVICENOW_URL env-переменных create_snow_incident возвращает None."""
    event = {
        "event_type": "stealer_log",
        "severity": "critical",
        "target_domain": "example.com",
        "payload": {},
    }
    with patch("tasks.ticketing._SNOW_AVAILABLE", False):
        result = create_snow_incident(event, ["hint"])
    assert result is None


def test_create_snow_parses_response():
    """create_snow_incident корректно парсит ответ ServiceNow."""
    event = {
        "event_type": "port_scan",
        "severity": "high",
        "target_domain": "example.com",
        "payload": {},
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 201
    mock_resp.json.return_value = {
        "result": {"number": "INC0001234", "sys_id": "abc123"}
    }

    with patch("tasks.ticketing._SNOW_AVAILABLE", True), \
         patch("tasks.ticketing._SNOW_URL", "https://test.service-now.com"), \
         patch("tasks.ticketing._SNOW_USER", "u"), \
         patch("tasks.ticketing._SNOW_PASS", "p"), \
         patch("httpx.post", return_value=mock_resp):
        result = create_snow_incident(event, [])

    assert result is not None
    assert result["ticket_id"] == "INC0001234"
    assert result["platform"] == "servicenow"
    assert "sys_id=abc123" in result["url"]


# ─── Unit-тесты: create_ticket_for_event ─────────────────────────────────────

def test_create_ticket_uses_jira_first():
    """create_ticket_for_event использует Jira в первую очередь."""
    event = {
        "event_type": "stealer_log",
        "severity": "critical",
        "target_domain": "example.com",
        "payload": {},
    }

    jira_result = {"ticket_id": "SEC-99", "url": "http://j/browse/SEC-99", "platform": "jira", "internal_id": "999"}

    with patch("tasks.ticketing.create_jira_ticket", return_value=jira_result) as mock_jira, \
         patch("tasks.ticketing.create_snow_incident") as mock_snow:
        from tasks import ticketing
        result = ticketing.create_ticket_for_event(event)

    assert result["created"] is True
    assert result["platform"] == "jira"
    assert result["ticket_id"] == "SEC-99"
    mock_snow.assert_not_called()


def test_create_ticket_fallback_to_snow():
    """create_ticket_for_event использует ServiceNow если Jira недоступна."""
    event = {
        "event_type": "port_scan",
        "severity": "high",
        "target_domain": "example.com",
        "payload": {},
    }

    snow_result = {
        "ticket_id": "INC0001",
        "url": "http://sn/incident",
        "platform": "servicenow",
        "sys_id": "x",
    }

    with patch("tasks.ticketing.create_jira_ticket", return_value=None), \
         patch("tasks.ticketing.create_snow_incident", return_value=snow_result):
        from tasks import ticketing
        result = ticketing.create_ticket_for_event(event)

    assert result["created"] is True
    assert result["platform"] == "servicenow"
    assert result["ticket_id"] == "INC0001"


def test_create_ticket_returns_not_created_when_both_unavailable():
    """create_ticket_for_event возвращает created=False если ни один провайдер не настроен."""
    event = {
        "event_type": "port_scan",
        "severity": "low",
        "target_domain": "example.com",
        "payload": {},
    }

    with patch("tasks.ticketing.create_jira_ticket", return_value=None), \
         patch("tasks.ticketing.create_snow_incident", return_value=None):
        from tasks import ticketing
        result = ticketing.create_ticket_for_event(event)

    assert result["created"] is False
    assert result["platform"] is None
    assert result["ticket_id"] is None


# ─── API-тесты: POST /api/v1/events/{id}/ticket ──────────────────────────────

@pytest.mark.asyncio
async def test_ticket_endpoint_returns_503_without_config(
    client: AsyncClient,
    superuser_token: str,
    event_in_db: Event,
):
    """POST /ticket без настроенного Jira/ServiceNow → 503."""
    with patch("app.api.v1.endpoints.tickets._JIRA_AVAILABLE", False), \
         patch("app.api.v1.endpoints.tickets._SNOW_AVAILABLE", False):
        resp = await client.post(
            f"/api/v1/events/{event_in_db.id}/ticket",
            headers={"Authorization": f"Bearer {superuser_token}"},
        )
    assert resp.status_code == 503
    assert "Ticketing" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_ticket_endpoint_requires_auth(
    client: AsyncClient,
    event_in_db: Event,
):
    """POST /ticket без токена → 401."""
    resp = await client.post(f"/api/v1/events/{event_in_db.id}/ticket")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_ticket_endpoint_creates_ticket(
    client: AsyncClient,
    superuser_token: str,
    event_in_db: Event,
):
    """POST /ticket с замокированным Jira → 200, ticket_id заполнен."""
    mock_result = {
        "created": True,
        "platform": "jira",
        "ticket_id": "SEC-42",
        "url": "https://test.atlassian.net/browse/SEC-42",
        "internal_id": "10042",
    }

    with patch("app.api.v1.endpoints.tickets._JIRA_AVAILABLE", True), \
         patch("app.api.v1.endpoints.tickets._SNOW_AVAILABLE", False), \
         patch("app.api.v1.endpoints.tickets.create_ticket_for_event", return_value=mock_result):
        resp = await client.post(
            f"/api/v1/events/{event_in_db.id}/ticket",
            headers={"Authorization": f"Bearer {superuser_token}"},
        )

    assert resp.status_code == 200, f"Ответ: {resp.text}"
    data = resp.json()
    assert data["created"] is True
    assert data["platform"] == "jira"
    assert data["ticket_id"] == "SEC-42"
    assert data["ticket_ref"] == "jira:SEC-42"


@pytest.mark.asyncio
async def test_ticket_endpoint_not_found(
    client: AsyncClient,
    superuser_token: str,
    org_and_asset,
):
    """POST /ticket с несуществующим event_id → 404."""
    with patch("app.api.v1.endpoints.tickets._JIRA_AVAILABLE", True), \
         patch("app.api.v1.endpoints.tickets._SNOW_AVAILABLE", False):
        resp = await client.post(
            "/api/v1/events/nonexistent-event-99999/ticket",
            headers={"Authorization": f"Bearer {superuser_token}"},
        )
    assert resp.status_code == 404


# ─── API-тесты: GET /api/v1/events/{id}/ticket ───────────────────────────────

@pytest.mark.asyncio
async def test_get_ticket_status_no_ticket(
    client: AsyncClient,
    superuser_token: str,
    event_in_db: Event,
):
    """GET /ticket для события без тикета → created=False."""
    resp = await client.get(
        f"/api/v1/events/{event_in_db.id}/ticket",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["created"] is False
    assert data["ticket_ref"] is None


@pytest.mark.asyncio
async def test_get_ticket_status_with_ticket(
    client: AsyncClient,
    superuser_token: str,
    event_in_db: Event,
    db_session: AsyncSession,
):
    """GET /ticket для события с ticket_ref → корректный статус."""
    # Устанавливаем ticket_ref вручную в БД
    event_in_db.ticket_ref = "jira:SEC-55"
    await db_session.commit()
    await db_session.refresh(event_in_db)

    # _JIRA_URL живёт в workers/tasks/ticketing, патчим там
    with patch("tasks.ticketing._JIRA_URL", "https://test.atlassian.net"):
        resp = await client.get(
            f"/api/v1/events/{event_in_db.id}/ticket",
            headers={"Authorization": f"Bearer {superuser_token}"},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["created"] is True
    assert data["platform"] == "jira"
    assert data["ticket_id"] == "SEC-55"
    assert data["ticket_ref"] == "jira:SEC-55"


@pytest.mark.asyncio
async def test_get_ticket_status_requires_auth(
    client: AsyncClient,
    event_in_db: Event,
):
    """GET /ticket без токена → 401."""
    resp = await client.get(f"/api/v1/events/{event_in_db.id}/ticket")
    assert resp.status_code == 401
