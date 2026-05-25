"""Тесты Executive Dashboard (задача 11.C)."""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset
from app.models.event import Event
from app.models.organization import Organization, OrgPlan
from app.models.user import User

DASHBOARD_URL = "/api/v1/dashboard/executive"


# ─── Фикстуры ────────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def org_with_user(db_session: AsyncSession, superuser: User) -> Organization:
    """Организация, привязанная к superuser."""
    uid = uuid.uuid4().hex[:8]
    org = Organization(
        name=f"Dashboard Org {uid}",
        slug=f"dashboard-org-{uid}",
        plan=OrgPlan.starter.value,
    )
    db_session.add(org)
    await db_session.flush()
    superuser.organization_id = org.id
    await db_session.commit()
    await db_session.refresh(org)
    return org


@pytest_asyncio.fixture
async def asset_with_events(
    db_session: AsyncSession,
    org_with_user: Organization,
) -> Asset:
    """Актив с несколькими событиями разной серьёзности."""
    asset = Asset(
        domain=f"test-{uuid.uuid4().hex[:6]}.com",
        organization_id=org_with_user.id,
        importance=1.0,
    )
    db_session.add(asset)
    await db_session.flush()

    now = datetime.now(timezone.utc)

    # critical событие (stealer_log → credential_exposure)
    ev_critical = Event(
        event_type="stealer_log",
        severity="critical",
        source_type="stealer",
        source_name="test_source",
        target_domain=asset.domain,
        payload={"description": "Критические учётные данные обнаружены"},
        detected_at=now - timedelta(hours=2),
        asset_id=asset.id,
    )

    # high событие (phishing_domain → brand_safety)
    ev_high = Event(
        event_type="phishing_domain",
        severity="high",
        source_type="phishing",
        source_name="test_source",
        target_domain=asset.domain,
        payload={"description": "Фишинговый домен"},
        detected_at=now - timedelta(hours=5),
        asset_id=asset.id,
    )

    # medium событие (darknet_mention → dark_web_presence)
    ev_medium = Event(
        event_type="darknet_mention",
        severity="medium",
        source_type="darknet",
        source_name="test_source",
        target_domain=asset.domain,
        payload={},
        detected_at=now - timedelta(hours=10),
        asset_id=asset.id,
    )

    # low событие (exposed_service → network_security)
    ev_low = Event(
        event_type="exposed_service",
        severity="low",
        source_type="scan",
        source_name="test_source",
        target_domain=asset.domain,
        payload={},
        detected_at=now - timedelta(hours=20),
        asset_id=asset.id,
    )

    db_session.add_all([ev_critical, ev_high, ev_medium, ev_low])
    await db_session.commit()
    await db_session.refresh(asset)
    return asset


# ─── Тесты ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_dashboard_returns_200_with_data(
    client: AsyncClient,
    superuser_token: str,
    asset_with_events: Asset,
):
    """Авторизованный пользователь получает корректный дашборд."""
    resp = await client.get(
        DASHBOARD_URL,
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 200

    data = resp.json()

    # Обязательные поля присутствуют
    assert "generated_at" in data
    assert "organization" in data
    assert "overall_score" in data
    assert "score_trend" in data
    assert "category_scores" in data
    assert "top_risks" in data
    assert "asset_count" in data
    assert "open_events_by_severity" in data

    # score в диапазоне 0–100
    assert 0.0 <= data["overall_score"] <= 100.0

    # Организация заполнена
    org = data["organization"]
    assert org["id"] != ""
    assert "Dashboard Org" in org["name"]

    # Активы: хотя бы один
    assert data["asset_count"] >= 1

    # Тренд: 7 точек
    assert len(data["score_trend"]) == 7

    # Категорийные оценки: все 6 категорий
    cats = data["category_scores"]
    for cat in ["network_security", "dns_health", "application_security",
                "credential_exposure", "dark_web_presence", "brand_safety"]:
        assert cat in cats, f"Категория {cat} отсутствует в category_scores"

    # open_events_by_severity: все уровни присутствуют
    sev_counts = data["open_events_by_severity"]
    for sev in ["critical", "high", "medium", "low"]:
        assert sev in sev_counts

    # Есть хотя бы одно событие (critical или high)
    assert sev_counts["critical"] >= 1 or sev_counts["high"] >= 1


@pytest.mark.asyncio
async def test_dashboard_requires_auth(client: AsyncClient):
    """Без авторизации возвращает 401."""
    resp = await client.get(DASHBOARD_URL)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_dashboard_top_risks_sorted_by_severity(
    client: AsyncClient,
    superuser_token: str,
    asset_with_events: Asset,
):
    """Critical-события идут первыми в top_risks."""
    resp = await client.get(
        DASHBOARD_URL,
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 200

    top_risks = resp.json()["top_risks"]
    assert len(top_risks) >= 1

    # Проверяем что первый элемент — critical (если critical есть)
    severities = [r["severity"] for r in top_risks]
    # Найдём индекс первого critical
    crit_indices = [i for i, s in enumerate(severities) if s == "critical"]
    high_indices = [i for i, s in enumerate(severities) if s == "high"]

    # Все critical идут перед всеми high
    if crit_indices and high_indices:
        assert max(crit_indices) < min(high_indices), (
            f"Critical ({crit_indices}) должны быть до high ({high_indices})"
        )


@pytest.mark.asyncio
async def test_dashboard_empty_org_returns_zeros(
    client: AsyncClient,
    superuser_token: str,
    org_with_user: Organization,  # org без активов и событий
):
    """Пустая организация возвращает нулевые/пустые значения без ошибок."""
    resp = await client.get(
        DASHBOARD_URL,
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 200

    data = resp.json()

    # Пустая org: asset_count = 0, top_risks = []
    assert data["asset_count"] == 0
    assert data["top_risks"] == []

    # Для пустой org score_engine возвращает 100 (нет угроз = идеальный score)
    assert data["overall_score"] == 100.0

    # open_events_by_severity все нули
    sev_counts = data["open_events_by_severity"]
    assert sev_counts["critical"] == 0
    assert sev_counts["high"] == 0
    assert sev_counts["medium"] == 0
    assert sev_counts["low"] == 0
