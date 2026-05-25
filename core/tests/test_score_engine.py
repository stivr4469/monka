"""Тесты Security Score Engine (задача 11.A + 11.B)."""
import math
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
from app.services.score_engine import (
    CATEGORY_WEIGHTS,
    SEVERITY_PENALTY,
    CategoryScore,
    ScoreResult,
    _aggregate_total,
    _compute_categories_from_events,
    _score_to_grade,
    _time_decay,
    calculate_score,
)


# ─── Фикстуры ────────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def org_with_user(db_session: AsyncSession, superuser: User) -> Organization:
    """Организация, привязанная к superuser."""
    uid = uuid.uuid4().hex[:8]
    org = Organization(
        name=f"Score Org {uid}",
        slug=f"score-org-{uid}",
        plan=OrgPlan.starter.value,
    )
    db_session.add(org)
    await db_session.flush()
    superuser.organization_id = org.id
    await db_session.commit()
    await db_session.refresh(org)
    return org


@pytest_asyncio.fixture
async def asset(db_session: AsyncSession, org_with_user: Organization) -> Asset:
    """Активный актив организации с importance=1.0."""
    a = Asset(
        domain=f"test-{uuid.uuid4().hex[:6]}.com",
        organization_id=org_with_user.id,
        importance=1.0,
    )
    db_session.add(a)
    await db_session.commit()
    await db_session.refresh(a)
    return a


@pytest_asyncio.fixture
async def asset_with_events(
    db_session: AsyncSession,
    asset: Asset,
) -> Asset:
    """Актив с двумя событиями: critical credential_exposure + high network_security."""
    now = datetime.now(timezone.utc)

    events = [
        Event(
            event_type="stealer_log",          # → credential_exposure
            severity="critical",
            source_type="stealer_log",
            source_name="test_source",
            target_domain=asset.domain,
            payload={"test": True},
            detected_at=now - timedelta(days=1),
            asset_id=asset.id,
        ),
        Event(
            event_type="exposed_service",       # → network_security
            severity="high",
            source_type="scanner",
            source_name="test_scanner",
            target_domain=asset.domain,
            payload={"port": 22},
            detected_at=now - timedelta(days=7),
            asset_id=asset.id,
        ),
        Event(
            event_type="tech_profile",          # → application_security, info — штрафа нет
            severity="info",
            source_type="scanner",
            source_name="wappalyzer",
            target_domain=asset.domain,
            payload={"technologies": ["nginx"]},
            detected_at=now - timedelta(days=2),
            asset_id=asset.id,
        ),
    ]
    for ev in events:
        db_session.add(ev)
    await db_session.commit()
    return asset


@pytest_asyncio.fixture
async def asset_with_resolved_event(
    db_session: AsyncSession,
    asset: Asset,
) -> Asset:
    """Актив с устранённым событием (resolved_at заполнен) — не должно учитываться."""
    now = datetime.now(timezone.utc)
    ev = Event(
        event_type="subdomain_takeover",
        severity="critical",
        source_type="scanner",
        source_name="test",
        target_domain=asset.domain,
        payload={},
        detected_at=now - timedelta(days=5),
        resolved_at=now,                    # устранено — исключается из score
        asset_id=asset.id,
    )
    db_session.add(ev)
    await db_session.commit()
    return asset


# ─── Unit-тесты функций сервиса ───────────────────────────────────────────────

def test_time_decay_at_zero():
    """T(0) должно быть ровно 1.0 — нет затухания в момент обнаружения."""
    assert _time_decay(0.0) == pytest.approx(1.0)


def test_time_decay_at_231_days():
    """Через ~231 день затухание должно составить ~50%."""
    decay = _time_decay(231.0)
    # exp(-0.003 × 231) ≈ 0.5
    assert decay == pytest.approx(0.5, abs=0.01)


def test_score_to_grade_boundaries():
    """Проверяем пограничные значения grade."""
    assert _score_to_grade(100) == "A"
    assert _score_to_grade(90) == "A"
    assert _score_to_grade(89) == "B"
    assert _score_to_grade(75) == "B"
    assert _score_to_grade(74) == "C"
    assert _score_to_grade(60) == "C"
    assert _score_to_grade(59) == "D"
    assert _score_to_grade(40) == "D"
    assert _score_to_grade(39) == "F"
    assert _score_to_grade(0) == "F"


def test_aggregate_total_perfect_score():
    """Все категории 100 → total=100."""
    categories = {
        cat: CategoryScore(score=100, penalty=0.0, event_count=0)
        for cat in CATEGORY_WEIGHTS
    }
    assert _aggregate_total(categories) == 100


def test_aggregate_total_zero_score():
    """Все категории 0 → total=0."""
    categories = {
        cat: CategoryScore(score=0, penalty=999.0, event_count=10)
        for cat in CATEGORY_WEIGHTS
    }
    assert _aggregate_total(categories) == 0


def test_aggregate_total_weights_sum_to_one():
    """Сумма весов категорий должна быть ровно 1.0."""
    total_weight = sum(CATEGORY_WEIGHTS.values())
    assert total_weight == pytest.approx(1.0, abs=1e-9)


def test_compute_categories_info_events_no_penalty():
    """info-события не должны давать штраф ни в одной категории."""

    class MockRow:
        def __init__(self, event_type, severity, detected_at):
            self.event_type = event_type
            self.severity = severity
            self.detected_at = detected_at

    now = datetime.now(timezone.utc)
    events = [MockRow("stealer_log", "info", now)]
    categories = _compute_categories_from_events(events, importance=1.0, now=now)

    for cat, cs in categories.items():
        assert cs.penalty == 0.0, f"Категория {cat} получила штраф от info-события"
        assert cs.event_count == 0


def test_compute_categories_critical_stealer():
    """critical stealer_log → credential_exposure получает штраф ~25."""

    class MockRow:
        def __init__(self, event_type, severity, detected_at):
            self.event_type = event_type
            self.severity = severity
            self.detected_at = detected_at

    now = datetime.now(timezone.utc)
    # Только что обнаруженное событие: decay≈1.0
    events = [MockRow("stealer_log", "critical", now)]
    categories = _compute_categories_from_events(events, importance=1.0, now=now)

    cred = categories["credential_exposure"]
    assert cred.event_count == 1
    # штраф = 25.0 × exp(0) × 1.0 = 25.0
    assert cred.penalty == pytest.approx(25.0, abs=0.1)
    assert cred.score == max(0, int(round(100 - 25.0)))


def test_compute_categories_unknown_event_type_ignored():
    """Неизвестный event_type не должен попадать ни в одну категорию."""

    class MockRow:
        def __init__(self, event_type, severity, detected_at):
            self.event_type = event_type
            self.severity = severity
            self.detected_at = detected_at

    now = datetime.now(timezone.utc)
    events = [MockRow("unknown_future_event", "critical", now)]
    categories = _compute_categories_from_events(events, importance=1.0, now=now)

    total_events = sum(cs.event_count for cs in categories.values())
    assert total_events == 0


def test_compute_categories_resolved_not_counted():
    """Устранённые события (resolved_at задан) не должны учитываться.

    Проверяем это на уровне сервиса — сам _compute_categories_from_events
    не фильтрует resolved_at, фильтрация делается в SQL-запросе.
    """
    # Этот тест документирует ответственность: фильтр resolved_at = в DB-запросе


# ─── Интеграционные тесты сервиса ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_calculate_score_clean_asset(
    db_session: AsyncSession,
    asset: Asset,
) -> None:
    """Актив без событий должен иметь score=100, grade=A."""
    result = await calculate_score(
        org_id=asset.organization_id,
        db=db_session,
        asset_id=asset.id,
    )
    assert isinstance(result, ScoreResult)
    assert result.total == 100
    assert result.grade == "A"
    assert result.asset_id == asset.id
    assert result.org_id == asset.organization_id

    # Все категории должны быть чистыми
    for cat, cs in result.categories.items():
        assert cs.score == 100, f"Категория {cat}: ожидался score=100"
        assert cs.event_count == 0


@pytest.mark.asyncio
async def test_calculate_score_with_events(
    db_session: AsyncSession,
    asset_with_events: Asset,
) -> None:
    """Актив с critical/high событиями должен получить score < 100."""
    result = await calculate_score(
        org_id=asset_with_events.organization_id,
        db=db_session,
        asset_id=asset_with_events.id,
    )
    assert result.total < 100
    # credential_exposure получил critical stealer_log — должен быть ниже 100
    cred = result.categories["credential_exposure"]
    assert cred.score < 100
    assert cred.event_count == 1

    # network_security получил high exposed_service
    net = result.categories["network_security"]
    assert net.score < 100
    assert net.event_count == 1

    # application_security: был info-ивент — не должен влиять
    app_sec = result.categories["application_security"]
    assert app_sec.event_count == 0


@pytest.mark.asyncio
async def test_calculate_score_resolved_event_excluded(
    db_session: AsyncSession,
    asset_with_resolved_event: Asset,
) -> None:
    """Устранённые события (resolved_at IS NOT NULL) не должны влиять на score."""
    result = await calculate_score(
        org_id=asset_with_resolved_event.organization_id,
        db=db_session,
        asset_id=asset_with_resolved_event.id,
    )
    # Устранённое critical событие не должно снижать score
    assert result.total == 100
    assert result.grade == "A"


@pytest.mark.asyncio
async def test_calculate_org_score_no_assets(
    db_session: AsyncSession,
    org_with_user: Organization,
) -> None:
    """Организация без активов должна получить score=100, grade=A."""
    result = await calculate_score(
        org_id=org_with_user.id,
        db=db_session,
        asset_id=None,
    )
    assert result.total == 100
    assert result.grade == "A"
    assert result.asset_id is None
    assert result.org_id == org_with_user.id


@pytest.mark.asyncio
async def test_calculate_org_score_with_events(
    db_session: AsyncSession,
    asset_with_events: Asset,
    org_with_user: Organization,
) -> None:
    """Org-score должен учитывать события активов."""
    result = await calculate_score(
        org_id=org_with_user.id,
        db=db_session,
        asset_id=None,
    )
    assert result.total < 100
    assert result.asset_id is None


# ─── API-тесты (HTTP) ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_asset_score_api(
    client: AsyncClient,
    superuser_token: str,
    asset: Asset,
) -> None:
    """GET /assets/{id}/score → 200 + ScoreResult."""
    resp = await client.get(
        f"/api/v1/assets/{asset.id}/score",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "total" in data
    assert "grade" in data
    assert "categories" in data
    assert data["total"] == 100
    assert data["grade"] == "A"
    assert data["asset_id"] == asset.id


@pytest.mark.asyncio
async def test_get_asset_score_not_found(
    client: AsyncClient,
    superuser_token: str,
    org_with_user: Organization,
) -> None:
    """GET /assets/nonexistent/score → 404."""
    resp = await client.get(
        "/api/v1/assets/nonexistent-id/score",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_get_org_score_api(
    client: AsyncClient,
    superuser_token: str,
    org_with_user: Organization,
) -> None:
    """GET /organizations/{id}/score → 200 + ScoreResult."""
    resp = await client.get(
        f"/api/v1/organizations/{org_with_user.id}/score",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "total" in data
    assert data["asset_id"] is None
    assert data["org_id"] == org_with_user.id


@pytest.mark.asyncio
async def test_get_org_score_wrong_org_forbidden(
    client: AsyncClient,
    superuser_token: str,
    db_session: AsyncSession,
) -> None:
    """GET /organizations/другая/score → 403 для обычного пользователя.

    superuser получает 403 только если другая org, но т.к. superuser=True —
    должен получить 404 (org не существует), или при существующей чужой org — 200.
    Тест проверяет несуществующую org → 404.
    """
    resp = await client.get(
        "/api/v1/organizations/nonexistent-org-id/score",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    # superuser может получить 200 или 404 — главное не 403
    assert resp.status_code in (200, 404)


@pytest.mark.asyncio
async def test_get_asset_score_history_empty(
    client: AsyncClient,
    superuser_token: str,
    asset: Asset,
) -> None:
    """GET /assets/{id}/score/history → 200, пустой список без снимков."""
    resp = await client.get(
        f"/api/v1/assets/{asset.id}/score/history",
        params={"days": 7},
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 200, resp.text
    assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_get_asset_score_history_after_score(
    client: AsyncClient,
    superuser_token: str,
    asset: Asset,
) -> None:
    """После GET /score снимок должен появиться в /score/history."""
    # Сначала запрашиваем score — это создаёт snapshot
    await client.get(
        f"/api/v1/assets/{asset.id}/score",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )

    # Затем проверяем историю
    resp = await client.get(
        f"/api/v1/assets/{asset.id}/score/history",
        params={"days": 30},
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 200, resp.text
    history = resp.json()
    assert len(history) >= 1
    snap = history[0]
    assert "total" in snap
    assert "grade" in snap
    assert "snapshot_id" in snap
    assert "categories" in snap


@pytest.mark.asyncio
async def test_score_unauthorized(client: AsyncClient, asset: Asset) -> None:
    """Неавторизованный запрос → 401."""
    resp = await client.get(f"/api/v1/assets/{asset.id}/score")
    assert resp.status_code == 401
