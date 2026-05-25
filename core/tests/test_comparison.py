"""Тесты Multi-org Industry Comparison (Phase 13.I).

Покрывает:
    - test_comparison_returns_orgs_data        — правильная структура ответа
    - test_comparison_requires_auth            — 401 без токена
    - test_comparison_filters_foreign_orgs     — нельзя видеть чужие org
    - test_portfolio_view_for_mssp             — MSSP видит своих клиентов
    - test_trend_improving_when_score_increased — тренд improving при росте score
    - test_trend_degrading_when_score_decreased — тренд degrading при падении score
    - test_summary_best_worst_score            — сводка best/worst/avg
    - test_empty_org_ids_returns_own_org       — без org_ids возвращает свою org
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.models.organization import Organization, OrgPlan
from app.models.score_snapshot import ScoreSnapshot
from app.models.user import User

# asyncio_mode = auto в pytest.ini, используем @pytest.mark.asyncio

# Пароль для тестовых пользователей
TEST_PASSWORD = "testpassword"


# ─── Вспомогательные функции ─────────────────────────────────────────────────

def _uid() -> str:
    return uuid.uuid4().hex[:8]


def _make_categories_json(base_score: int = 80) -> dict:
    """Создаёт categories_json для ScoreSnapshot."""
    return {
        "network_security": {"score": base_score, "penalty": 0, "event_count": 0},
        "dns_health": {"score": base_score, "penalty": 0, "event_count": 0},
        "application_security": {"score": base_score, "penalty": 0, "event_count": 0},
        "credential_exposure": {"score": base_score, "penalty": 0, "event_count": 0},
        "dark_web_presence": {"score": base_score, "penalty": 0, "event_count": 0},
        "brand_safety": {"score": base_score, "penalty": 0, "event_count": 0},
    }


# ─── Фикстуры ─────────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def org_a(db_session: AsyncSession) -> Organization:
    """Организация A для тестов сравнения."""
    uid = _uid()
    org = Organization(
        name=f"Org Alpha {uid}",
        slug=f"org-alpha-{uid}",
        plan=OrgPlan.enterprise.value,
        industry="fintech",
    )
    db_session.add(org)
    await db_session.commit()
    await db_session.refresh(org)
    return org


@pytest_asyncio.fixture
async def org_b(db_session: AsyncSession) -> Organization:
    """Организация B для тестов сравнения."""
    uid = _uid()
    org = Organization(
        name=f"Org Beta {uid}",
        slug=f"org-beta-{uid}",
        plan=OrgPlan.enterprise.value,
        industry="saas",
    )
    db_session.add(org)
    await db_session.commit()
    await db_session.refresh(org)
    return org


@pytest_asyncio.fixture
async def org_c(db_session: AsyncSession) -> Organization:
    """Организация C — без привязки к тестовому пользователю."""
    uid = _uid()
    org = Organization(
        name=f"Org Gamma {uid}",
        slug=f"org-gamma-{uid}",
        plan=OrgPlan.starter.value,
        industry="healthcare",
    )
    db_session.add(org)
    await db_session.commit()
    await db_session.refresh(org)
    return org


@pytest_asyncio.fixture
async def user_with_org_a(db_session: AsyncSession, org_a: Organization) -> User:
    """Обычный пользователь, привязанный к org_a."""
    uid = _uid()
    user = User(
        email=f"user_a_{uid}@test.com",
        hashed_password=hash_password(TEST_PASSWORD),
        is_superuser=False,
        is_mssp_operator=False,
        organization_id=org_a.id,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def mssp_operator(db_session: AsyncSession) -> User:
    """MSSP-оператор без собственной org."""
    uid = _uid()
    user = User(
        email=f"mssp_{uid}@test.com",
        hashed_password=hash_password(TEST_PASSWORD),
        is_superuser=False,
        is_mssp_operator=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def mssp_with_clients(
    db_session: AsyncSession,
    mssp_operator: User,
    org_a: Organization,
    org_b: Organization,
) -> User:
    """MSSP-оператор с двумя клиентскими организациями."""
    org_a.mssp_owner_id = mssp_operator.id  # type: ignore[assignment]
    org_b.mssp_owner_id = mssp_operator.id  # type: ignore[assignment]
    await db_session.commit()
    await db_session.refresh(mssp_operator)
    return mssp_operator


async def _get_token(client: AsyncClient, email: str, password: str) -> str:
    resp = await client.post(
        "/api/v1/auth/token",
        data={"username": email, "password": password},
    )
    assert resp.status_code == 200, f"Ошибка логина: {resp.text}"
    return resp.json()["access_token"]


# ─── Тесты ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_comparison_returns_orgs_data(
    client: AsyncClient,
    superuser_token: str,
    superuser: User,
    org_a: Organization,
    db_session: AsyncSession,
):
    """Проверяет структуру ответа /comparison/portfolio для superuser."""
    # Привязываем org_a к superuser чтобы superuser имел организацию
    superuser.organization_id = org_a.id
    await db_session.commit()

    resp = await client.get(
        "/api/v1/comparison/portfolio",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "organizations" in data
    assert "summary" in data
    # Если есть организации — проверяем структуру первой
    if data["organizations"]:
        org = data["organizations"][0]
        assert "org_id" in org
        assert "name" in org
        assert "industry" in org
        assert "score" in org
        assert "rank" in org
        assert "category_scores" in org
        assert "trend" in org
        assert "open_critical" in org
        assert "open_high" in org


@pytest.mark.asyncio
async def test_comparison_requires_auth(client: AsyncClient):
    """Проверяет, что без токена возвращается 401/403."""
    resp = await client.get("/api/v1/comparison/portfolio")
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_comparison_filters_foreign_orgs(
    client: AsyncClient,
    user_with_org_a: User,
    org_a: Organization,
    org_c: Organization,
    db_session: AsyncSession,
):
    """Обычный пользователь не может видеть чужие организации.

    При запросе /comparison/orgs с org_ids=org_c.id (чужая org) — ответ не содержит org_c.
    """
    token = await _get_token(client, user_with_org_a.email, TEST_PASSWORD)

    # Запрашиваем чужую org (org_c) — пользователь принадлежит org_a
    resp = await client.get(
        f"/api/v1/comparison/orgs?org_ids={org_c.id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    # Чужая org не должна попасть в ответ — возвращается пустой список
    returned_ids = [o["org_id"] for o in data["organizations"]]
    assert org_c.id not in returned_ids


@pytest.mark.asyncio
async def test_portfolio_view_for_mssp(
    client: AsyncClient,
    mssp_with_clients: User,
    org_a: Organization,
    org_b: Organization,
):
    """MSSP-оператор видит всех привязанных клиентов в портфеле."""
    token = await _get_token(client, mssp_with_clients.email, TEST_PASSWORD)

    resp = await client.get(
        "/api/v1/comparison/portfolio",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "organizations" in data
    returned_ids = {o["org_id"] for o in data["organizations"]}
    assert org_a.id in returned_ids
    assert org_b.id in returned_ids


@pytest.mark.asyncio
async def test_trend_improving_when_score_increased(
    db_session: AsyncSession,
    client: AsyncClient,
    superuser_token: str,
    superuser: User,
    org_a: Organization,
):
    """Тренд 'improving' если score в текущем периоде выше предыдущего на >3."""
    superuser.organization_id = org_a.id
    await db_session.commit()

    now = datetime.now(timezone.utc)

    # Предыдущий период (31-60 дней назад): score = 50
    snap_prev = ScoreSnapshot(
        org_id=org_a.id,
        asset_id=None,
        total_score=50,
        grade="C",
        categories_json=_make_categories_json(50),
        calculated_at=now - timedelta(days=45),
    )
    # Текущий период (последние 30 дней): score = 80
    snap_curr = ScoreSnapshot(
        org_id=org_a.id,
        asset_id=None,
        total_score=80,
        grade="B",
        categories_json=_make_categories_json(80),
        calculated_at=now - timedelta(days=5),
    )
    db_session.add(snap_prev)
    db_session.add(snap_curr)
    await db_session.commit()

    resp = await client.get(
        f"/api/v1/comparison/orgs?org_ids={org_a.id}&days=30",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["organizations"]) == 1
    assert data["organizations"][0]["trend"] == "improving"


@pytest.mark.asyncio
async def test_trend_degrading_when_score_decreased(
    db_session: AsyncSession,
    client: AsyncClient,
    superuser_token: str,
    superuser: User,
    org_b: Organization,
):
    """Тренд 'degrading' если score в текущем периоде ниже предыдущего на >3."""
    superuser.organization_id = org_b.id
    await db_session.commit()

    now = datetime.now(timezone.utc)

    # Предыдущий период: score = 85
    snap_prev = ScoreSnapshot(
        org_id=org_b.id,
        asset_id=None,
        total_score=85,
        grade="B",
        categories_json=_make_categories_json(85),
        calculated_at=now - timedelta(days=40),
    )
    # Текущий период: score = 55 (упал на 30)
    snap_curr = ScoreSnapshot(
        org_id=org_b.id,
        asset_id=None,
        total_score=55,
        grade="D",
        categories_json=_make_categories_json(55),
        calculated_at=now - timedelta(days=10),
    )
    db_session.add(snap_prev)
    db_session.add(snap_curr)
    await db_session.commit()

    resp = await client.get(
        f"/api/v1/comparison/orgs?org_ids={org_b.id}&days=30",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["organizations"]) == 1
    assert data["organizations"][0]["trend"] == "degrading"


@pytest.mark.asyncio
async def test_summary_best_worst_score(
    client: AsyncClient,
    mssp_with_clients: User,
    org_a: Organization,
    org_b: Organization,
    db_session: AsyncSession,
):
    """Проверяет что сводка корректно определяет best/worst/avg score."""
    token = await _get_token(client, mssp_with_clients.email, TEST_PASSWORD)

    resp = await client.get(
        "/api/v1/comparison/portfolio",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    summary = data.get("summary")

    if summary and data["organizations"]:
        scores = [o["score"] for o in data["organizations"]]
        assert summary["best_score"]["score"] == max(scores)
        assert summary["worst_score"]["score"] == min(scores)
        assert summary["total_orgs"] == len(data["organizations"])
        # avg_score должен быть примерно правильным
        expected_avg = round(sum(scores) / len(scores), 1)
        assert abs(summary["avg_score"] - expected_avg) < 0.2


@pytest.mark.asyncio
async def test_empty_org_ids_returns_own_org(
    client: AsyncClient,
    user_with_org_a: User,
    org_a: Organization,
):
    """Если org_ids не указаны — обычный пользователь видит только свою org."""
    token = await _get_token(client, user_with_org_a.email, TEST_PASSWORD)

    resp = await client.get(
        "/api/v1/comparison/orgs",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    # Обычный пользователь видит только свою org
    returned_ids = [o["org_id"] for o in data["organizations"]]
    assert org_a.id in returned_ids


@pytest.mark.asyncio
async def test_portfolio_requires_mssp_or_superuser(
    client: AsyncClient,
    user_with_org_a: User,
):
    """Обычный пользователь получает 403 при обращении к /comparison/portfolio."""
    token = await _get_token(client, user_with_org_a.email, TEST_PASSWORD)

    resp = await client.get(
        "/api/v1/comparison/portfolio",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403
