"""Тесты SaaS биллинга и лимитов доменов (задача 8.I)."""

import uuid

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.organization import Organization, OrgPlan
from app.models.user import User


# ─── Фикстуры ────────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def org_starter(db_session: AsyncSession, superuser: User) -> Organization:
    """Организация на плане starter (лимит 3 домена)."""
    uid = uuid.uuid4().hex[:8]
    org = Organization(
        name=f"Starter Org {uid}",
        slug=f"starter-{uid}",
        plan=OrgPlan.starter.value,
    )
    db_session.add(org)
    await db_session.flush()
    superuser.organization_id = org.id
    await db_session.commit()
    await db_session.refresh(org)
    return org


@pytest_asyncio.fixture
async def org_professional(db_session: AsyncSession, superuser: User) -> Organization:
    """Организация на плане professional (лимит 10 доменов)."""
    uid = uuid.uuid4().hex[:8]
    org = Organization(
        name=f"Pro Org {uid}",
        slug=f"pro-{uid}",
        plan=OrgPlan.professional.value,
    )
    db_session.add(org)
    await db_session.flush()
    superuser.organization_id = org.id
    await db_session.commit()
    await db_session.refresh(org)
    return org


@pytest_asyncio.fixture
async def org_enterprise(db_session: AsyncSession, superuser: User) -> Organization:
    """Организация на плане enterprise (фактически безлимит)."""
    uid = uuid.uuid4().hex[:8]
    org = Organization(
        name=f"Enterprise Org {uid}",
        slug=f"enterprise-{uid}",
        plan=OrgPlan.enterprise.value,
    )
    db_session.add(org)
    await db_session.flush()
    superuser.organization_id = org.id
    await db_session.commit()
    await db_session.refresh(org)
    return org


# ─── GET /api/v1/billing/plan ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_plan_starter(
    client: AsyncClient,
    superuser_token: str,
    org_starter: Organization,
) -> None:
    """GET /billing/plan возвращает корректные данные для плана starter."""
    resp = await client.get(
        "/api/v1/billing/plan",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["plan"] == "starter"
    assert data["plan_label"] == "Starter"
    assert data["domain_limit"] == 3
    assert data["domains_used"] == 0
    assert data["domains_remaining"] == 3


@pytest.mark.asyncio
async def test_get_plan_professional(
    client: AsyncClient,
    superuser_token: str,
    org_professional: Organization,
) -> None:
    """GET /billing/plan возвращает корректные данные для плана professional."""
    resp = await client.get(
        "/api/v1/billing/plan",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["plan"] == "professional"
    assert data["domain_limit"] == 10


@pytest.mark.asyncio
async def test_get_plan_enterprise(
    client: AsyncClient,
    superuser_token: str,
    org_enterprise: Organization,
) -> None:
    """GET /billing/plan возвращает корректные данные для плана enterprise."""
    resp = await client.get(
        "/api/v1/billing/plan",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["plan"] == "enterprise"
    assert data["domain_limit"] == 999_999


@pytest.mark.asyncio
async def test_get_plan_unauthenticated(client: AsyncClient) -> None:
    """GET /billing/plan требует аутентификации."""
    resp = await client.get("/api/v1/billing/plan")
    assert resp.status_code == 401


# ─── Лимиты при создании активов ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_starter_plan_allows_up_to_3_domains(
    client: AsyncClient,
    superuser_token: str,
    org_starter: Organization,
) -> None:
    """Стартовый план позволяет добавить ровно 3 домена."""
    headers = {"Authorization": f"Bearer {superuser_token}"}

    # Добавляем 3 домена — должны пройти
    for i in range(1, 4):
        resp = await client.post(
            "/api/v1/assets/",
            json={"domain": f"domain{i}-{uuid.uuid4().hex[:6]}.example.com"},
            headers=headers,
        )
        assert resp.status_code == 201, f"Домен {i}: {resp.text}"


@pytest.mark.asyncio
async def test_starter_plan_blocks_4th_domain(
    client: AsyncClient,
    superuser_token: str,
    org_starter: Organization,
) -> None:
    """Стартовый план блокирует добавление 4-го домена с HTTP 402."""
    headers = {"Authorization": f"Bearer {superuser_token}"}

    # Добавляем 3 домена (до лимита)
    for i in range(1, 4):
        resp = await client.post(
            "/api/v1/assets/",
            json={"domain": f"limit-test{i}-{uuid.uuid4().hex[:6]}.example.com"},
            headers=headers,
        )
        assert resp.status_code == 201, f"Домен {i}: {resp.text}"

    # 4-й домен должен быть заблокирован
    resp = await client.post(
        "/api/v1/assets/",
        json={"domain": f"over-limit-{uuid.uuid4().hex[:6]}.example.com"},
        headers=headers,
    )
    assert resp.status_code == 402, f"Ожидали 402, получили {resp.status_code}: {resp.text}"
    assert "лимит" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_plan_counter_reflects_used_domains(
    client: AsyncClient,
    superuser_token: str,
    org_starter: Organization,
) -> None:
    """После добавления доменов счётчик domains_used обновляется корректно."""
    headers = {"Authorization": f"Bearer {superuser_token}"}

    # Добавляем 2 домена
    for i in range(1, 3):
        await client.post(
            "/api/v1/assets/",
            json={"domain": f"counter-test{i}-{uuid.uuid4().hex[:6]}.example.com"},
            headers=headers,
        )

    resp = await client.get("/api/v1/billing/plan", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["domains_used"] == 2
    assert data["domains_remaining"] == 1
    assert data["domain_limit"] == 3


@pytest.mark.asyncio
async def test_enterprise_plan_allows_many_domains(
    client: AsyncClient,
    superuser_token: str,
    org_enterprise: Organization,
) -> None:
    """Enterprise план позволяет добавлять домены без блокировки."""
    headers = {"Authorization": f"Bearer {superuser_token}"}

    # Добавляем 5 доменов — никаких ограничений
    for i in range(1, 6):
        resp = await client.post(
            "/api/v1/assets/",
            json={"domain": f"enterprise-{i}-{uuid.uuid4().hex[:6]}.example.com"},
            headers=headers,
        )
        assert resp.status_code == 201, f"Домен {i}: {resp.text}"


# ─── PUT /api/v1/billing/plan ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_superuser_can_update_plan(
    client: AsyncClient,
    superuser_token: str,
    org_starter: Organization,
) -> None:
    """Суперпользователь может сменить тарифный план."""
    headers = {"Authorization": f"Bearer {superuser_token}"}
    resp = await client.put(
        "/api/v1/billing/plan",
        json={"plan": "professional"},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["plan"] == "professional"
    assert data["domain_limit"] == 10


@pytest.mark.asyncio
async def test_update_plan_invalid_value(
    client: AsyncClient,
    superuser_token: str,
    org_starter: Organization,
) -> None:
    """Передача недопустимого значения плана возвращает 422."""
    resp = await client.put(
        "/api/v1/billing/plan",
        json={"plan": "ultra_premium"},
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 422
