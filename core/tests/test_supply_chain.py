"""Тесты Phase 12.C — Supply Chain Monitoring.

Проверяют создание и получение vendor/subsidiary активов,
привязанных к primary asset организации.
"""
import uuid

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.organization import Organization
from app.models.user import User

ASSETS_URL = "/api/v1/assets"


# ─── Фикстуры ────────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def org_with_user(db_session: AsyncSession, superuser: User) -> Organization:
    """Организация, привязанная к superuser."""
    uid = uuid.uuid4().hex[:8]
    org = Organization(name=f"SC Org {uid}", slug=f"sc-org-{uid}")
    db_session.add(org)
    await db_session.flush()
    superuser.organization_id = org.id
    await db_session.commit()
    await db_session.refresh(org)
    return org


@pytest_asyncio.fixture
async def asset(client: AsyncClient, superuser_token: str, org_with_user: Organization) -> dict:
    """Primary актив, созданный через API."""
    uid = uuid.uuid4().hex[:8]
    resp = await client.post(
        f"{ASSETS_URL}/",
        json={"domain": f"primary-{uid}.example.com", "description": "Primary Asset"},
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 201, f"Не удалось создать primary asset: {resp.text}"
    return resp.json()


@pytest_asyncio.fixture
async def vendor_asset(client: AsyncClient, superuser_token: str, asset: dict) -> dict:
    """Vendor актив, привязанный к primary asset."""
    uid = uuid.uuid4().hex[:8]
    resp = await client.post(
        f"{ASSETS_URL}/{asset['id']}/supply-chain",
        json={"domain": f"vendor-{uid}.com", "asset_type": "vendor"},
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 201, f"Не удалось создать vendor asset: {resp.text}"
    return resp.json()


# ─── Тесты ───────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_add_vendor_domain(client: AsyncClient, superuser_token: str, asset: dict):
    """POST /assets/{id}/supply-chain создаёт vendor asset с корректными полями."""
    uid = uuid.uuid4().hex[:8]
    resp = await client.post(
        f"{ASSETS_URL}/{asset['id']}/supply-chain",
        json={"domain": f"vendor-{uid}.com", "asset_type": "vendor"},
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["asset_type"] == "vendor"
    assert data["parent_asset_id"] == asset["id"]
    assert "id" in data
    assert data["domain"] == f"vendor-{uid}.com"


@pytest.mark.asyncio
async def test_add_subsidiary_domain(client: AsyncClient, superuser_token: str, asset: dict):
    """POST /assets/{id}/supply-chain создаёт subsidiary asset."""
    uid = uuid.uuid4().hex[:8]
    resp = await client.post(
        f"{ASSETS_URL}/{asset['id']}/supply-chain",
        json={"domain": f"sub-{uid}.example.com", "asset_type": "subsidiary"},
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["asset_type"] == "subsidiary"
    assert data["parent_asset_id"] == asset["id"]


@pytest.mark.asyncio
async def test_list_supply_chain(
    client: AsyncClient, superuser_token: str, asset: dict, vendor_asset: dict
):
    """GET /assets/{id}/supply-chain возвращает список supply chain активов."""
    resp = await client.get(
        f"{ASSETS_URL}/{asset['id']}/supply-chain",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    # Проверяем что наш vendor asset есть в списке
    ids = [item["id"] for item in data]
    assert vendor_asset["id"] in ids


@pytest.mark.asyncio
async def test_vendor_asset_has_correct_type(
    client: AsyncClient, superuser_token: str, asset: dict, vendor_asset: dict
):
    """Все активы в supply-chain list имеют корректный asset_type."""
    resp = await client.get(
        f"{ASSETS_URL}/{asset['id']}/supply-chain",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    for item in data:
        assert item["asset_type"] in ("vendor", "subsidiary")
        assert item["parent_asset_id"] == asset["id"]


@pytest.mark.asyncio
async def test_supply_chain_requires_auth(client: AsyncClient, asset: dict):
    """POST и GET /supply-chain возвращают 401 без токена авторизации."""
    uid = uuid.uuid4().hex[:8]
    # POST без токена
    resp_post = await client.post(
        f"{ASSETS_URL}/{asset['id']}/supply-chain",
        json={"domain": f"vendor-{uid}.com", "asset_type": "vendor"},
    )
    assert resp_post.status_code == 401

    # GET без токена
    resp_get = await client.get(
        f"{ASSETS_URL}/{asset['id']}/supply-chain",
    )
    assert resp_get.status_code == 401


@pytest.mark.asyncio
async def test_cannot_add_vendor_to_vendor(
    client: AsyncClient, superuser_token: str, asset: dict, vendor_asset: dict
):
    """Нельзя добавить vendor актив к другому vendor (только к primary)."""
    uid = uuid.uuid4().hex[:8]
    resp = await client.post(
        f"{ASSETS_URL}/{vendor_asset['id']}/supply-chain",
        json={"domain": f"nested-{uid}.com", "asset_type": "vendor"},
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 400
    detail = resp.json().get("detail", "")
    assert "primary" in detail.lower() or "vendor" in detail.lower()


@pytest.mark.asyncio
async def test_supply_chain_list_empty_for_new_asset(
    client: AsyncClient, superuser_token: str, asset: dict
):
    """Новый primary asset имеет пустой список supply chain."""
    uid = uuid.uuid4().hex[:8]
    # Создаём отдельный primary asset без вендоров
    resp_create = await client.post(
        f"{ASSETS_URL}/",
        json={"domain": f"lonely-{uid}.example.com"},
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp_create.status_code == 201
    new_asset = resp_create.json()

    resp = await client.get(
        f"{ASSETS_URL}/{new_asset['id']}/supply-chain",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_supply_chain_not_found_for_unknown_asset(
    client: AsyncClient, superuser_token: str, org_with_user: Organization
):
    """GET /assets/{unknown_id}/supply-chain возвращает 404."""
    resp = await client.get(
        f"{ASSETS_URL}/nonexistent-asset-id/supply-chain",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_primary_asset_has_correct_default_type(
    client: AsyncClient, superuser_token: str, asset: dict
):
    """Primary asset созданный через POST /assets/ имеет asset_type='primary'."""
    assert asset["asset_type"] == "primary"
    assert asset["parent_asset_id"] is None
