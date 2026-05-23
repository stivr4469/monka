"""Тесты CRUD активов."""
import uuid

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.organization import Organization
from app.models.user import User


@pytest_asyncio.fixture
async def org_with_user(db_session: AsyncSession, superuser: User) -> Organization:
    uid = uuid.uuid4().hex[:8]
    org = Organization(name=f"Test Org {uid}", slug=f"test-org-{uid}")
    db_session.add(org)
    await db_session.flush()
    superuser.organization_id = org.id
    await db_session.commit()
    await db_session.refresh(org)
    return org


@pytest.mark.asyncio
async def test_create_asset(client: AsyncClient, superuser_token: str, org_with_user: Organization):
    resp = await client.post(
        "/api/v1/assets/",
        json={"domain": "target.example.com", "description": "Main site"},
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["domain"] == "target.example.com"
    assert "id" in data


@pytest.mark.asyncio
async def test_list_assets(client: AsyncClient, superuser_token: str, org_with_user: Organization):
    resp = await client.get(
        "/api/v1/assets/",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_asset_not_found(client: AsyncClient, superuser_token: str, org_with_user: Organization):
    resp = await client.get(
        "/api/v1/assets/nonexistent-id",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_unauthenticated_access(client: AsyncClient):
    resp = await client.get("/api/v1/assets/")
    assert resp.status_code == 401
