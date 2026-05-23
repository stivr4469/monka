"""Тесты авторизации."""
import pytest
from httpx import AsyncClient

from app.models.user import User
from tests.conftest import TEST_PASSWORD


@pytest.mark.asyncio
async def test_login_success(client: AsyncClient, superuser: User):
    resp = await client.post(
        "/api/v1/auth/token",
        data={"username": superuser.email, "password": TEST_PASSWORD},
    )
    assert resp.status_code == 200
    assert "access_token" in resp.json()
    assert resp.json()["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_login_wrong_password(client: AsyncClient, superuser: User):
    resp = await client.post(
        "/api/v1/auth/token",
        data={"username": superuser.email, "password": "wrongpass"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_login_unknown_user(client: AsyncClient):
    resp = await client.post(
        "/api/v1/auth/token",
        data={"username": "nobody@test.com", "password": TEST_PASSWORD},
    )
    assert resp.status_code == 401
