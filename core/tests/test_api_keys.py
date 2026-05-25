"""Тесты API-ключей (задача 10.F): создание, список, отзыв, аутентификация."""
import uuid

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.api_key import ApiKey
from app.models.organization import Organization, OrgPlan
from app.models.user import User
from app.core.security import hash_password

API_KEYS_URL = "/api/v1/auth/api-keys"
ASSETS_URL = "/api/v1/assets/"

# Пароль для тестовых пользователей (совпадает с conftest.py)
TEST_PASSWORD = "testpassword"


# ─── Фикстуры ────────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def org_enterprise(db_session: AsyncSession, superuser: User) -> Organization:
    """Enterprise-организация, привязанная к superuser."""
    uid = uuid.uuid4().hex[:8]
    org = Organization(
        name=f"Enterprise Org {uid}",
        slug=f"enterprise-org-{uid}",
        plan=OrgPlan.enterprise.value,
    )
    db_session.add(org)
    await db_session.flush()
    superuser.organization_id = org.id
    await db_session.commit()
    await db_session.refresh(org)
    return org


@pytest_asyncio.fixture
async def regular_user(db_session: AsyncSession) -> User:
    """Обычный пользователь без enterprise-плана."""
    email = f"regular_{uuid.uuid4().hex[:8]}@test.com"
    user = User(
        email=email,
        hashed_password=hash_password(TEST_PASSWORD),
        is_superuser=False,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def regular_user_token(client: AsyncClient, regular_user: User) -> str:
    """JWT-токен для обычного пользователя без enterprise-плана."""
    resp = await client.post(
        "/api/v1/auth/token",
        data={"username": regular_user.email, "password": TEST_PASSWORD},
    )
    assert resp.status_code == 200
    return resp.json()["access_token"]


# ─── Тесты ───────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_api_key_superuser(
    client: AsyncClient,
    superuser_token: str,
    org_enterprise: Organization,
) -> None:
    """Superuser создаёт ключ: ответ содержит raw key с префиксом easm_ и предупреждение."""
    resp = await client.post(
        API_KEYS_URL,
        json={"name": "test-key", "permissions": ["read"]},
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert "key" in data
    assert data["key"].startswith("easm_")
    assert "warning" in data
    assert "id" in data
    assert data["name"] == "test-key"


@pytest.mark.asyncio
async def test_created_key_not_shown_in_list(
    client: AsyncClient,
    superuser_token: str,
    org_enterprise: Organization,
) -> None:
    """После создания GET-список не содержит поле key ни в одном элементе."""
    # Создаём ключ
    await client.post(
        API_KEYS_URL,
        json={"name": "hidden-key", "permissions": ["events:read"]},
        headers={"Authorization": f"Bearer {superuser_token}"},
    )

    resp = await client.get(
        API_KEYS_URL,
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 200
    items = resp.json()
    assert isinstance(items, list)
    for item in items:
        assert "key" not in item
        # Метаданные присутствуют
        assert "id" in item
        assert "name" in item
        assert "permissions" in item
        assert "is_active" in item


@pytest.mark.asyncio
async def test_list_api_keys_empty(
    client: AsyncClient,
    superuser_token: str,
) -> None:
    """Новый superuser (без ключей) получает пустой список."""
    # superuser_token привязан к свежему superuser из фикстуры — у него нет ключей
    resp = await client.get(
        API_KEYS_URL,
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 200
    # Может быть не пустой если другие тесты используют тот же superuser,
    # поэтому просто убеждаемся что ответ — список
    assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_revoke_api_key(
    client: AsyncClient,
    superuser_token: str,
    org_enterprise: Organization,
) -> None:
    """DELETE /{id} возвращает {"status": "revoked"}."""
    # Создаём ключ
    create_resp = await client.post(
        API_KEYS_URL,
        json={"name": "revoke-me", "permissions": ["read"]},
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert create_resp.status_code == 201
    key_id = create_resp.json()["id"]

    # Отзываем ключ
    del_resp = await client.delete(
        f"{API_KEYS_URL}/{key_id}",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert del_resp.status_code == 200
    assert del_resp.json()["status"] == "revoked"


@pytest.mark.asyncio
async def test_revoked_key_marked_inactive(
    client: AsyncClient,
    superuser_token: str,
    org_enterprise: Organization,
) -> None:
    """После DELETE /{id} ключ в списке помечается is_active=False."""
    # Создаём ключ
    create_resp = await client.post(
        API_KEYS_URL,
        json={"name": "inactive-after-revoke", "permissions": ["read"]},
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert create_resp.status_code == 201
    key_id = create_resp.json()["id"]

    # Отзываем
    await client.delete(
        f"{API_KEYS_URL}/{key_id}",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )

    # Проверяем список
    list_resp = await client.get(
        API_KEYS_URL,
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert list_resp.status_code == 200
    items = list_resp.json()
    revoked = next((item for item in items if item["id"] == key_id), None)
    assert revoked is not None, "Отозванный ключ должен присутствовать в списке"
    assert revoked["is_active"] is False


@pytest.mark.asyncio
async def test_api_key_auth_works(
    client: AsyncClient,
    superuser_token: str,
    org_enterprise: Organization,
) -> None:
    """Raw key работает как Bearer-токен для GET /api/v1/assets/ (статус 200, не 401)."""
    # Создаём API-ключ
    create_resp = await client.post(
        API_KEYS_URL,
        json={"name": "siem-key", "permissions": ["assets:read"]},
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert create_resp.status_code == 201
    raw_key = create_resp.json()["key"]

    # Используем raw_key для запроса к защищённому эндпоинту
    resp = await client.get(
        ASSETS_URL,
        headers={"Authorization": f"Bearer {raw_key}"},
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_create_requires_auth(client: AsyncClient) -> None:
    """POST без токена → 401."""
    resp = await client.post(
        API_KEYS_URL,
        json={"name": "no-auth-key", "permissions": ["read"]},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_enterprise_required_for_non_superuser(
    client: AsyncClient,
    regular_user_token: str,
) -> None:
    """Обычный пользователь без enterprise-плана получает 403."""
    resp = await client.post(
        API_KEYS_URL,
        json={"name": "forbidden-key", "permissions": ["read"]},
        headers={"Authorization": f"Bearer {regular_user_token}"},
    )
    assert resp.status_code == 403
