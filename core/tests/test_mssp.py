"""
Тесты MSSP Multi-Tenancy API (задача 9.F).

Покрывают:
  - 403 для обычных пользователей
  - superuser видит все организации
  - mssp_operator видит только свои организации
  - GET /clients/{org_id} с проверкой доступа
  - POST /clients/{org_id}/assign (только superuser)
  - POST /clients/{org_id}/unassign (только superuser)
  - Корректный расчёт risk_score и risk_delta_24h
  - Сортировка по деградации
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.models.asset import Asset
from app.models.event import Event
from app.models.organization import Organization
from app.models.user import User

# Пароль для тестовых пользователей — переиспользуем константу из conftest
TEST_PASSWORD = "testpassword"


# ─── Вспомогательные фикстуры ────────────────────────────────────────────────

@pytest_asyncio.fixture
async def mssp_operator(db_session: AsyncSession) -> User:
    """Пользователь с флагом is_mssp_operator=True без организации."""
    email = f"mssp_{uuid.uuid4().hex[:8]}@test.com"
    user = User(
        email=email,
        hashed_password=hash_password(TEST_PASSWORD),
        is_mssp_operator=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def regular_user(db_session: AsyncSession) -> User:
    """Обычный пользователь без особых прав."""
    email = f"regular_{uuid.uuid4().hex[:8]}@test.com"
    user = User(
        email=email,
        hashed_password=hash_password(TEST_PASSWORD),
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def mssp_operator_token(client: AsyncClient, mssp_operator: User) -> str:
    resp = await client.post(
        "/api/v1/auth/token",
        data={"username": mssp_operator.email, "password": TEST_PASSWORD},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


@pytest_asyncio.fixture
async def regular_user_token(client: AsyncClient, regular_user: User) -> str:
    resp = await client.post(
        "/api/v1/auth/token",
        data={"username": regular_user.email, "password": TEST_PASSWORD},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


async def _make_org(db: AsyncSession, name: str, owner_id: str | None = None) -> Organization:
    """Создаёт организацию и опционально привязывает к MSSP-оператору."""
    uid = uuid.uuid4().hex[:6]
    org = Organization(
        name=f"{name} {uid}",
        slug=f"{name.lower().replace(' ', '-')}-{uid}",
        mssp_owner_id=owner_id,
    )
    db.add(org)
    await db.commit()
    await db.refresh(org)
    return org


async def _make_asset(db: AsyncSession, org: Organization, domain: str) -> Asset:
    asset = Asset(domain=domain, organization_id=org.id)
    db.add(asset)
    await db.commit()
    await db.refresh(asset)
    return asset


async def _make_event(
    db: AsyncSession,
    asset: Asset,
    severity: str,
    hours_ago: float = 1.0,
) -> Event:
    """Создаёт событие с заданным severity и временем обнаружения."""
    detected_at = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    ev = Event(
        event_type="test_event",
        severity=severity,
        source_type="test",
        source_name="test-source",
        target_domain=asset.domain,
        payload={"test": True},
        detected_at=detected_at,
        asset_id=asset.id,
    )
    db.add(ev)
    await db.commit()
    await db.refresh(ev)
    return ev


# ─── Тесты авторизации ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_mssp_clients_requires_auth(client: AsyncClient):
    """Без токена — 401."""
    resp = await client.get("/api/v1/mssp/clients")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_mssp_clients_forbidden_for_regular_user(
    client: AsyncClient, regular_user_token: str
):
    """Обычный пользователь получает 403."""
    resp = await client.get(
        "/api/v1/mssp/clients",
        headers={"Authorization": f"Bearer {regular_user_token}"},
    )
    assert resp.status_code == 403
    assert "MSSP" in resp.json()["detail"] or "оператор" in resp.json()["detail"].lower()


# ─── Тесты superuser доступа ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_superuser_sees_all_orgs(
    client: AsyncClient,
    db_session: AsyncSession,
    superuser_token: str,
    superuser: User,
):
    """Superuser видит все организации, даже без mssp_owner_id."""
    org_a = await _make_org(db_session, "Alpha Corp")
    org_b = await _make_org(db_session, "Beta Corp")

    resp = await client.get(
        "/api/v1/mssp/clients",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    org_ids = {c["organization_id"] for c in data}
    assert org_a.id in org_ids
    assert org_b.id in org_ids


@pytest.mark.asyncio
async def test_superuser_sees_org_details(
    client: AsyncClient,
    db_session: AsyncSession,
    superuser_token: str,
):
    """Superuser видит детали конкретной организации."""
    org = await _make_org(db_session, "Gamma Corp")

    resp = await client.get(
        f"/api/v1/mssp/clients/{org.id}",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["organization_id"] == org.id


# ─── Тесты mssp_operator доступа ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_mssp_operator_sees_only_own_orgs(
    client: AsyncClient,
    db_session: AsyncSession,
    mssp_operator: User,
    mssp_operator_token: str,
):
    """MSSP-оператор видит только организации, где mssp_owner_id == operator.id."""
    org_mine  = await _make_org(db_session, "My Client", owner_id=mssp_operator.id)
    org_other = await _make_org(db_session, "Someone Else Client")  # без привязки

    resp = await client.get(
        "/api/v1/mssp/clients",
        headers={"Authorization": f"Bearer {mssp_operator_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    org_ids = {c["organization_id"] for c in data}
    assert org_mine.id in org_ids
    assert org_other.id not in org_ids


@pytest.mark.asyncio
async def test_mssp_operator_empty_when_no_clients(
    client: AsyncClient,
    db_session: AsyncSession,
    mssp_operator_token: str,
):
    """MSSP-оператор без клиентов получает пустой список."""
    # Создаём отдельного оператора без клиентов
    email = f"empty_mssp_{uuid.uuid4().hex[:6]}@test.com"
    empty_op = User(
        email=email,
        hashed_password=hash_password(TEST_PASSWORD),
        is_mssp_operator=True,
    )
    db_session.add(empty_op)
    await db_session.commit()

    token_resp = await client.post(
        "/api/v1/auth/token",
        data={"username": email, "password": TEST_PASSWORD},
    )
    token = token_resp.json()["access_token"]

    resp = await client.get(
        "/api/v1/mssp/clients",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_mssp_operator_forbidden_on_other_org(
    client: AsyncClient,
    db_session: AsyncSession,
    mssp_operator_token: str,
):
    """MSSP-оператор получает 403 при запросе чужой организации."""
    org_foreign = await _make_org(db_session, "Foreign Corp")

    resp = await client.get(
        f"/api/v1/mssp/clients/{org_foreign.id}",
        headers={"Authorization": f"Bearer {mssp_operator_token}"},
    )
    assert resp.status_code == 403


# ─── Тесты схемы ответа ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_client_summary_fields(
    client: AsyncClient,
    db_session: AsyncSession,
    superuser_token: str,
    superuser: User,
):
    """Ответ содержит все обязательные поля ClientRiskSummary."""
    org = await _make_org(db_session, "Schema Test Org")

    resp = await client.get(
        f"/api/v1/mssp/clients/{org.id}",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()

    required_fields = {
        "organization_id", "organization_name", "plan", "domain_count",
        "risk_score", "risk_delta_24h", "critical_events", "last_event_at",
    }
    assert required_fields.issubset(data.keys()), f"Отсутствуют поля: {required_fields - data.keys()}"
    assert data["domain_count"] == 0
    assert 0 <= data["risk_score"] <= 100
    assert data["last_event_at"] is None


# ─── Тесты расчёта Risk Score ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_risk_score_decreases_with_critical_events(
    client: AsyncClient,
    db_session: AsyncSession,
    superuser_token: str,
):
    """Critical-события снижают Risk Score ниже 100."""
    org = await _make_org(db_session, "Risk Score Test")
    asset = await _make_asset(db_session, org, f"risk-{uuid.uuid4().hex[:6]}.test")

    # Создаём critical-событие в пределах 24ч
    await _make_event(db_session, asset, "critical", hours_ago=2)

    resp = await client.get(
        f"/api/v1/mssp/clients/{org.id}",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    # Risk Score должен быть меньше 100 (100 - 25 = 75)
    assert data["risk_score"] < 100
    assert data["critical_events"] == 1


@pytest.mark.asyncio
async def test_risk_score_is_100_with_no_events(
    client: AsyncClient,
    db_session: AsyncSession,
    superuser_token: str,
):
    """Без событий Risk Score = 100."""
    org = await _make_org(db_session, "Clean Org")
    await _make_asset(db_session, org, f"clean-{uuid.uuid4().hex[:6]}.test")

    resp = await client.get(
        f"/api/v1/mssp/clients/{org.id}",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["risk_score"] == 100


@pytest.mark.asyncio
async def test_risk_score_clamped_to_zero(
    client: AsyncClient,
    db_session: AsyncSession,
    superuser_token: str,
):
    """Risk Score не может быть меньше 0 даже при множестве событий."""
    org = await _make_org(db_session, "Heavily Attacked Org")
    asset = await _make_asset(db_session, org, f"attacked-{uuid.uuid4().hex[:6]}.test")

    # Добавляем много critical-событий (более 4 × 25 = 100 штрафа)
    for _ in range(6):
        await _make_event(db_session, asset, "critical", hours_ago=1)

    resp = await client.get(
        f"/api/v1/mssp/clients/{org.id}",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["risk_score"] == 0


# ─── Тесты risk_delta_24h ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_risk_delta_is_negative_when_degraded(
    client: AsyncClient,
    db_session: AsyncSession,
    superuser_token: str,
):
    """
    Если сейчас больше событий чем 24–48ч назад — delta отрицательная (ухудшение).

    Сценарий:
      - Предыдущий период (24–48ч): нет событий  → score_prev = 100
      - Текущий период (0–24ч): 1 critical        → score_now  = 75
      - delta = 75 - 100 = -25 (ухудшение)
    """
    org = await _make_org(db_session, "Degraded Org")
    asset = await _make_asset(db_session, org, f"degraded-{uuid.uuid4().hex[:6]}.test")

    # Событие в текущем окне (2 часа назад)
    await _make_event(db_session, asset, "critical", hours_ago=2)

    resp = await client.get(
        f"/api/v1/mssp/clients/{org.id}",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_delta_24h"] < 0, f"Ожидался отрицательный delta, получили: {data['risk_delta_24h']}"


@pytest.mark.asyncio
async def test_risk_delta_is_positive_when_improved(
    client: AsyncClient,
    db_session: AsyncSession,
    superuser_token: str,
):
    """
    Если сейчас меньше событий чем 24–48ч назад — delta положительная (улучшение).

    Сценарий:
      - Предыдущий период (24–48ч): 1 critical  → score_prev = 75
      - Текущий период (0–24ч): нет событий    → score_now  = 100
      - delta = 100 - 75 = +25 (улучшение)
    """
    org = await _make_org(db_session, "Improved Org")
    asset = await _make_asset(db_session, org, f"improved-{uuid.uuid4().hex[:6]}.test")

    # Событие в предыдущем окне (30 часов назад, т.е. 24–48ч)
    await _make_event(db_session, asset, "critical", hours_ago=30)

    resp = await client.get(
        f"/api/v1/mssp/clients/{org.id}",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_delta_24h"] > 0, f"Ожидался положительный delta, получили: {data['risk_delta_24h']}"


# ─── Тесты сортировки ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_clients_sorted_by_degradation(
    client: AsyncClient,
    db_session: AsyncSession,
    superuser: User,
    superuser_token: str,
):
    """
    Клиенты отсортированы по деградации: сначала худший risk_delta_24h.

    Создаём оператора с двумя клиентами:
      - Клиент A: много текущих событий, delta < 0 (деградация)
      - Клиент B: нет событий, delta = 0 (стабильно)
    Клиент A должен быть первым в ответе.
    """
    # Создаём отдельного оператора для этого теста
    op_email = f"sort_op_{uuid.uuid4().hex[:6]}@test.com"
    sort_op = User(
        email=op_email,
        hashed_password=hash_password(TEST_PASSWORD),
        is_mssp_operator=True,
    )
    db_session.add(sort_op)
    await db_session.commit()
    await db_session.refresh(sort_op)

    op_token_resp = await client.post(
        "/api/v1/auth/token",
        data={"username": op_email, "password": TEST_PASSWORD},
    )
    op_token = op_token_resp.json()["access_token"]

    # Оба клиента принадлежат нашему оператору
    org_bad  = await _make_org(db_session, "Bad Client",    owner_id=sort_op.id)
    org_good = await _make_org(db_session, "Stable Client", owner_id=sort_op.id)

    asset_bad = await _make_asset(db_session, org_bad, f"bad-{uuid.uuid4().hex[:6]}.test")
    # Добавляем critical-событие только в текущем окне (деградация)
    await _make_event(db_session, asset_bad, "critical", hours_ago=1)

    resp = await client.get(
        "/api/v1/mssp/clients",
        headers={"Authorization": f"Bearer {op_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 2

    # Первый элемент должен быть с наименьшим delta (деградировавший)
    assert data[0]["organization_id"] == org_bad.id, (
        f"Ожидался деградировавший клиент первым, "
        f"получили: {data[0]['organization_name']} (delta={data[0]['risk_delta_24h']})"
    )


# ─── Тесты assign/unassign (только superuser) ────────────────────────────────

@pytest.mark.asyncio
async def test_assign_client_to_operator(
    client: AsyncClient,
    db_session: AsyncSession,
    superuser_token: str,
    mssp_operator: User,
):
    """Superuser успешно привязывает организацию к MSSP-оператору."""
    org = await _make_org(db_session, "Unassigned Org")
    assert org.mssp_owner_id is None

    resp = await client.post(
        f"/api/v1/mssp/clients/{org.id}/assign",
        json={"operator_id": mssp_operator.id},
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["mssp_owner_id"] == mssp_operator.id

    # Оператор теперь видит эту организацию в своём списке
    op_token_resp = await client.post(
        "/api/v1/auth/token",
        data={"username": mssp_operator.email, "password": TEST_PASSWORD},
    )
    op_token = op_token_resp.json()["access_token"]

    list_resp = await client.get(
        "/api/v1/mssp/clients",
        headers={"Authorization": f"Bearer {op_token}"},
    )
    assert list_resp.status_code == 200
    org_ids = {c["organization_id"] for c in list_resp.json()}
    assert org.id in org_ids


@pytest.mark.asyncio
async def test_assign_forbidden_for_mssp_operator(
    client: AsyncClient,
    db_session: AsyncSession,
    mssp_operator_token: str,
    mssp_operator: User,
):
    """MSSP-оператор не может самостоятельно привязывать организации."""
    org = await _make_org(db_session, "No Self Assign Org")

    resp = await client.post(
        f"/api/v1/mssp/clients/{org.id}/assign",
        json={"operator_id": mssp_operator.id},
        headers={"Authorization": f"Bearer {mssp_operator_token}"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_assign_to_non_operator_fails(
    client: AsyncClient,
    db_session: AsyncSession,
    superuser_token: str,
    regular_user: User,
):
    """Нельзя назначить организацию пользователю без роли MSSP-оператора."""
    org = await _make_org(db_session, "Wrong Operator Org")

    resp = await client.post(
        f"/api/v1/mssp/clients/{org.id}/assign",
        json={"operator_id": regular_user.id},
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_unassign_client(
    client: AsyncClient,
    db_session: AsyncSession,
    superuser_token: str,
    mssp_operator: User,
):
    """Superuser успешно отвязывает организацию от MSSP-оператора."""
    org = await _make_org(db_session, "To Unassign Org", owner_id=mssp_operator.id)
    assert org.mssp_owner_id == mssp_operator.id

    resp = await client.post(
        f"/api/v1/mssp/clients/{org.id}/unassign",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 200

    # После unassign оператор не видит организацию
    op_token_resp = await client.post(
        "/api/v1/auth/token",
        data={"username": mssp_operator.email, "password": TEST_PASSWORD},
    )
    op_token = op_token_resp.json()["access_token"]

    list_resp = await client.get(
        "/api/v1/mssp/clients",
        headers={"Authorization": f"Bearer {op_token}"},
    )
    org_ids = {c["organization_id"] for c in list_resp.json()}
    assert org.id not in org_ids


# ─── Тесты 404 ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_nonexistent_org(
    client: AsyncClient, superuser_token: str
):
    """404 для несуществующей организации."""
    resp = await client.get(
        "/api/v1/mssp/clients/nonexistent-uuid",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_assign_nonexistent_org(
    client: AsyncClient,
    db_session: AsyncSession,
    superuser_token: str,
    mssp_operator: User,
):
    """404 при попытке привязать несуществующую организацию."""
    resp = await client.post(
        "/api/v1/mssp/clients/nonexistent-uuid/assign",
        json={"operator_id": mssp_operator.id},
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 404
