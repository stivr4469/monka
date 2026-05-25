"""Тесты центра уведомлений (задача 10.I)."""

import uuid

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.notification import Notification
from app.models.organization import Organization, OrgPlan
from app.models.user import User


# ─── Фикстуры ────────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def org_with_notifications(db_session: AsyncSession, superuser: User) -> Organization:
    """Организация с 2 непрочитанными уведомлениями, привязанная к superuser."""
    uid = uuid.uuid4().hex[:8]
    org = Organization(
        name=f"Notif Org {uid}",
        slug=f"notif-org-{uid}",
        plan=OrgPlan.starter.value,
    )
    db_session.add(org)
    await db_session.flush()

    superuser.organization_id = org.id
    await db_session.flush()

    for i in range(2):
        notif = Notification(
            org_id=org.id,
            message=f"Тестовое уведомление {i + 1}",
            severity="info",
            is_read=False,
        )
        db_session.add(notif)

    await db_session.commit()
    await db_session.refresh(org)
    return org


# ─── GET /notifications ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_notifications_empty_for_new_user(
    client: AsyncClient,
    superuser_token: str,
    superuser: User,
) -> None:
    resp = await client.get(
        "/api/v1/notifications",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == []


@pytest.mark.asyncio
async def test_notifications_list_org(
    client: AsyncClient,
    superuser_token: str,
    org_with_notifications: Organization,
) -> None:
    resp = await client.get(
        "/api/v1/notifications",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert len(data) == 2


# ─── GET /notifications/count ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_notifications_count_zero(
    client: AsyncClient,
    superuser_token: str,
    superuser: User,
) -> None:
    resp = await client.get(
        "/api/v1/notifications/count",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"unread": 0}


@pytest.mark.asyncio
async def test_notifications_count_unread(
    client: AsyncClient,
    superuser_token: str,
    org_with_notifications: Organization,
) -> None:
    resp = await client.get(
        "/api/v1/notifications/count",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["unread"] == 2


# ─── POST /notifications/{id}/read ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_notifications_mark_read(
    client: AsyncClient,
    superuser_token: str,
    org_with_notifications: Organization,
) -> None:
    list_resp = await client.get(
        "/api/v1/notifications",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    notif_id = list_resp.json()[0]["id"]

    read_resp = await client.post(
        f"/api/v1/notifications/{notif_id}/read",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert read_resp.status_code == 200, read_resp.text
    assert read_resp.json()["status"] == "ok"

    count_resp = await client.get(
        "/api/v1/notifications/count",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert count_resp.json()["unread"] == 1


# ─── POST /notifications/read-all ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_notifications_mark_all_read(
    client: AsyncClient,
    superuser_token: str,
    org_with_notifications: Organization,
) -> None:
    resp = await client.post(
        "/api/v1/notifications/read-all",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["updated"] == 2

    count_resp = await client.get(
        "/api/v1/notifications/count",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert count_resp.json()["unread"] == 0


# ─── Порядок сортировки ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_notifications_unread_first(
    client: AsyncClient,
    db_session: AsyncSession,
    superuser_token: str,
    superuser: User,
) -> None:
    uid = uuid.uuid4().hex[:8]
    org = Organization(
        name=f"Sort Org {uid}",
        slug=f"sort-org-{uid}",
        plan=OrgPlan.starter.value,
    )
    db_session.add(org)
    await db_session.flush()
    superuser.organization_id = org.id
    await db_session.flush()

    db_session.add(Notification(
        org_id=org.id,
        message="Прочитанное уведомление",
        severity="info",
        is_read=True,
    ))
    db_session.add(Notification(
        org_id=org.id,
        message="Непрочитанное уведомление",
        severity="high",
        is_read=False,
    ))
    await db_session.commit()

    resp = await client.get(
        "/api/v1/notifications",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 200, resp.text
    items = resp.json()
    assert len(items) == 2
    assert items[0]["is_read"] is False


# ─── Авторизация ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_notifications_unauthorized(client: AsyncClient) -> None:
    resp = await client.get("/api/v1/notifications")
    assert resp.status_code == 401
