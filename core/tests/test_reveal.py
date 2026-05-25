"""Тесты расшифровки паролей (reveal) и аудит-лога (задача 10.B)."""

import uuid

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.crypto import encrypt_password
from app.core.security import hash_password
from app.models.audit_log import AuditLog
from app.models.event import Event
from app.models.organization import Organization, OrgPlan
from app.models.user import User

TEST_PASSWORD = "testpassword"


# ─── Фикстуры ────────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def stealer_event(db_session: AsyncSession, superuser: User) -> Event:
    """Событие source_type=stealer с зашифрованным паролем, привязанное к superuser через org."""
    uid = uuid.uuid4().hex[:8]
    org = Organization(
        name=f"Reveal Org {uid}",
        slug=f"reveal-org-{uid}",
        plan=OrgPlan.professional.value,
    )
    db_session.add(org)
    await db_session.flush()

    superuser.organization_id = org.id
    await db_session.flush()

    event = Event(
        event_type="credential_leak",
        severity="high",
        source_type="stealer",
        source_name="stealer-source",
        target_domain="bank.com",
        payload={
            "password_enc": encrypt_password("secret123", settings.INTERNAL_API_SECRET),
            "login": "user@example.com",
            "url": "https://bank.com",
        },
        asset_id=None,
    )
    db_session.add(event)
    await db_session.commit()
    await db_session.refresh(event)
    return event


# ─── GET /events/{event_id}/reveal ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_reveal_returns_decrypted_password(
    client: AsyncClient,
    superuser_token: str,
    stealer_event: Event,
) -> None:
    resp = await client.get(
        f"/api/v1/events/{stealer_event.id}/reveal",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["password"] == "secret123"
    assert data["login"] == "user@example.com"
    assert data["expires_in_seconds"] == 30
    assert data["event_id"] == stealer_event.id


@pytest.mark.asyncio
async def test_reveal_writes_audit_log(
    client: AsyncClient,
    superuser_token: str,
    stealer_event: Event,
) -> None:
    await client.get(
        f"/api/v1/events/{stealer_event.id}/reveal",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )

    resp = await client.get(
        "/api/v1/audit-logs",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 200, resp.text
    logs = resp.json()
    matching = [log for log in logs if log["target_id"] == stealer_event.id]
    assert len(matching) >= 1
    assert matching[0]["action"] == "reveal_password"


@pytest.mark.asyncio
async def test_reveal_404_on_nonexistent_event(
    client: AsyncClient,
    superuser_token: str,
) -> None:
    resp = await client.get(
        "/api/v1/events/nonexistent-uuid/reveal",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_reveal_400_on_wrong_source_type(
    client: AsyncClient,
    db_session: AsyncSession,
    superuser_token: str,
) -> None:
    event = Event(
        event_type="subdomain_found",
        severity="info",
        source_type="subfinder",
        source_name="subfinder",
        target_domain="example.com",
        payload={"subdomain": "test.example.com"},
        asset_id=None,
    )
    db_session.add(event)
    await db_session.commit()
    await db_session.refresh(event)

    resp = await client.get(
        f"/api/v1/events/{event.id}/reveal",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_reveal_404_when_no_password_enc(
    client: AsyncClient,
    db_session: AsyncSession,
    superuser_token: str,
) -> None:
    event = Event(
        event_type="credential_leak",
        severity="high",
        source_type="stealer",
        source_name="stealer-source",
        target_domain="example.com",
        payload={},
        asset_id=None,
    )
    db_session.add(event)
    await db_session.commit()
    await db_session.refresh(event)

    resp = await client.get(
        f"/api/v1/events/{event.id}/reveal",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_reveal_requires_auth(
    client: AsyncClient,
    stealer_event: Event,
) -> None:
    resp = await client.get(f"/api/v1/events/{stealer_event.id}/reveal")
    assert resp.status_code == 401


# ─── GET /audit-logs ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_audit_logs_superuser_only(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    email = f"regular_{uuid.uuid4().hex[:8]}@test.com"
    regular = User(
        email=email,
        hashed_password=hash_password(TEST_PASSWORD),
        is_superuser=False,
    )
    db_session.add(regular)
    await db_session.commit()

    token_resp = await client.post(
        "/api/v1/auth/token",
        data={"username": email, "password": TEST_PASSWORD},
    )
    assert token_resp.status_code == 200
    token = token_resp.json()["access_token"]

    resp = await client.get(
        "/api/v1/audit-logs",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_audit_logs_returns_list(
    client: AsyncClient,
    superuser_token: str,
) -> None:
    resp = await client.get(
        "/api/v1/audit-logs",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)
