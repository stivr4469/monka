"""Тесты AI Risk Narrative — фаза 13.G."""
import os
import sys
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

# Добавляем workers в sys.path чтобы тесты видели tasks.ai_narrative
_workers_path = str(Path(__file__).parents[2] / "workers")
if _workers_path not in sys.path:
    sys.path.insert(0, _workers_path)

from tasks.ai_narrative import (
    _ANTHROPIC_AVAILABLE,
    _MODEL,
    _static_narrative,
    generate_risk_narrative,
)

from app.models.asset import Asset
from app.models.event import Event
from app.models.organization import Organization, OrgPlan
from app.models.user import User


# ─── Фикстуры ────────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def org_and_asset(db_session: AsyncSession, superuser: User):
    """Организация + актив, привязанные к superuser."""
    uid = uuid.uuid4().hex[:8]
    org = Organization(
        name=f"Narrative Org {uid}",
        slug=f"narrative-org-{uid}",
        plan=OrgPlan.starter.value,
    )
    db_session.add(org)
    await db_session.flush()

    superuser.organization_id = org.id

    asset = Asset(
        domain=f"example-{uid}.com",
        organization_id=org.id,
        is_active=True,
        importance=1.0,
    )
    db_session.add(asset)
    await db_session.commit()
    await db_session.refresh(org)
    await db_session.refresh(asset)
    return org, asset


# ─── Тесты generate_risk_narrative (unit) ────────────────────────────────────

def test_narrative_fallback_when_no_api_key():
    """Без ANTHROPIC_API_KEY возвращается статичный шаблон."""
    env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
    with patch.dict(os.environ, env, clear=True):
        result = generate_risk_narrative(
            domain="test.com",
            score=65.0,
            category_scores={"network_security": 80.0, "dns_health": 90.0},
            top_risks=[],
            org_name="Test Corp",
        )
    # Должен вернуть статичный шаблон
    assert "Test Corp" in result
    assert "65" in result
    assert "test.com" in result


def test_static_narrative_contains_score():
    """Статичный шаблон содержит score и domain."""
    result = _static_narrative(
        domain="target.org",
        score=42.0,
        category_scores={},
        top_risks=[
            {"event_type": "stealer_log", "severity": "critical", "description": "leak detected"},
        ],
        org_name="Acme Corp",
    )
    assert "42" in result
    assert "target.org" in result
    assert "Acme Corp" in result
    # Должна присутствовать буквенная оценка D (42 → D)
    assert "D" in result


def test_static_narrative_grade_a():
    """Score 95 → Grade A."""
    result = _static_narrative("x.com", 95.0, {}, [], "HighScore Inc")
    assert "A" in result


def test_static_narrative_grade_f():
    """Score 20 → Grade F."""
    result = _static_narrative("x.com", 20.0, {}, [], "LowScore Inc")
    assert "F" in result


def test_static_narrative_lists_top_risks():
    """Статичный шаблон включает переданные риски."""
    risks = [
        {"event_type": "phishing_domain", "severity": "high", "description": "clone of site"},
        {"event_type": "credential_leak", "severity": "critical", "description": "password dump"},
    ]
    result = _static_narrative("corp.com", 55.0, {}, risks, "Test Org")
    assert "phishing_domain" in result
    assert "credential_leak" in result
    assert "CRITICAL" in result


def test_generate_with_mocked_anthropic():
    """Мокируем anthropic.Anthropic().messages.create() для проверки happy path."""
    fake_text = "Executive narrative: your security posture requires attention."

    with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-test-key"}):
        with patch("tasks.ai_narrative._ANTHROPIC_AVAILABLE", True):
            with patch("tasks.ai_narrative.anthropic") as mock_anthropic_module:
                mock_client_instance = MagicMock()
                mock_anthropic_module.Anthropic.return_value = mock_client_instance
                mock_client_instance.messages.create.return_value = MagicMock(
                    content=[MagicMock(text=fake_text)]
                )
                result = generate_risk_narrative(
                    domain="example.com",
                    score=75.0,
                    category_scores={
                        "network_security": 80.0,
                        "dns_health": 90.0,
                        "application_security": 70.0,
                        "credential_exposure": 60.0,
                        "dark_web_presence": 85.0,
                        "brand_safety": 95.0,
                    },
                    top_risks=[],
                    org_name="Test Corp",
                )

    assert result == fake_text
    mock_client_instance.messages.create.assert_called_once()

    # Проверяем что prompt caching был использован (cache_control в system)
    call_kwargs = mock_client_instance.messages.create.call_args
    system_arg = call_kwargs.kwargs.get("system") or call_kwargs.args[0] if call_kwargs.args else None
    if system_arg is None:
        system_arg = call_kwargs.kwargs["system"]
    assert isinstance(system_arg, list)
    assert system_arg[0]["cache_control"]["type"] == "ephemeral"


def test_generate_falls_back_on_api_error():
    """При ошибке API возвращается статичный fallback (не поднимается исключение)."""
    with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-bad-key"}):
        with patch("tasks.ai_narrative._ANTHROPIC_AVAILABLE", True):
            with patch("tasks.ai_narrative.anthropic") as mock_anthropic_module:
                mock_client_instance = MagicMock()
                mock_anthropic_module.Anthropic.return_value = mock_client_instance
                mock_client_instance.messages.create.side_effect = Exception("connection error")

                result = generate_risk_narrative(
                    domain="error.com",
                    score=50.0,
                    category_scores={},
                    top_risks=[],
                    org_name="Error Corp",
                )

    # Должен вернуть статичный fallback без raise
    assert "Error Corp" in result
    assert "error.com" in result


# ─── Тесты HTTP endpoint ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_narrative_endpoint_returns_200(
    client: AsyncClient,
    superuser_token: str,
    org_and_asset: tuple,
):
    """POST /api/v1/ai/narrative возвращает 200 с narrative."""
    org, asset = org_and_asset

    with patch("app.api.v1.endpoints.ai_narrative.generate_risk_narrative") as mock_gen:
        mock_gen.return_value = "Mocked executive summary for test."

        resp = await client.post(
            "/api/v1/ai/narrative",
            json={"asset_id": asset.id, "days": 7},
            headers={"Authorization": f"Bearer {superuser_token}"},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert "narrative" in data
    assert data["narrative"] == "Mocked executive summary for test."
    assert "model" in data
    assert "cached" in data


@pytest.mark.asyncio
async def test_narrative_endpoint_404_unknown_asset(
    client: AsyncClient,
    superuser_token: str,
    org_and_asset: tuple,
):
    """POST /api/v1/ai/narrative с неизвестным asset_id возвращает 404."""
    resp = await client.post(
        "/api/v1/ai/narrative",
        json={"asset_id": str(uuid.uuid4()), "days": 7},
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_narrative_endpoint_requires_auth(
    client: AsyncClient,
    org_and_asset: tuple,
):
    """POST /api/v1/ai/narrative без токена возвращает 401/403."""
    org, asset = org_and_asset
    resp = await client.post(
        "/api/v1/ai/narrative",
        json={"asset_id": asset.id, "days": 7},
    )
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_narrative_endpoint_static_fallback_no_api_key(
    client: AsyncClient,
    superuser_token: str,
    org_and_asset: tuple,
):
    """При отсутствии ANTHROPIC_API_KEY endpoint возвращает статичный нарратив."""
    org, asset = org_and_asset
    env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}

    with patch.dict(os.environ, env, clear=True):
        resp = await client.post(
            "/api/v1/ai/narrative",
            json={"asset_id": asset.id, "days": 7},
            headers={"Authorization": f"Bearer {superuser_token}"},
        )

    assert resp.status_code == 200
    data = resp.json()
    # Статичный шаблон содержит domain актива
    assert asset.domain in data["narrative"]
    assert data["model"] == "static-template"
