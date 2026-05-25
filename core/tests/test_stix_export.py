"""
Тесты для STIX 2.1 export — Phase 13.E.

Покрытие:
- Структура Bundle (тип, spec_version)
- Маппинг event_type → STIX объекты
- Минимальный Bundle при пустом списке событий
- HTTP эндпоинты: авторизация и формат ответа
"""
import sys
import uuid
from pathlib import Path

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

# Подключаем workers в sys.path
_workers_path = str(Path(__file__).parents[3] / "workers")
if _workers_path not in sys.path:
    sys.path.insert(0, _workers_path)

from tasks.stix_export import (
    events_to_stix_bundle,
    event_to_indicator,
    event_to_observed_data,
    event_to_vulnerability,
)

from app.models.organization import Organization, OrgPlan
from app.models.user import User

# ---------------------------------------------------------------------------
# Тестовые фикстуры / данные
# ---------------------------------------------------------------------------

STEALER_EVENT = {
    "event_type": "stealer_log",
    "severity": "critical",
    "target_domain": "example.com",
    "payload": {"email": "user@example.com", "login": "user", "url": "https://example.com"},
    "created_at": "2026-05-25T10:00:00",
    "source_name": "stealer_parser",
}

PORT_SCAN_EVENT = {
    "event_type": "port_scan",
    "severity": "medium",
    "target_domain": "example.com",
    "payload": {"port": 22, "protocol": "tcp", "state": "open"},
    "created_at": "2026-05-25T10:00:00",
    "source_name": "masscan",
}

NUCLEI_EVENT = {
    "event_type": "nuclei_finding",
    "severity": "high",
    "target_domain": "example.com",
    "payload": {"cve": "CVE-2021-44228", "template_id": "log4j-rce", "url": "https://example.com"},
    "created_at": "2026-05-25T10:00:00",
    "source_name": "nuclei",
}

NUCLEI_NO_CVE_EVENT = {
    "event_type": "nuclei_finding",
    "severity": "low",
    "target_domain": "target.org",
    "payload": {"template_id": "exposed-panel", "name": "Admin Panel"},
    "created_at": "2026-05-25T10:00:00",
    "source_name": "nuclei",
}

DARK_WEB_EVENT = {
    "event_type": "dark_web_mention",
    "severity": "high",
    "target_domain": "corp.com",
    "payload": {"group": "LockBit", "source": "forum", "snippet": "selling data"},
    "created_at": "2026-05-25T10:00:00",
    "source_name": "darknet_monitor",
}

RANSOMWARE_EVENT = {
    "event_type": "ransomware_mention",
    "severity": "critical",
    "target_domain": "victim.io",
    "payload": {"group": "BlackCat", "published_at": "2026-05-25"},
    "created_at": "2026-05-25T10:00:00",
    "source_name": "ransomware_sites",
}

BREACH_EVENT = {
    "event_type": "breach",
    "severity": "high",
    "target_domain": "breached.com",
    "payload": {"records_count": 5000, "source": "HIBP"},
    "created_at": "2026-05-25T10:00:00",
    "source_name": "breach_checker",
}

GENERIC_LOW_EVENT = {
    "event_type": "tls_expiry",
    "severity": "low",
    "target_domain": "mysite.net",
    "payload": {"days_left": 5, "cert_cn": "mysite.net"},
    "created_at": "2026-05-25T10:00:00",
    "source_name": "tls_scanner",
}


# ---------------------------------------------------------------------------
# Юнит-тесты: events_to_stix_bundle
# ---------------------------------------------------------------------------


def test_bundle_has_correct_type():
    """Bundle должен иметь type == 'bundle'."""
    bundle = events_to_stix_bundle([STEALER_EVENT], "Test Corp")
    assert bundle["type"] == "bundle"


def test_bundle_spec_version():
    """spec_version должна быть '2.1'."""
    bundle = events_to_stix_bundle([STEALER_EVENT], "Test Corp")
    assert bundle["spec_version"] == "2.1"


def test_bundle_has_id():
    """Bundle должен иметь id в формате bundle--<uuid>."""
    bundle = events_to_stix_bundle([STEALER_EVENT], "Test Corp")
    assert "id" in bundle
    assert bundle["id"].startswith("bundle--")


def test_bundle_has_objects_list():
    """Bundle.objects должен быть списком."""
    bundle = events_to_stix_bundle([STEALER_EVENT], "Test Corp")
    assert isinstance(bundle["objects"], list)


def test_empty_events_returns_minimal_bundle():
    """При пустом списке событий Bundle содержит только Identity object."""
    bundle = events_to_stix_bundle([], "Empty Org")
    assert bundle["type"] == "bundle"
    assert bundle["spec_version"] == "2.1"
    objects = bundle["objects"]
    # Только identity
    assert len(objects) == 1
    assert objects[0]["type"] == "identity"


def test_identity_object_present():
    """В Bundle всегда есть Identity object с корректными полями."""
    bundle = events_to_stix_bundle([STEALER_EVENT], "My Company")
    identity_objs = [o for o in bundle["objects"] if o["type"] == "identity"]
    assert len(identity_objs) == 1
    identity = identity_objs[0]
    assert identity["name"] == "My Company"
    assert identity["identity_class"] == "system"
    assert identity["spec_version"] == "2.1"
    assert identity["id"].startswith("identity--")


def test_stealer_log_becomes_indicator():
    """stealer_log события должны порождать Indicator объект."""
    bundle = events_to_stix_bundle([STEALER_EVENT], "Test Corp")
    indicator_objs = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert len(indicator_objs) >= 1
    ind = indicator_objs[0]
    assert ind["spec_version"] == "2.1"
    assert ind["id"].startswith("indicator--")
    assert "malicious-activity" in ind["indicator_types"]
    assert "pattern" in ind
    assert "valid_from" in ind


def test_breach_becomes_indicator():
    """breach события также должны давать Indicator."""
    bundle = events_to_stix_bundle([BREACH_EVENT], "Test Corp")
    indicator_objs = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert len(indicator_objs) >= 1


def test_port_scan_becomes_observed_data():
    """port_scan должен давать observed-data с network-traffic объектом."""
    bundle = events_to_stix_bundle([PORT_SCAN_EVENT], "Test Corp")
    obs_objs = [o for o in bundle["objects"] if o["type"] == "observed-data"]
    assert len(obs_objs) >= 1
    obs = obs_objs[0]
    assert obs["spec_version"] == "2.1"
    assert obs["id"].startswith("observed-data--")
    assert "objects" in obs
    # Проверяем наличие network-traffic в obs.objects
    has_net_traffic = any(
        v.get("type") == "network-traffic"
        for v in obs["objects"].values()
    )
    assert has_net_traffic


def test_nuclei_finding_becomes_vulnerability():
    """nuclei_finding должен порождать Vulnerability объект."""
    bundle = events_to_stix_bundle([NUCLEI_EVENT], "Test Corp")
    vuln_objs = [o for o in bundle["objects"] if o["type"] == "vulnerability"]
    assert len(vuln_objs) >= 1
    vuln = vuln_objs[0]
    assert vuln["spec_version"] == "2.1"
    assert vuln["id"].startswith("vulnerability--")
    # CVE должен быть в имени или external_references
    assert "CVE-2021-44228" in vuln["name"] or any(
        "CVE-2021-44228" in str(ref) for ref in vuln.get("external_references", [])
    )


def test_nuclei_without_cve_uses_template_id():
    """nuclei_finding без CVE использует template_id в описании."""
    bundle = events_to_stix_bundle([NUCLEI_NO_CVE_EVENT], "Test Corp")
    vuln_objs = [o for o in bundle["objects"] if o["type"] == "vulnerability"]
    assert len(vuln_objs) >= 1
    vuln = vuln_objs[0]
    # template_id должен фигурировать в name или external_references
    assert "exposed-panel" in vuln["name"] or any(
        "exposed-panel" in str(ref) for ref in vuln.get("external_references", [])
    )


def test_dark_web_mention_becomes_threat_actor():
    """dark_web_mention должен давать threat-actor объект."""
    bundle = events_to_stix_bundle([DARK_WEB_EVENT], "Test Corp")
    ta_objs = [o for o in bundle["objects"] if o["type"] == "threat-actor"]
    assert len(ta_objs) >= 1
    ta = ta_objs[0]
    assert ta["spec_version"] == "2.1"
    assert ta["id"].startswith("threat-actor--")
    # Группа из payload должна быть в name
    assert "LockBit" in ta["name"]


def test_ransomware_mention_becomes_threat_actor():
    """ransomware_mention также должен давать threat-actor."""
    bundle = events_to_stix_bundle([RANSOMWARE_EVENT], "Test Corp")
    ta_objs = [o for o in bundle["objects"] if o["type"] == "threat-actor"]
    assert len(ta_objs) >= 1


def test_critical_high_events_get_indicator():
    """События с severity critical/high должны всегда иметь Indicator."""
    for event in [STEALER_EVENT, NUCLEI_EVENT, DARK_WEB_EVENT, RANSOMWARE_EVENT]:
        bundle = events_to_stix_bundle([event], "Test Corp")
        indicator_objs = [o for o in bundle["objects"] if o["type"] == "indicator"]
        assert len(indicator_objs) >= 1, f"No indicator for event_type={event['event_type']}"


def test_low_severity_generic_no_indicator():
    """Событие с низкой severity без критичного типа не должно добавлять indicator."""
    bundle = events_to_stix_bundle([GENERIC_LOW_EVENT], "Test Corp")
    indicator_objs = [o for o in bundle["objects"] if o["type"] == "indicator"]
    # low severity generic event — только observed-data, без indicator
    assert len(indicator_objs) == 0


def test_all_stix_objects_have_required_fields():
    """Все STIX объекты должны иметь обязательные поля: type, spec_version, id, created, modified."""
    events = [STEALER_EVENT, PORT_SCAN_EVENT, NUCLEI_EVENT, DARK_WEB_EVENT, BREACH_EVENT]
    bundle = events_to_stix_bundle(events, "Test Corp")
    for obj in bundle["objects"]:
        assert "type" in obj, f"Missing 'type' in {obj}"
        assert "spec_version" in obj, f"Missing 'spec_version' in {obj}"
        assert "id" in obj, f"Missing 'id' in {obj}"
        assert "created" in obj, f"Missing 'created' in {obj}"
        assert "modified" in obj, f"Missing 'modified' in {obj}"
        # id должен быть в формате type--uuid
        assert obj["id"].startswith(obj["type"] + "--"), (
            f"Bad id format: {obj['id']} for type {obj['type']}"
        )


def test_bundle_with_multiple_events():
    """Bundle из нескольких разных событий содержит > 2 STIX объектов."""
    events = [STEALER_EVENT, PORT_SCAN_EVENT, BREACH_EVENT]
    bundle = events_to_stix_bundle(events, "Test Corp")
    assert len(bundle["objects"]) >= 4  # identity + минимум 3 события


def test_bundle_objects_minimum_with_single_event():
    """Bundle из одного события содержит не менее 2 объектов (identity + событие)."""
    bundle = events_to_stix_bundle([STEALER_EVENT], "Test Corp")
    assert len(bundle["objects"]) >= 2


# ---------------------------------------------------------------------------
# Юнит-тесты: отдельные функции конвертации
# ---------------------------------------------------------------------------


def test_event_to_indicator_fields():
    """event_to_indicator возвращает объект со всеми обязательными полями."""
    ind = event_to_indicator(STEALER_EVENT)
    assert ind["type"] == "indicator"
    assert ind["spec_version"] == "2.1"
    assert ind["id"].startswith("indicator--")
    assert "pattern" in ind
    assert "valid_from" in ind
    assert "indicator_types" in ind


def test_event_to_observed_data_fields():
    """event_to_observed_data возвращает объект с обязательными полями."""
    obs = event_to_observed_data(PORT_SCAN_EVENT)
    assert obs["type"] == "observed-data"
    assert obs["spec_version"] == "2.1"
    assert obs["id"].startswith("observed-data--")
    assert obs["number_observed"] == 1
    assert "first_observed" in obs
    assert "last_observed" in obs


def test_event_to_vulnerability_with_cve():
    """event_to_vulnerability с CVE возвращает корректный Vulnerability объект."""
    vuln = event_to_vulnerability(NUCLEI_EVENT)
    assert vuln is not None
    assert vuln["type"] == "vulnerability"
    assert "CVE-2021-44228" in vuln["name"]


def test_event_to_vulnerability_returns_none_for_non_nuclei():
    """event_to_vulnerability должен вернуть None для не-nuclei событий."""
    result = event_to_vulnerability(STEALER_EVENT)
    assert result is None


# ---------------------------------------------------------------------------
# Фикстуры для HTTP-тестов (суперюзер с организацией)
# ---------------------------------------------------------------------------

TEST_PASSWORD = "testpassword"


@pytest_asyncio.fixture
async def superuser_with_org(db_session: AsyncSession, superuser: User) -> User:
    """Суперюзер с привязанной организацией (нужен для STIX export endpoint)."""
    uid = uuid.uuid4().hex[:8]
    org = Organization(
        name=f"STIX Test Org {uid}",
        slug=f"stix-test-org-{uid}",
        plan=OrgPlan.enterprise.value,
    )
    db_session.add(org)
    await db_session.flush()
    superuser.organization_id = org.id
    await db_session.commit()
    await db_session.refresh(superuser)
    return superuser


@pytest_asyncio.fixture
async def stix_token(client: AsyncClient, superuser_with_org: User) -> str:
    """JWT токен суперюзера с организацией."""
    resp = await client.post(
        "/api/v1/auth/token",
        data={"username": superuser_with_org.email, "password": TEST_PASSWORD},
    )
    assert resp.status_code == 200
    return resp.json()["access_token"]


# ---------------------------------------------------------------------------
# Интеграционные тесты: HTTP эндпоинты
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_export_endpoint_requires_auth(client):
    """GET /api/v1/export/stix без токена должен вернуть 403."""
    resp = await client.get("/api/v1/export/stix")
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_export_endpoint_returns_json(client, stix_token):
    """GET /api/v1/export/stix с токеном → 200 + валидный JSON."""
    resp = await client.get(
        "/api/v1/export/stix",
        headers={"Authorization": f"Bearer {stix_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["type"] == "bundle"
    assert data["spec_version"] == "2.1"
    assert isinstance(data["objects"], list)


@pytest.mark.asyncio
async def test_export_endpoint_content_type(client, stix_token):
    """Content-Type ответа должен быть application/json."""
    resp = await client.get(
        "/api/v1/export/stix",
        headers={"Authorization": f"Bearer {stix_token}"},
    )
    assert resp.status_code == 200
    assert "application/json" in resp.headers.get("content-type", "")


@pytest.mark.asyncio
async def test_export_download_endpoint_returns_attachment(client, stix_token):
    """GET /api/v1/export/stix/bundle.json → Content-Disposition: attachment."""
    resp = await client.get(
        "/api/v1/export/stix/bundle.json",
        headers={"Authorization": f"Bearer {stix_token}"},
    )
    assert resp.status_code == 200
    cd = resp.headers.get("content-disposition", "")
    assert "attachment" in cd
    assert "stix_bundle_" in cd


@pytest.mark.asyncio
async def test_export_download_requires_auth(client):
    """GET /api/v1/export/stix/bundle.json без токена → 403."""
    resp = await client.get("/api/v1/export/stix/bundle.json")
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_export_endpoint_with_days_param(client, stix_token):
    """GET /api/v1/export/stix?days=7 должен работать корректно."""
    resp = await client.get(
        "/api/v1/export/stix?days=7",
        headers={"Authorization": f"Bearer {stix_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["type"] == "bundle"


@pytest.mark.asyncio
async def test_export_endpoint_with_invalid_days(client, superuser_token):
    """GET /api/v1/export/stix?days=0 должен вернуть 422 (валидация)."""
    resp = await client.get(
        "/api/v1/export/stix?days=0",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 422
