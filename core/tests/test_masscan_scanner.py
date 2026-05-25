"""
Тесты masscan-сканера (Phase 13.A).

Покрывает:
  - resolve_ips: успешный резолвинг, фильтрация приватных IP, пустой результат
  - run_masscan: парсинг JSON, graceful fallback при отсутствии masscan, timeout
  - fingerprint_with_nmap: парсинг XML, graceful fallback при отсутствии nmap
  - severity logic: критические / высокие / средние порты
  - scan_domain: полный пайплайн с моками, отсутствие IP
  - API endpoint: 202 accepted, 403 non-enterprise, 422 невалидный домен, 401 без токена
"""
import subprocess
import uuid
from unittest.mock import MagicMock, patch

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.organization import Organization, OrgPlan
from app.models.user import User

# Путь к воркеру (через workers/ в sys.path — добавляется conftest)
_MASSCAN_MODULE = "tasks.masscan_scanner"
# Путь для patch в контексте эндпоинта
_SCAN_DOMAIN_PATH = "app.api.v1.endpoints.masscan_scan.scan_domain"

MASSCAN_URL = "/api/v1/scan/masscan"


# ─── Вспомогательные функции ──────────────────────────────────────────────────

def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ─── Фикстуры организаций ────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def org_enterprise(db_session: AsyncSession, superuser: User) -> Organization:
    """Организация на плане enterprise."""
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


@pytest_asyncio.fixture
async def org_starter(db_session: AsyncSession, superuser: User) -> Organization:
    """Организация на плане starter."""
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


# ═══════════════════════════════════════════════════════════════════════════════
# 1. resolve_ips
# ═══════════════════════════════════════════════════════════════════════════════

def test_resolve_ips_returns_public_ips():
    """resolve_ips возвращает публичные IP при успешном резолвинге."""
    # Имитируем getaddrinfo с публичным IP
    mock_info = [(None, None, None, None, ("93.184.216.34", 0))]
    with patch("socket.getaddrinfo", return_value=mock_info):
        from tasks.masscan_scanner import resolve_ips
        result = resolve_ips("example.com")
    assert result == ["93.184.216.34"]


def test_resolve_ips_filters_private_10x():
    """resolve_ips отфильтровывает 10.x.x.x (RFC 1918)."""
    mock_info = [
        (None, None, None, None, ("10.0.0.1", 0)),
        (None, None, None, None, ("93.184.216.34", 0)),
    ]
    with patch("socket.getaddrinfo", return_value=mock_info):
        from tasks.masscan_scanner import resolve_ips
        result = resolve_ips("example.com")
    assert "10.0.0.1" not in result
    assert "93.184.216.34" in result


def test_resolve_ips_filters_loopback():
    """resolve_ips отфильтровывает 127.x.x.x (loopback)."""
    mock_info = [(None, None, None, None, ("127.0.0.1", 0))]
    with patch("socket.getaddrinfo", return_value=mock_info):
        from tasks.masscan_scanner import resolve_ips
        result = resolve_ips("localhost")
    assert result == []


def test_resolve_ips_dns_error_returns_empty():
    """resolve_ips возвращает [] при ошибке DNS (gaierror)."""
    import socket
    with patch("socket.getaddrinfo", side_effect=socket.gaierror("NXDOMAIN")):
        from tasks.masscan_scanner import resolve_ips
        result = resolve_ips("nonexistent.invalid")
    assert result == []


def test_resolve_ips_deduplicates():
    """resolve_ips дедублицирует одинаковые IP из нескольких записей."""
    mock_info = [
        (None, None, None, None, ("1.2.3.4", 0)),
        (None, None, None, None, ("1.2.3.4", 0)),  # дубликат
    ]
    with patch("socket.getaddrinfo", return_value=mock_info):
        from tasks.masscan_scanner import resolve_ips
        result = resolve_ips("example.com")
    assert result == ["1.2.3.4"]


# ═══════════════════════════════════════════════════════════════════════════════
# 2. run_masscan
# ═══════════════════════════════════════════════════════════════════════════════

def test_run_masscan_parses_json_output():
    """run_masscan корректно парсит JSON-вывод masscan с открытым портом."""
    masscan_output = (
        '{ "ip": "1.2.3.4", "ports": [{"port": 80, "proto": "tcp", "status": "open"}] }'
    )
    mock_proc = MagicMock()
    mock_proc.stdout = masscan_output
    mock_proc.returncode = 0

    with patch("subprocess.run", return_value=mock_proc):
        from tasks.masscan_scanner import run_masscan
        result = run_masscan(["1.2.3.4"])

    assert len(result) == 1
    assert result[0] == {"ip": "1.2.3.4", "port": 80, "proto": "tcp"}


def test_run_masscan_not_found_returns_empty():
    """run_masscan возвращает [] если masscan не установлен (FileNotFoundError)."""
    with patch("subprocess.run", side_effect=FileNotFoundError()):
        from tasks.masscan_scanner import run_masscan
        result = run_masscan(["1.2.3.4"])
    assert result == []


def test_run_masscan_timeout_returns_empty():
    """run_masscan возвращает [] при таймауте."""
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="masscan", timeout=120)):
        from tasks.masscan_scanner import run_masscan
        result = run_masscan(["1.2.3.4"])
    assert result == []


def test_run_masscan_empty_targets_returns_empty():
    """run_masscan возвращает [] если список targets пустой."""
    from tasks.masscan_scanner import run_masscan
    result = run_masscan([])
    assert result == []


def test_run_masscan_skips_closed_ports():
    """run_masscan не включает порты со status != open."""
    masscan_output = (
        '{ "ip": "1.2.3.4", "ports": ['
        '{"port": 80, "proto": "tcp", "status": "open"},'
        '{"port": 443, "proto": "tcp", "status": "closed"}'
        '] }'
    )
    mock_proc = MagicMock()
    mock_proc.stdout = masscan_output
    mock_proc.returncode = 0

    with patch("subprocess.run", return_value=mock_proc):
        from tasks.masscan_scanner import run_masscan
        result = run_masscan(["1.2.3.4"])

    assert len(result) == 1
    assert result[0]["port"] == 80


# ═══════════════════════════════════════════════════════════════════════════════
# 3. fingerprint_with_nmap
# ═══════════════════════════════════════════════════════════════════════════════

# Минимальный XML-ответ nmap с открытым портом 80 и сервисом nginx
_NMAP_XML_NGINX = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.24.0" extrainfo="Ubuntu"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

_NMAP_XML_EMPTY = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports/>
  </host>
</nmaprun>"""


def test_fingerprint_with_nmap_parses_xml():
    """fingerprint_with_nmap корректно парсит XML с информацией о сервисе."""
    mock_proc = MagicMock()
    mock_proc.stdout = _NMAP_XML_NGINX
    mock_proc.returncode = 0

    with patch("subprocess.run", return_value=mock_proc):
        from tasks.masscan_scanner import fingerprint_with_nmap
        result = fingerprint_with_nmap("1.2.3.4", 80)

    assert result["service"] == "http"
    assert result["product"] == "nginx"
    assert "1.24.0" in result["version"]


def test_fingerprint_with_nmap_not_found_returns_empty():
    """fingerprint_with_nmap возвращает {} если nmap не установлен."""
    with patch("subprocess.run", side_effect=FileNotFoundError()):
        from tasks.masscan_scanner import fingerprint_with_nmap
        result = fingerprint_with_nmap("1.2.3.4", 80)
    assert result == {}


def test_fingerprint_with_nmap_timeout_returns_empty():
    """fingerprint_with_nmap возвращает {} при таймауте nmap."""
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="nmap", timeout=30)):
        from tasks.masscan_scanner import fingerprint_with_nmap
        result = fingerprint_with_nmap("1.2.3.4", 80)
    assert result == {}


def test_fingerprint_with_nmap_empty_xml_returns_empty():
    """fingerprint_with_nmap возвращает {} если в XML нет открытых портов."""
    mock_proc = MagicMock()
    mock_proc.stdout = _NMAP_XML_EMPTY
    mock_proc.returncode = 0

    with patch("subprocess.run", return_value=mock_proc):
        from tasks.masscan_scanner import fingerprint_with_nmap
        result = fingerprint_with_nmap("1.2.3.4", 80)
    assert result == {}


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Severity logic
# ═══════════════════════════════════════════════════════════════════════════════

def test_severity_ssh_is_high():
    """Порт 22 (SSH) → severity=high."""
    from tasks.masscan_scanner import _get_severity
    assert _get_severity(22) == "high"


def test_severity_rdp_is_high():
    """Порт 3389 (RDP) → severity=high."""
    from tasks.masscan_scanner import _get_severity
    assert _get_severity(3389) == "high"


def test_severity_mysql_is_critical():
    """Порт 3306 (MySQL) → severity=critical."""
    from tasks.masscan_scanner import _get_severity
    assert _get_severity(3306) == "critical"


def test_severity_redis_is_critical():
    """Порт 6379 (Redis) → severity=critical."""
    from tasks.masscan_scanner import _get_severity
    assert _get_severity(6379) == "critical"


def test_severity_http_is_medium():
    """Порт 80 (HTTP) → severity=medium (не в списке → fallback)."""
    from tasks.masscan_scanner import _get_severity
    assert _get_severity(80) == "medium"


def test_severity_unknown_port_is_medium():
    """Неизвестный порт → severity=medium."""
    from tasks.masscan_scanner import _get_severity
    assert _get_severity(12345) == "medium"


# ═══════════════════════════════════════════════════════════════════════════════
# 5. scan_domain
# ═══════════════════════════════════════════════════════════════════════════════

def test_scan_domain_no_ips_returns_error():
    """scan_domain возвращает error=no_ips если resolve_ips вернул []."""
    with patch(f"{_MASSCAN_MODULE}.resolve_ips", return_value=[]):
        from tasks.masscan_scanner import scan_domain
        result = scan_domain("noresolve.invalid", "http://localhost:8000", "secret")
    assert result["error"] == "no_ips"
    assert result["sent"] == 0


def test_scan_domain_full_pipeline_sends_events():
    """scan_domain формирует и отправляет события при наличии открытых портов."""
    mock_ips = ["1.2.3.4"]
    mock_ports = [{"ip": "1.2.3.4", "port": 22, "proto": "tcp"}]
    mock_fingerprint = {"service": "ssh", "version": "OpenSSH 8.4", "product": "OpenSSH"}
    mock_bulk = {"sent": 1, "errors": 0}

    with (
        patch(f"{_MASSCAN_MODULE}.resolve_ips", return_value=mock_ips),
        patch(f"{_MASSCAN_MODULE}.run_masscan", return_value=mock_ports),
        patch(f"{_MASSCAN_MODULE}.fingerprint_with_nmap", return_value=mock_fingerprint),
        patch(f"{_MASSCAN_MODULE}.bulk_ingest", return_value=mock_bulk) as mock_ingest,
    ):
        from tasks.masscan_scanner import scan_domain
        result = scan_domain("example.com", "http://localhost:8000", "secret")

    assert result["ips_scanned"] == 1
    assert result["ports_found"] == 1
    assert result["sent"] == 1

    # Проверяем структуру отправленного события
    call_args = mock_ingest.call_args
    events = call_args[0][0]
    assert len(events) == 1
    event = events[0]
    assert event["event_type"] == "exposed_service"
    assert event["severity"] == "high"          # порт 22 → high
    assert event["source_name"] == "masscan"
    assert event["payload"]["ip"] == "1.2.3.4"
    assert event["payload"]["port"] == 22
    assert event["payload"]["scanner"] == "masscan+nmap"


def test_scan_domain_no_open_ports_sends_nothing():
    """scan_domain не вызывает bulk_ingest если masscan не нашёл открытых портов."""
    with (
        patch(f"{_MASSCAN_MODULE}.resolve_ips", return_value=["1.2.3.4"]),
        patch(f"{_MASSCAN_MODULE}.run_masscan", return_value=[]),
        patch(f"{_MASSCAN_MODULE}.bulk_ingest") as mock_ingest,
    ):
        from tasks.masscan_scanner import scan_domain
        result = scan_domain("example.com", "http://localhost:8000", "secret")

    assert result["ports_found"] == 0
    assert result["sent"] == 0
    mock_ingest.assert_not_called()


# ═══════════════════════════════════════════════════════════════════════════════
# 6. API эндпоинт
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_masscan_endpoint_202_enterprise(
    client: AsyncClient,
    superuser_token: str,
    org_enterprise: Organization,
) -> None:
    """POST /scan/masscan с Enterprise-планом возвращает 202 accepted."""
    with patch(_SCAN_DOMAIN_PATH, return_value={"ips_scanned": 1, "ports_found": 0, "sent": 0}):
        resp = await client.post(
            MASSCAN_URL,
            json={"domain": "example.com"},
            headers=_auth(superuser_token),
        )
    assert resp.status_code == 202
    data = resp.json()
    assert data["status"] == "accepted"
    assert data["domain"] == "example.com"


@pytest.mark.asyncio
async def test_masscan_endpoint_403_starter_plan(
    client: AsyncClient,
    superuser_token: str,
    org_starter: Organization,
) -> None:
    """POST /scan/masscan со Starter-планом возвращает 403."""
    resp = await client.post(
        MASSCAN_URL,
        json={"domain": "example.com"},
        headers=_auth(superuser_token),
    )
    assert resp.status_code == 403
    assert "Enterprise" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_masscan_endpoint_403_no_org(
    client: AsyncClient,
    superuser_token: str,
) -> None:
    """POST /scan/masscan без организации возвращает 403."""
    resp = await client.post(
        MASSCAN_URL,
        json={"domain": "example.com"},
        headers=_auth(superuser_token),
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_masscan_endpoint_422_invalid_domain(
    client: AsyncClient,
    superuser_token: str,
    org_enterprise: Organization,
) -> None:
    """POST /scan/masscan с невалидным доменом возвращает 422."""
    resp = await client.post(
        MASSCAN_URL,
        json={"domain": "not a domain!!!"},
        headers=_auth(superuser_token),
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_masscan_endpoint_401_no_token(client: AsyncClient) -> None:
    """POST /scan/masscan без токена возвращает 401."""
    resp = await client.post(
        MASSCAN_URL,
        json={"domain": "example.com"},
    )
    assert resp.status_code == 401
