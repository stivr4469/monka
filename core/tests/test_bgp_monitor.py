"""
Тесты BGP/ASN Monitor — workers/tasks/bgp_monitor.py + POST /api/v1/scan/bgp.

Покрытие:
  - Unit: get_ip_info, load_baseline / save_baseline, check_bgp
  - Integration: endpoint 202/422/401/503
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from httpx import AsyncClient

# Добавляем workers/ в sys.path для импорта tasks.*
_workers_path = str(Path(__file__).parents[2] / "workers")
if _workers_path not in sys.path:
    sys.path.insert(0, _workers_path)

# ─── Пути для мокинга ─────────────────────────────────────────────────────────

_WORKER_MODULE = "tasks.bgp_monitor"
_ENDPOINT_CHECK_BGP = "app.api.v1.endpoints.bgp_scan.check_bgp"
_ENDPOINT_AVAILABLE = "app.api.v1.endpoints.bgp_scan._BGP_AVAILABLE"

BGP_SCAN_URL = "/api/v1/scan/bgp"


# ─── Вспомогательные данные ───────────────────────────────────────────────────

_CLOUDFLARE_INFO = {
    "asn": 13335,
    "as_name": "CLOUDFLARENET",
    "prefix": "1.1.1.0/24",
    "country": "US",
}

_GOOGLE_INFO = {
    "asn": 15169,
    "as_name": "GOOGLE",
    "prefix": "8.8.8.0/24",
    "country": "US",
}

# Пример ответа BGPView API для IP 1.1.1.1
_BGPVIEW_RESPONSE = {
    "status": "ok",
    "data": {
        "ip": "1.1.1.1",
        "prefixes": [
            {
                "prefix": "1.1.1.0/24",
                "country_code": "US",
                "asn": {
                    "asn": 13335,
                    "name": "CLOUDFLARENET",
                    "description": "CLOUDFLARENET",
                    "country_code": "US",
                },
            }
        ],
    },
}


def _auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ─── Unit: get_ip_info ────────────────────────────────────────────────────────

class TestGetIpInfo:
    """Тесты парсинга ответа BGPView API."""

    def test_get_ip_info_parses_response(self):
        """Мокируем httpx.get, проверяем корректный парсинг полей ASN."""
        from tasks.bgp_monitor import get_ip_info

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _BGPVIEW_RESPONSE

        with patch("httpx.get", return_value=mock_resp):
            result = get_ip_info("1.1.1.1")

        assert result is not None
        assert result["asn"] == 13335
        assert result["as_name"] == "CLOUDFLARENET"
        assert result["prefix"] == "1.1.1.0/24"
        assert result["country"] == "US"

    def test_get_ip_info_non_200_returns_none(self):
        """HTTP ошибка (не 200) → None."""
        from tasks.bgp_monitor import get_ip_info

        mock_resp = MagicMock()
        mock_resp.status_code = 404

        with patch("httpx.get", return_value=mock_resp):
            result = get_ip_info("1.2.3.4")

        assert result is None

    def test_get_ip_info_empty_prefixes_returns_none(self):
        """Ответ без prefixes → None."""
        from tasks.bgp_monitor import get_ip_info

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"status": "ok", "data": {"ip": "1.2.3.4", "prefixes": []}}

        with patch("httpx.get", return_value=mock_resp):
            result = get_ip_info("1.2.3.4")

        assert result is None

    def test_get_ip_info_network_error_returns_none(self):
        """Сетевая ошибка → None (не бросает исключение)."""
        from tasks.bgp_monitor import get_ip_info
        import httpx

        with patch("httpx.get", side_effect=httpx.RequestError("connection error")):
            result = get_ip_info("1.2.3.4")

        assert result is None


# ─── Unit: resolve_ips ────────────────────────────────────────────────────────

class TestResolveIps:
    """Тесты DNS-резолвера."""

    def test_private_ip_filtered(self):
        """Приватные IP (192.168.x.x) должны быть отфильтрованы."""
        from tasks.bgp_monitor import resolve_ips

        # Мокируем getaddrinfo, возвращающий приватный IP
        with patch("socket.getaddrinfo", return_value=[
            (None, None, None, None, ("192.168.1.1", 0)),
            (None, None, None, None, ("10.0.0.1", 0)),
        ]):
            result = resolve_ips("private.example.com")

        assert result == []

    def test_public_ip_returned(self):
        """Публичные IP проходят фильтр."""
        from tasks.bgp_monitor import resolve_ips

        with patch("socket.getaddrinfo", return_value=[
            (None, None, None, None, ("1.1.1.1", 0)),
        ]):
            result = resolve_ips("cloudflare.com")

        assert "1.1.1.1" in result

    def test_dns_error_returns_empty(self):
        """Ошибка DNS → пустой список (не исключение)."""
        import socket
        from tasks.bgp_monitor import resolve_ips

        with patch("socket.getaddrinfo", side_effect=socket.gaierror("NXDOMAIN")):
            result = resolve_ips("nonexistent-xyz-domain.com")

        assert result == []


# ─── Unit: load_baseline / save_baseline ─────────────────────────────────────

class TestBaselineIO:
    """Тесты сохранения и загрузки baseline."""

    def test_save_then_load_roundtrip(self, tmp_path, monkeypatch):
        """save_baseline → load_baseline возвращает те же данные."""
        import tasks.bgp_monitor as bgp_mod
        monkeypatch.setattr(bgp_mod, "_BASELINE_DIR", tmp_path)

        from tasks.bgp_monitor import load_baseline, save_baseline

        data = {"1.1.1.1": _CLOUDFLARE_INFO}
        save_baseline("example.com", data)
        loaded = load_baseline("example.com")

        assert loaded is not None
        assert loaded["1.1.1.1"]["asn"] == 13335

    def test_load_nonexistent_returns_none(self, tmp_path, monkeypatch):
        """Загрузка несуществующего baseline → None."""
        import tasks.bgp_monitor as bgp_mod
        monkeypatch.setattr(bgp_mod, "_BASELINE_DIR", tmp_path)

        from tasks.bgp_monitor import load_baseline

        result = load_baseline("no-such-domain-xyz.com")
        assert result is None


# ─── Unit: check_bgp — основная логика ───────────────────────────────────────

class TestCheckBgp:
    """Тесты основной логики check_bgp."""

    def test_no_baseline_returns_zero_changes(self, tmp_path, monkeypatch):
        """Первый запуск: baseline отсутствует → создаётся, изменений нет."""
        import tasks.bgp_monitor as bgp_mod
        monkeypatch.setattr(bgp_mod, "_BASELINE_DIR", tmp_path)

        from tasks.bgp_monitor import check_bgp

        with patch(f"{_WORKER_MODULE}.resolve_ips", return_value=["1.1.1.1"]), \
             patch(f"{_WORKER_MODULE}.get_ip_info", return_value=_CLOUDFLARE_INFO), \
             patch(f"{_WORKER_MODULE}.bulk_ingest") as mock_ingest:
            result = check_bgp("example.com", "http://localhost:8000", "secret")

        assert result["changes"] == 0
        assert result["checked"] >= 1
        mock_ingest.assert_not_called()

        # Проверяем что baseline был создан
        from tasks.bgp_monitor import load_baseline
        baseline = load_baseline("example.com")
        assert baseline is not None
        assert "1.1.1.1" in baseline

    def test_asn_change_generates_high_event(self, tmp_path, monkeypatch):
        """Смена ASN → событие severity=high."""
        import tasks.bgp_monitor as bgp_mod
        monkeypatch.setattr(bgp_mod, "_BASELINE_DIR", tmp_path)

        old_info = {"asn": 13335, "as_name": "CLOUDFLARENET", "prefix": "1.1.1.0/24", "country": "US"}
        new_info = {"asn": 15169, "as_name": "GOOGLE", "prefix": "8.8.8.0/24", "country": "US"}

        from tasks.bgp_monitor import save_baseline, check_bgp
        save_baseline("example.com", {"1.2.3.4": old_info})

        sent_events = []

        def capture_ingest(events, *args, **kwargs):
            sent_events.extend(events)
            return {"sent": len(events), "errors": 0}

        with patch(f"{_WORKER_MODULE}.resolve_ips", return_value=["1.2.3.4"]), \
             patch(f"{_WORKER_MODULE}.get_ip_info", return_value=new_info), \
             patch(f"{_WORKER_MODULE}.bulk_ingest", side_effect=capture_ingest):
            result = check_bgp("example.com", "http://localhost:8000", "secret")

        assert result["changes"] >= 1
        high_events = [e for e in sent_events if e["severity"] == "high"]
        assert len(high_events) >= 1

        asn_event = high_events[0]
        assert asn_event["payload"]["change"] == "asn"
        assert asn_event["payload"]["old_asn"] == 13335
        assert asn_event["payload"]["new_asn"] == 15169
        assert asn_event["payload"]["as_name"] == "GOOGLE"

    def test_prefix_change_generates_medium_event(self, tmp_path, monkeypatch):
        """Смена prefix при том же ASN → событие severity=medium."""
        import tasks.bgp_monitor as bgp_mod
        monkeypatch.setattr(bgp_mod, "_BASELINE_DIR", tmp_path)

        old_info = {"asn": 13335, "as_name": "CLOUDFLARENET", "prefix": "1.1.1.0/24", "country": "US"}
        new_info = {"asn": 13335, "as_name": "CLOUDFLARENET", "prefix": "1.1.2.0/24", "country": "US"}

        from tasks.bgp_monitor import save_baseline, check_bgp
        save_baseline("example.com", {"1.2.3.4": old_info})

        sent_events = []

        def capture_ingest(events, *args, **kwargs):
            sent_events.extend(events)
            return {"sent": len(events), "errors": 0}

        with patch(f"{_WORKER_MODULE}.resolve_ips", return_value=["1.2.3.4"]), \
             patch(f"{_WORKER_MODULE}.get_ip_info", return_value=new_info), \
             patch(f"{_WORKER_MODULE}.bulk_ingest", side_effect=capture_ingest):
            result = check_bgp("example.com", "http://localhost:8000", "secret")

        assert result["changes"] >= 1
        medium_events = [e for e in sent_events if e["severity"] == "medium"]
        assert len(medium_events) >= 1

        prefix_event = medium_events[0]
        assert prefix_event["payload"]["change"] == "ip_prefix"
        assert prefix_event["payload"]["old_prefix"] == "1.1.1.0/24"
        assert prefix_event["payload"]["new_prefix"] == "1.1.2.0/24"

    def test_no_change_generates_no_events(self, tmp_path, monkeypatch):
        """Данные не изменились → bulk_ingest не вызывается."""
        import tasks.bgp_monitor as bgp_mod
        monkeypatch.setattr(bgp_mod, "_BASELINE_DIR", tmp_path)

        from tasks.bgp_monitor import save_baseline, check_bgp
        save_baseline("example.com", {"1.2.3.4": _CLOUDFLARE_INFO})

        with patch(f"{_WORKER_MODULE}.resolve_ips", return_value=["1.2.3.4"]), \
             patch(f"{_WORKER_MODULE}.get_ip_info", return_value=_CLOUDFLARE_INFO.copy()), \
             patch(f"{_WORKER_MODULE}.bulk_ingest") as mock_ingest:
            result = check_bgp("example.com", "http://localhost:8000", "secret")

        assert result["changes"] == 0
        mock_ingest.assert_not_called()

    def test_new_ip_generates_low_event(self, tmp_path, monkeypatch):
        """Новый IP (не было в baseline) → событие severity=low."""
        import tasks.bgp_monitor as bgp_mod
        monkeypatch.setattr(bgp_mod, "_BASELINE_DIR", tmp_path)

        from tasks.bgp_monitor import save_baseline, check_bgp
        # Baseline с одним IP
        save_baseline("example.com", {"1.2.3.4": _CLOUDFLARE_INFO})

        sent_events = []

        def capture_ingest(events, *args, **kwargs):
            sent_events.extend(events)
            return {"sent": len(events), "errors": 0}

        # Теперь DNS вернул другой (новый) IP
        with patch(f"{_WORKER_MODULE}.resolve_ips", return_value=["9.9.9.9"]), \
             patch(f"{_WORKER_MODULE}.get_ip_info", return_value=_GOOGLE_INFO), \
             patch(f"{_WORKER_MODULE}.bulk_ingest", side_effect=capture_ingest):
            result = check_bgp("example.com", "http://localhost:8000", "secret")

        assert result["changes"] >= 1
        low_events = [e for e in sent_events if e["severity"] == "low"]
        assert len(low_events) >= 1
        assert low_events[0]["payload"]["change"] == "new_ip"
        assert low_events[0]["payload"]["ip"] == "9.9.9.9"

    def test_no_ips_returns_error(self, tmp_path, monkeypatch):
        """DNS не вернул IP → checked=0, error в результате."""
        import tasks.bgp_monitor as bgp_mod
        monkeypatch.setattr(bgp_mod, "_BASELINE_DIR", tmp_path)

        from tasks.bgp_monitor import check_bgp

        with patch(f"{_WORKER_MODULE}.resolve_ips", return_value=[]), \
             patch(f"{_WORKER_MODULE}.bulk_ingest") as mock_ingest:
            result = check_bgp("unreachable.com", "http://localhost:8000", "secret")

        assert result["checked"] == 0
        assert "error" in result
        mock_ingest.assert_not_called()

    def test_private_ip_not_in_baseline(self, tmp_path, monkeypatch):
        """Приватные IP фильтруются на этапе resolve_ips — не попадают в baseline."""
        import tasks.bgp_monitor as bgp_mod
        monkeypatch.setattr(bgp_mod, "_BASELINE_DIR", tmp_path)

        import socket
        from tasks.bgp_monitor import check_bgp, load_baseline

        # resolve_ips с реальным фильтром вернёт [] для приватных IP
        with patch("socket.getaddrinfo", return_value=[
            (None, None, None, None, ("192.168.1.1", 0)),
        ]), patch(f"{_WORKER_MODULE}.bulk_ingest") as mock_ingest:
            result = check_bgp("private.example.com", "http://localhost:8000", "secret")

        assert result["checked"] == 0
        assert "error" in result
        mock_ingest.assert_not_called()


# ─── Integration: POST /api/v1/scan/bgp ──────────────────────────────────────

@pytest.mark.asyncio
async def test_bgp_scan_endpoint_returns_202(
    client: AsyncClient,
    superuser_token: str,
) -> None:
    """POST с валидным доменом → 202 Accepted с полями status и domain."""
    with patch(_ENDPOINT_CHECK_BGP, return_value={"checked": 1, "changes": 0, "sent": 0}):
        resp = await client.post(
            BGP_SCAN_URL,
            json={"domain": "example.com"},
            headers=_auth_headers(superuser_token),
        )

    assert resp.status_code == 202
    data = resp.json()
    assert data["status"] == "accepted"
    assert data["domain"] == "example.com"


@pytest.mark.asyncio
async def test_bgp_scan_normalizes_domain(
    client: AsyncClient,
    superuser_token: str,
) -> None:
    """Домен в верхнем регистре нормализуется в нижний."""
    with patch(_ENDPOINT_CHECK_BGP, return_value={"checked": 1, "changes": 0, "sent": 0}):
        resp = await client.post(
            BGP_SCAN_URL,
            json={"domain": "EXAMPLE.COM"},
            headers=_auth_headers(superuser_token),
        )

    assert resp.status_code == 202
    assert resp.json()["domain"] == "example.com"


@pytest.mark.asyncio
async def test_bgp_scan_invalid_domain_empty(
    client: AsyncClient,
    superuser_token: str,
) -> None:
    """Пустой домен → 422."""
    resp = await client.post(
        BGP_SCAN_URL,
        json={"domain": ""},
        headers=_auth_headers(superuser_token),
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_bgp_scan_invalid_domain_with_path(
    client: AsyncClient,
    superuser_token: str,
) -> None:
    """Домен с path injection → 422."""
    resp = await client.post(
        BGP_SCAN_URL,
        json={"domain": "evil.com/../../etc"},
        headers=_auth_headers(superuser_token),
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_bgp_scan_requires_auth(client: AsyncClient) -> None:
    """Запрос без токена → 401."""
    resp = await client.post(
        BGP_SCAN_URL,
        json={"domain": "example.com"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_bgp_scan_worker_unavailable(
    client: AsyncClient,
    superuser_token: str,
) -> None:
    """Воркер недоступен (ImportError) → 503."""
    with patch(_ENDPOINT_AVAILABLE, False):
        resp = await client.post(
            BGP_SCAN_URL,
            json={"domain": "example.com"},
            headers=_auth_headers(superuser_token),
        )
    assert resp.status_code == 503


@pytest.mark.asyncio
async def test_bgp_scan_rate_limit_not_blocking_first_request(
    client: AsyncClient,
    superuser_token: str,
) -> None:
    """Первый запрос не блокируется rate limiter'ом."""
    with patch(_ENDPOINT_CHECK_BGP, return_value={"checked": 1, "changes": 0, "sent": 0}):
        resp = await client.post(
            BGP_SCAN_URL,
            json={"domain": "ratelimit-test.com"},
            headers=_auth_headers(superuser_token),
        )
    assert resp.status_code == 202
