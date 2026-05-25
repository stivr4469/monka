"""
Тесты Censys Enrichment (Phase 13.B).

Все тесты мокируются — реальные API credentials не нужны.
"""
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from httpx import AsyncClient

# Добавляем workers/ в sys.path для прямого импорта tasks.*
_workers_path = str(Path(__file__).parents[2] / "workers")
if _workers_path not in sys.path:
    sys.path.insert(0, _workers_path)


# ─── Импорт модуля воркера ────────────────────────────────────────────────────

from tasks.censys_enricher import (
    enrich_domain_with_censys,
    get_censys_host,
    search_censys_hosts,
)

CENSYS_SCAN_URL = "/api/v1/scan/censys"

_MOCK_SEARCH_RESPONSE = {
    "result": {
        "hits": [
            {
                "ip": "1.2.3.4",
                "services": [
                    {"port": 443, "transport_protocol": "TCP", "service_name": "HTTPS"},
                    {"port": 80, "transport_protocol": "TCP", "service_name": "HTTP"},
                ],
                "location": {"country": "US", "city": "San Francisco"},
                "autonomous_system": {"asn": 13335, "name": "CLOUDFLARENET"},
            }
        ]
    }
}

_MOCK_HOST_RESPONSE = {
    "result": {
        "ip": "1.2.3.4",
        "services": [
            {"port": 443, "transport_protocol": "TCP", "service_name": "HTTPS"},
            {"port": 22, "transport_protocol": "TCP", "service_name": "SSH"},
        ],
        "location": {"country": "US", "city": "San Francisco"},
        "autonomous_system": {"asn": 13335, "name": "CLOUDFLARENET"},
    }
}


def _auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ─── Тесты воркера (unit) ──────────────────────────────────────────────────────

class TestSearchCensysHosts:
    def test_search_returns_empty_without_credentials(self):
        """Без env vars возвращает пустой список без обращения к API."""
        # Убеждаемся что переменных нет
        env_without_creds = {k: v for k, v in os.environ.items()
                             if k not in ("CENSYS_API_ID", "CENSYS_API_SECRET")}
        with patch.dict(os.environ, env_without_creds, clear=True):
            result = search_censys_hosts("parsed.names: example.com")
        assert result == []

    def test_search_calls_correct_endpoint(self):
        """Мокируем httpx.get, проверяем что URL содержит censys.io."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _MOCK_SEARCH_RESPONSE

        with patch.dict(os.environ, {"CENSYS_API_ID": "test-id", "CENSYS_API_SECRET": "test-secret"}):
            with patch("httpx.get", return_value=mock_resp) as mock_get:
                result = search_censys_hosts("parsed.names: example.com")
                assert mock_get.called
                call_url = mock_get.call_args[0][0]
                assert "censys.io" in call_url

    def test_search_returns_hits_from_response(self):
        """Парсит список hits из ответа API."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _MOCK_SEARCH_RESPONSE

        with patch.dict(os.environ, {"CENSYS_API_ID": "test-id", "CENSYS_API_SECRET": "test-secret"}):
            with patch("httpx.get", return_value=mock_resp):
                result = search_censys_hosts("parsed.names: example.com")

        assert len(result) == 1
        assert result[0]["ip"] == "1.2.3.4"

    def test_search_returns_empty_on_401(self):
        """При 401 — пустой список без исключения."""
        mock_resp = MagicMock()
        mock_resp.status_code = 401

        with patch.dict(os.environ, {"CENSYS_API_ID": "bad-id", "CENSYS_API_SECRET": "bad-secret"}):
            with patch("httpx.get", return_value=mock_resp):
                result = search_censys_hosts("parsed.names: example.com")

        assert result == []

    def test_search_returns_empty_on_network_error(self):
        """При сетевой ошибке — пустой список без исключения."""
        import httpx as _httpx

        with patch.dict(os.environ, {"CENSYS_API_ID": "test-id", "CENSYS_API_SECRET": "test-secret"}):
            with patch("httpx.get", side_effect=_httpx.TimeoutException("timeout")):
                result = search_censys_hosts("parsed.names: example.com")

        assert result == []


class TestGetCensysHost:
    def test_host_data_parsed_correctly(self):
        """Парсит данные хоста из ответа API."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _MOCK_HOST_RESPONSE

        with patch.dict(os.environ, {"CENSYS_API_ID": "test-id", "CENSYS_API_SECRET": "test-secret"}):
            with patch("httpx.get", return_value=mock_resp):
                result = get_censys_host("1.2.3.4")

        assert result is not None
        assert result["ip"] == "1.2.3.4"
        assert len(result["services"]) == 2
        assert result["location"]["country"] == "US"
        assert result["autonomous_system"]["asn"] == 13335

    def test_host_returns_none_on_404(self):
        """При 404 возвращает None без исключения."""
        mock_resp = MagicMock()
        mock_resp.status_code = 404

        with patch.dict(os.environ, {"CENSYS_API_ID": "test-id", "CENSYS_API_SECRET": "test-secret"}):
            with patch("httpx.get", return_value=mock_resp):
                result = get_censys_host("1.2.3.4")

        assert result is None

    def test_host_returns_none_without_credentials(self):
        """Без credentials возвращает None."""
        env_without_creds = {k: v for k, v in os.environ.items()
                             if k not in ("CENSYS_API_ID", "CENSYS_API_SECRET")}
        with patch.dict(os.environ, env_without_creds, clear=True):
            result = get_censys_host("1.2.3.4")

        assert result is None


class TestPortSeverity:
    def test_high_risk_port_generates_event(self):
        """Порт 22 → severity=high в сгенерированных событиях."""
        host_data_with_ssh = {
            "ip": "1.2.3.4",
            "services": [
                {"port": 22, "transport_protocol": "TCP", "service_name": "SSH"},
            ],
            "location": {"country": "US", "city": "NYC"},
            "autonomous_system": {"asn": 1234, "name": "TESTNET"},
        }

        mock_search_resp = MagicMock()
        mock_search_resp.status_code = 200
        mock_search_resp.json.return_value = {
            "result": {"hits": [{"ip": "1.2.3.4", **host_data_with_ssh}]}
        }

        mock_host_resp = MagicMock()
        mock_host_resp.status_code = 200
        mock_host_resp.json.return_value = {"result": host_data_with_ssh}

        captured_events: list = []

        def fake_bulk_ingest(events, *args, **kwargs):
            captured_events.extend(events)
            return {"sent": len(events), "errors": 0}

        with patch.dict(os.environ, {"CENSYS_API_ID": "test-id", "CENSYS_API_SECRET": "test-secret"}):
            with patch("httpx.get") as mock_get:
                mock_get.return_value = mock_host_resp
                with patch("tasks.censys_enricher.bulk_ingest", side_effect=fake_bulk_ingest):
                    with patch("tasks.censys_enricher._resolve_to_ips", return_value=["1.2.3.4"]):
                        with patch("tasks.censys_enricher.search_censys_hosts", return_value=[]):
                            enrich_domain_with_censys(
                                "example.com",
                                "http://localhost:8000",
                                "test-secret",
                            )

        port_scan_events = [e for e in captured_events if e["event_type"] == "port_scan"]
        assert len(port_scan_events) > 0
        ssh_event = next(e for e in port_scan_events if e["payload"]["port"] == 22)
        assert ssh_event["severity"] == "high"

    def test_critical_port_generates_event(self):
        """Порт 6379 (Redis) → severity=critical."""
        host_data_with_redis = {
            "ip": "5.6.7.8",
            "services": [
                {"port": 6379, "transport_protocol": "TCP", "service_name": "REDIS"},
            ],
            "location": {"country": "DE", "city": "Frankfurt"},
            "autonomous_system": {"asn": 2222, "name": "HETZNER"},
        }

        mock_host_resp = MagicMock()
        mock_host_resp.status_code = 200
        mock_host_resp.json.return_value = {"result": host_data_with_redis}

        captured_events: list = []

        def fake_bulk_ingest(events, *args, **kwargs):
            captured_events.extend(events)
            return {"sent": len(events), "errors": 0}

        with patch.dict(os.environ, {"CENSYS_API_ID": "test-id", "CENSYS_API_SECRET": "test-secret"}):
            with patch("httpx.get", return_value=mock_host_resp):
                with patch("tasks.censys_enricher.bulk_ingest", side_effect=fake_bulk_ingest):
                    with patch("tasks.censys_enricher._resolve_to_ips", return_value=["5.6.7.8"]):
                        with patch("tasks.censys_enricher.search_censys_hosts", return_value=[]):
                            enrich_domain_with_censys(
                                "redis-target.com",
                                "http://localhost:8000",
                                "test-secret",
                            )

        port_scan_events = [e for e in captured_events if e["event_type"] == "port_scan"]
        assert len(port_scan_events) > 0
        redis_event = next(e for e in port_scan_events if e["payload"]["port"] == 6379)
        assert redis_event["severity"] == "critical"

    def test_other_ports_generate_info_severity(self):
        """Порт 443 (HTTPS) → severity=info."""
        host_data = {
            "ip": "9.10.11.12",
            "services": [
                {"port": 443, "transport_protocol": "TCP", "service_name": "HTTPS"},
            ],
            "location": {},
            "autonomous_system": {},
        }

        mock_host_resp = MagicMock()
        mock_host_resp.status_code = 200
        mock_host_resp.json.return_value = {"result": host_data}

        captured_events: list = []

        def fake_bulk_ingest(events, *args, **kwargs):
            captured_events.extend(events)
            return {"sent": len(events), "errors": 0}

        with patch.dict(os.environ, {"CENSYS_API_ID": "test-id", "CENSYS_API_SECRET": "test-secret"}):
            with patch("httpx.get", return_value=mock_host_resp):
                with patch("tasks.censys_enricher.bulk_ingest", side_effect=fake_bulk_ingest):
                    with patch("tasks.censys_enricher._resolve_to_ips", return_value=["9.10.11.12"]):
                        with patch("tasks.censys_enricher.search_censys_hosts", return_value=[]):
                            enrich_domain_with_censys(
                                "safe.example.com",
                                "http://localhost:8000",
                                "test-secret",
                            )

        port_scan_events = [e for e in captured_events if e["event_type"] == "port_scan"]
        assert len(port_scan_events) > 0
        https_event = next(e for e in port_scan_events if e["payload"]["port"] == 443)
        assert https_event["severity"] == "info"


class TestEnrichDomainWithCensys:
    def test_enrich_domain_no_credentials_returns_zero(self):
        """Без API keys → checked=0, skipped=True."""
        env_without_creds = {k: v for k, v in os.environ.items()
                             if k not in ("CENSYS_API_ID", "CENSYS_API_SECRET")}
        with patch.dict(os.environ, env_without_creds, clear=True):
            result = enrich_domain_with_censys(
                "example.com",
                "http://localhost:8000",
                "test-secret",
            )

        assert result["checked"] == 0
        assert result["skipped"] is True
        assert result["reason"] == "no_credentials"

    def test_enrich_domain_no_ips_returns_zero(self):
        """Если DNS не резолвится и поиск пустой → checked=0."""
        with patch.dict(os.environ, {"CENSYS_API_ID": "test-id", "CENSYS_API_SECRET": "test-secret"}):
            with patch("tasks.censys_enricher._resolve_to_ips", return_value=[]):
                with patch("tasks.censys_enricher.search_censys_hosts", return_value=[]):
                    result = enrich_domain_with_censys(
                        "nonexistent-domain-xyz.example",
                        "http://localhost:8000",
                        "test-secret",
                    )

        assert result["checked"] == 0
        assert result["skipped"] is False
        assert result["reason"] == "no_ips"

    def test_enrich_domain_sends_events_for_found_ips(self):
        """При найденных IP отправляет события в bulk_ingest."""
        mock_host_resp = MagicMock()
        mock_host_resp.status_code = 200
        mock_host_resp.json.return_value = {
            "result": {
                "ip": "1.2.3.4",
                "services": [
                    {"port": 80, "transport_protocol": "TCP", "service_name": "HTTP"},
                ],
                "location": {"country": "US", "city": "NYC"},
                "autonomous_system": {"asn": 1111, "name": "TESTNET"},
            }
        }

        ingest_called = []

        def fake_bulk_ingest(events, *args, **kwargs):
            ingest_called.append(len(events))
            return {"sent": len(events), "errors": 0}

        with patch.dict(os.environ, {"CENSYS_API_ID": "test-id", "CENSYS_API_SECRET": "test-secret"}):
            with patch("httpx.get", return_value=mock_host_resp):
                with patch("tasks.censys_enricher.bulk_ingest", side_effect=fake_bulk_ingest):
                    with patch("tasks.censys_enricher._resolve_to_ips", return_value=["1.2.3.4"]):
                        with patch("tasks.censys_enricher.search_censys_hosts", return_value=[]):
                            result = enrich_domain_with_censys(
                                "example.com",
                                "http://localhost:8000",
                                "test-secret",
                            )

        assert result["checked"] == 1
        assert len(ingest_called) > 0  # bulk_ingest был вызван


# ─── Тесты API эндпоинта ──────────────────────────────────────────────────────

_WORKER_PATH = "app.api.v1.endpoints.censys_scan.enrich_domain_with_censys"
_CREDS_PATCH = {
    "CENSYS_API_ID": "test-id",
    "CENSYS_API_SECRET": "test-secret",
}


@pytest.mark.asyncio
async def test_censys_scan_endpoint_returns_202(
    client: AsyncClient,
    superuser_token: str,
) -> None:
    """POST с валидным доменом и credentials → 202 Accepted."""
    with patch.dict(os.environ, _CREDS_PATCH):
        with patch(_WORKER_PATH) as mock_worker:
            mock_worker.return_value = {"checked": 1, "sent": 2, "skipped": False}
            resp = await client.post(
                CENSYS_SCAN_URL,
                json={"domain": "example.com"},
                headers=_auth_headers(superuser_token),
            )

    assert resp.status_code == 202
    data = resp.json()
    assert data["status"] == "accepted"
    assert data["domain"] == "example.com"


@pytest.mark.asyncio
async def test_censys_scan_endpoint_503_without_creds(
    client: AsyncClient,
    superuser_token: str,
) -> None:
    """Без CENSYS_API_ID/SECRET → 503 Service Unavailable."""
    env_without_creds = {k: v for k, v in os.environ.items()
                         if k not in ("CENSYS_API_ID", "CENSYS_API_SECRET")}
    with patch.dict(os.environ, env_without_creds, clear=True):
        resp = await client.post(
            CENSYS_SCAN_URL,
            json={"domain": "example.com"},
            headers=_auth_headers(superuser_token),
        )

    assert resp.status_code == 503


@pytest.mark.asyncio
async def test_censys_scan_endpoint_requires_auth(
    client: AsyncClient,
) -> None:
    """Запрос без токена → 401."""
    resp = await client.post(
        CENSYS_SCAN_URL,
        json={"domain": "example.com"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_censys_scan_endpoint_invalid_domain(
    client: AsyncClient,
    superuser_token: str,
) -> None:
    """Пустой домен → 422 (ошибка валидации)."""
    with patch.dict(os.environ, _CREDS_PATCH):
        resp = await client.post(
            CENSYS_SCAN_URL,
            json={"domain": ""},
            headers=_auth_headers(superuser_token),
        )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_censys_scan_response_has_detail(
    client: AsyncClient,
    superuser_token: str,
) -> None:
    """202 ответ содержит поле detail с описанием."""
    with patch.dict(os.environ, _CREDS_PATCH):
        with patch(_WORKER_PATH) as mock_worker:
            mock_worker.return_value = {"checked": 0, "sent": 0, "skipped": False}
            resp = await client.post(
                CENSYS_SCAN_URL,
                json={"domain": "scan-target.com"},
                headers=_auth_headers(superuser_token),
            )

    assert resp.status_code == 202
    data = resp.json()
    assert "detail" in data
    assert len(data["detail"]) > 0
