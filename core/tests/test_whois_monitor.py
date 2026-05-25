"""
Тесты WHOIS/Registrant Monitor — workers/tasks/whois_monitor.py + POST /api/v1/scan/whois.

Покрытие:
  - Unit: fetch_whois_rdap, load_baseline, save_baseline, _build_events
  - Integration: endpoint 202/422/401/503
"""
import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from httpx import AsyncClient

# ─── Пути для мокинга ─────────────────────────────────────────────────────────

_WORKER_MODULE = "tasks.whois_monitor"
_ENDPOINT_CHECK_WHOIS = "app.api.v1.endpoints.whois_scan.check_whois"
_ENDPOINT_AVAILABLE = "app.api.v1.endpoints.whois_scan._WHOIS_AVAILABLE"

WHOIS_SCAN_URL = "/api/v1/scan/whois"


# ─── Вспомогательные данные ───────────────────────────────────────────────────

_SAMPLE_RDAP_RESPONSE = {
    "objectClassName": "domain",
    "ldhName": "example.com",
    "entities": [
        {
            "roles": ["registrant"],
            "vcardArray": [
                "vcard",
                [
                    ["version", {}, "text", "4.0"],
                    ["fn", {}, "text", "Example Registrant Inc."],
                    ["org", {}, "text", "Example Registrant Inc."],
                ],
            ],
        }
    ],
    "nameservers": [
        {"ldhName": "ns1.example.com"},
        {"ldhName": "ns2.example.com"},
    ],
    "events": [
        {"eventAction": "registration", "eventDate": "2010-01-01T00:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2099-12-31T00:00:00Z"},
    ],
}

_SAMPLE_NORMALIZED = {
    "registrant": "Example Registrant Inc.",
    "nameservers": ["ns1.example.com", "ns2.example.com"],
    "expiry_date": "2099-12-31T00:00:00Z",
}


def _auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ─── Unit: fetch_whois_rdap ───────────────────────────────────────────────────

class TestFetchWhoisRdap:
    """Тесты RDAP-клиента."""

    def test_successful_fetch_returns_normalized_dict(self):
        """Успешный RDAP ответ → нормализованный dict с тремя ключами."""
        import sys
        sys.path.insert(0, str(Path(__file__).parents[2] / "workers"))
        from tasks.whois_monitor import fetch_whois_rdap

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = _SAMPLE_RDAP_RESPONSE

        with patch("httpx.Client") as mock_client_cls:
            mock_ctx = MagicMock()
            mock_ctx.__enter__ = MagicMock(return_value=mock_ctx)
            mock_ctx.__exit__ = MagicMock(return_value=False)
            mock_ctx.get.return_value = mock_response
            mock_client_cls.return_value = mock_ctx

            result = fetch_whois_rdap("example.com")

        assert result is not None
        assert "registrant" in result
        assert "nameservers" in result
        assert "expiry_date" in result
        assert result["registrant"] == "Example Registrant Inc."
        assert "ns1.example.com" in result["nameservers"]

    def test_404_returns_none(self):
        """RDAP 404 (домен не найден) → None."""
        import sys
        sys.path.insert(0, str(Path(__file__).parents[2] / "workers"))
        from tasks.whois_monitor import fetch_whois_rdap

        mock_response = MagicMock()
        mock_response.status_code = 404

        with patch("httpx.Client") as mock_client_cls:
            mock_ctx = MagicMock()
            mock_ctx.__enter__ = MagicMock(return_value=mock_ctx)
            mock_ctx.__exit__ = MagicMock(return_value=False)
            mock_ctx.get.return_value = mock_response
            mock_client_cls.return_value = mock_ctx

            result = fetch_whois_rdap("nonexistent-xyz.com")

        assert result is None

    def test_timeout_returns_none(self):
        """Таймаут RDAP → None (не бросает исключение)."""
        import sys
        sys.path.insert(0, str(Path(__file__).parents[2] / "workers"))
        import httpx
        from tasks.whois_monitor import fetch_whois_rdap

        with patch("httpx.Client") as mock_client_cls:
            mock_ctx = MagicMock()
            mock_ctx.__enter__ = MagicMock(return_value=mock_ctx)
            mock_ctx.__exit__ = MagicMock(return_value=False)
            mock_ctx.get.side_effect = httpx.TimeoutException("timeout")
            mock_client_cls.return_value = mock_ctx

            result = fetch_whois_rdap("slow-domain.com")

        assert result is None


# ─── Unit: load_baseline / save_baseline ─────────────────────────────────────

class TestBaselineIO:
    """Тесты чтения и записи baseline-файлов."""

    def test_save_then_load_roundtrip(self):
        """save_baseline → load_baseline возвращает те же данные."""
        import sys
        sys.path.insert(0, str(Path(__file__).parents[2] / "workers"))
        from tasks.whois_monitor import load_baseline, save_baseline

        domain = "roundtrip-test.com"
        baseline_path = Path(f"/tmp/whois_baseline_roundtrip_test_com.json")
        # Очищаем перед тестом
        baseline_path.unlink(missing_ok=True)

        save_baseline(domain, _SAMPLE_NORMALIZED)
        loaded = load_baseline(domain)

        assert loaded is not None
        assert loaded["registrant"] == _SAMPLE_NORMALIZED["registrant"]
        assert loaded["nameservers"] == _SAMPLE_NORMALIZED["nameservers"]
        assert loaded["expiry_date"] == _SAMPLE_NORMALIZED["expiry_date"]

        # Очищаем после теста
        baseline_path.unlink(missing_ok=True)

    def test_load_nonexistent_returns_none(self):
        """load_baseline для несуществующего файла → None."""
        import sys
        sys.path.insert(0, str(Path(__file__).parents[2] / "workers"))
        from tasks.whois_monitor import load_baseline

        # Гарантируем что файл не существует
        Path("/tmp/whois_baseline_no_such_domain_xyz.json").unlink(missing_ok=True)

        result = load_baseline("no-such-domain.xyz")
        assert result is None

    def test_save_adds_metadata(self):
        """save_baseline добавляет метаданные _saved_at и _domain."""
        import sys
        sys.path.insert(0, str(Path(__file__).parents[2] / "workers"))
        from tasks.whois_monitor import save_baseline, _safe_domain_name

        domain = "meta-test.com"
        path = Path(f"/tmp/whois_baseline_{_safe_domain_name(domain)}.json")
        path.unlink(missing_ok=True)

        save_baseline(domain, _SAMPLE_NORMALIZED)

        raw = json.loads(path.read_text())
        assert "_saved_at" in raw
        assert raw["_domain"] == domain

        path.unlink(missing_ok=True)


# ─── Unit: check_whois (первый запуск vs. изменения) ─────────────────────────

class TestCheckWhois:
    """Тесты основной логики check_whois."""

    def _cleanup(self, domain: str):
        from tasks.whois_monitor import _safe_domain_name
        Path(f"/tmp/whois_baseline_{_safe_domain_name(domain)}.json").unlink(missing_ok=True)

    def test_first_run_saves_baseline_no_events(self):
        """Первый запуск: baseline отсутствует → сохраняется, изменений нет."""
        import sys
        sys.path.insert(0, str(Path(__file__).parents[2] / "workers"))
        from tasks.whois_monitor import check_whois

        domain = "first-run-test.example.com"
        self._cleanup(domain)

        with patch("tasks.whois_monitor.fetch_whois_rdap", return_value=dict(_SAMPLE_NORMALIZED)):
            with patch("tasks.whois_monitor.bulk_ingest") as mock_ingest:
                result = check_whois(domain, "http://localhost:8000", "secret")

        assert result["checked"] is True
        assert result["changes"] == 0
        assert result["sent"] == 0
        mock_ingest.assert_not_called()  # событий нет — bulk_ingest не вызывается

        self._cleanup(domain)

    def test_registrant_change_generates_high_event(self):
        """Смена registrant → событие severity=high."""
        import sys
        sys.path.insert(0, str(Path(__file__).parents[2] / "workers"))
        from tasks.whois_monitor import check_whois, save_baseline

        domain = "registrant-change.example.com"
        self._cleanup(domain)

        # Сохраняем старый baseline
        old_data = {**_SAMPLE_NORMALIZED, "registrant": "Old Owner LLC"}
        save_baseline(domain, old_data)

        # Новые данные с другим registrant
        new_data = {**_SAMPLE_NORMALIZED, "registrant": "New Owner Corp"}

        captured_events: list = []

        def mock_ingest(events, core_api_url, internal_secret, **kwargs):
            captured_events.extend(events)
            return {"sent": len(events), "errors": 0}

        with patch("tasks.whois_monitor.fetch_whois_rdap", return_value=new_data):
            with patch("tasks.whois_monitor.bulk_ingest", side_effect=mock_ingest):
                result = check_whois(domain, "http://localhost:8000", "secret")

        assert result["changes"] >= 1
        event_types = [e["payload"]["change"] for e in captured_events]
        assert "registrant_changed" in event_types

        registrant_event = next(e for e in captured_events if e["payload"]["change"] == "registrant_changed")
        assert registrant_event["severity"] == "high"
        assert registrant_event["payload"]["old_registrant"] == "Old Owner LLC"
        assert registrant_event["payload"]["new_registrant"] == "New Owner Corp"

        self._cleanup(domain)

    def test_nameserver_change_generates_high_event(self):
        """Смена nameservers → событие severity=high."""
        import sys
        sys.path.insert(0, str(Path(__file__).parents[2] / "workers"))
        from tasks.whois_monitor import check_whois, save_baseline

        domain = "ns-change.example.com"
        self._cleanup(domain)

        old_data = {**_SAMPLE_NORMALIZED, "nameservers": ["ns1.old.com", "ns2.old.com"]}
        save_baseline(domain, old_data)

        new_data = {**_SAMPLE_NORMALIZED, "nameservers": ["ns1.new-suspicious.ru", "ns2.new-suspicious.ru"]}

        captured_events: list = []

        def mock_ingest(events, core_api_url, internal_secret, **kwargs):
            captured_events.extend(events)
            return {"sent": len(events), "errors": 0}

        with patch("tasks.whois_monitor.fetch_whois_rdap", return_value=new_data):
            with patch("tasks.whois_monitor.bulk_ingest", side_effect=mock_ingest):
                result = check_whois(domain, "http://localhost:8000", "secret")

        assert result["changes"] >= 1
        ns_event = next(
            (e for e in captured_events if e["payload"]["change"] == "nameservers_changed"),
            None,
        )
        assert ns_event is not None
        assert ns_event["severity"] == "high"
        assert "ns1.old.com" in ns_event["payload"]["old_nameservers"]

        self._cleanup(domain)

    def test_expiry_critical_generates_critical_event(self):
        """Истечение < 30 дней → событие severity=critical."""
        import sys
        sys.path.insert(0, str(Path(__file__).parents[2] / "workers"))
        from datetime import datetime, timedelta, timezone
        from tasks.whois_monitor import check_whois, save_baseline

        domain = "expiry-critical.example.com"
        self._cleanup(domain)

        # Baseline с нормальным сроком (не провоцирует изменение expiry event в baseline сравнении)
        save_baseline(domain, _SAMPLE_NORMALIZED)

        # Истекает через 5 дней
        expiry_soon = (datetime.now(timezone.utc) + timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        current_data = {**_SAMPLE_NORMALIZED, "expiry_date": expiry_soon}

        captured_events: list = []

        def mock_ingest(events, core_api_url, internal_secret, **kwargs):
            captured_events.extend(events)
            return {"sent": len(events), "errors": 0}

        with patch("tasks.whois_monitor.fetch_whois_rdap", return_value=current_data):
            with patch("tasks.whois_monitor.bulk_ingest", side_effect=mock_ingest):
                result = check_whois(domain, "http://localhost:8000", "secret")

        expiry_events = [e for e in captured_events if "expiring" in e["payload"]["change"]]
        assert any(e["severity"] == "critical" for e in expiry_events), \
            f"Ожидалось critical событие, получено: {expiry_events}"

        self._cleanup(domain)

    def test_expiry_medium_generates_medium_event(self):
        """Истечение < 90 дней но >= 30 → событие severity=medium."""
        import sys
        sys.path.insert(0, str(Path(__file__).parents[2] / "workers"))
        from datetime import datetime, timedelta, timezone
        from tasks.whois_monitor import check_whois, save_baseline

        domain = "expiry-medium.example.com"
        self._cleanup(domain)

        save_baseline(domain, _SAMPLE_NORMALIZED)

        # Истекает через 60 дней — попадает в зону medium (30-90)
        expiry_medium = (datetime.now(timezone.utc) + timedelta(days=60)).strftime("%Y-%m-%dT%H:%M:%SZ")
        current_data = {**_SAMPLE_NORMALIZED, "expiry_date": expiry_medium}

        captured_events: list = []

        def mock_ingest(events, core_api_url, internal_secret, **kwargs):
            captured_events.extend(events)
            return {"sent": len(events), "errors": 0}

        with patch("tasks.whois_monitor.fetch_whois_rdap", return_value=current_data):
            with patch("tasks.whois_monitor.bulk_ingest", side_effect=mock_ingest):
                result = check_whois(domain, "http://localhost:8000", "secret")

        expiry_events = [e for e in captured_events if "expiring" in e["payload"]["change"]]
        assert any(e["severity"] == "medium" for e in expiry_events), \
            f"Ожидалось medium событие, получено: {expiry_events}"

        self._cleanup(domain)

    def test_rdap_unavailable_returns_error(self):
        """RDAP недоступен → checked=False, нет событий."""
        import sys
        sys.path.insert(0, str(Path(__file__).parents[2] / "workers"))
        from tasks.whois_monitor import check_whois

        with patch("tasks.whois_monitor.fetch_whois_rdap", return_value=None):
            with patch("tasks.whois_monitor.bulk_ingest") as mock_ingest:
                result = check_whois("unreachable.com", "http://localhost:8000", "secret")

        assert result["checked"] is False
        assert "error" in result
        mock_ingest.assert_not_called()

    def test_no_changes_no_events_sent(self):
        """Данные не изменились → bulk_ingest не вызывается."""
        import sys
        sys.path.insert(0, str(Path(__file__).parents[2] / "workers"))
        from tasks.whois_monitor import check_whois, save_baseline

        domain = "no-changes.example.com"
        self._cleanup(domain)

        save_baseline(domain, _SAMPLE_NORMALIZED)

        with patch("tasks.whois_monitor.fetch_whois_rdap", return_value=dict(_SAMPLE_NORMALIZED)):
            with patch("tasks.whois_monitor.bulk_ingest") as mock_ingest:
                result = check_whois(domain, "http://localhost:8000", "secret")

        assert result["changes"] == 0
        mock_ingest.assert_not_called()

        self._cleanup(domain)


# ─── Integration: POST /api/v1/scan/whois ────────────────────────────────────

@pytest.mark.asyncio
async def test_whois_scan_accepted(
    client: AsyncClient,
    superuser_token: str,
) -> None:
    """POST с валидным доменом → 202 Accepted с полями status и domain."""
    with patch(_ENDPOINT_CHECK_WHOIS, return_value={"checked": True, "changes": 0, "sent": 0}):
        resp = await client.post(
            WHOIS_SCAN_URL,
            json={"domain": "example.com"},
            headers=_auth_headers(superuser_token),
        )

    assert resp.status_code == 202
    data = resp.json()
    assert data["status"] == "accepted"
    assert data["domain"] == "example.com"


@pytest.mark.asyncio
async def test_whois_scan_normalizes_domain(
    client: AsyncClient,
    superuser_token: str,
) -> None:
    """Домен с заглавными буквами нормализуется в нижний регистр."""
    with patch(_ENDPOINT_CHECK_WHOIS, return_value={"checked": True, "changes": 0, "sent": 0}):
        resp = await client.post(
            WHOIS_SCAN_URL,
            json={"domain": "EXAMPLE.COM"},
            headers=_auth_headers(superuser_token),
        )

    assert resp.status_code == 202
    assert resp.json()["domain"] == "example.com"


@pytest.mark.asyncio
async def test_whois_scan_invalid_domain_empty(
    client: AsyncClient,
    superuser_token: str,
) -> None:
    """Пустой домен → 422 (ошибка валидации)."""
    resp = await client.post(
        WHOIS_SCAN_URL,
        json={"domain": ""},
        headers=_auth_headers(superuser_token),
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_whois_scan_invalid_domain_with_path(
    client: AsyncClient,
    superuser_token: str,
) -> None:
    """Домен со слешами (path injection) → 422."""
    resp = await client.post(
        WHOIS_SCAN_URL,
        json={"domain": "evil.com/../../etc"},
        headers=_auth_headers(superuser_token),
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_whois_scan_invalid_domain_with_scheme(
    client: AsyncClient,
    superuser_token: str,
) -> None:
    """Домен со схемой https:// → 422."""
    resp = await client.post(
        WHOIS_SCAN_URL,
        json={"domain": "https://example.com"},
        headers=_auth_headers(superuser_token),
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_whois_scan_requires_auth(client: AsyncClient) -> None:
    """Запрос без токена → 401."""
    resp = await client.post(
        WHOIS_SCAN_URL,
        json={"domain": "example.com"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_whois_scan_worker_unavailable(
    client: AsyncClient,
    superuser_token: str,
) -> None:
    """Воркер недоступен (ImportError) → 503."""
    with patch(_ENDPOINT_AVAILABLE, False):
        resp = await client.post(
            WHOIS_SCAN_URL,
            json={"domain": "example.com"},
            headers=_auth_headers(superuser_token),
        )
    assert resp.status_code == 503


@pytest.mark.asyncio
async def test_whois_scan_rate_limit_not_blocking_first_request(
    client: AsyncClient,
    superuser_token: str,
) -> None:
    """Первый запрос не блокируется rate limiter'ом."""
    with patch(_ENDPOINT_CHECK_WHOIS, return_value={"checked": True, "changes": 0, "sent": 0}):
        resp = await client.post(
            WHOIS_SCAN_URL,
            json={"domain": "ratelimit-test.com"},
            headers=_auth_headers(superuser_token),
        )
    assert resp.status_code == 202
