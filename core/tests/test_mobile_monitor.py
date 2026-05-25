"""
Тесты Mobile App Monitoring — Phase 12.D.

Покрытие:
  - search_app_store: network error → []; успешный парсинг полей
  - is_suspicious_app: разный developer → True; совпадающий → False
  - monitor_mobile_apps: suspicious app → событие; дедупликация
  - API: 202 accepted; 401 без токена

sys.path для workers добавляется в conftest.py
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest
import pytest_asyncio

from tasks.mobile_monitor import (
    _get_seen_cache_path,
    _load_seen_ids,
    _save_seen_ids,
    is_suspicious_app,
    monitor_mobile_apps,
    search_app_store,
    search_google_play,
)


# ──────────────────────────────────────────────
# Вспомогательные фабрики mock-ответов
# ──────────────────────────────────────────────

def _make_response(status_code: int, json_body=None) -> MagicMock:
    """Создаёт mock httpx-ответа."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_body or {}
    resp.raise_for_status = MagicMock()
    if status_code >= 400:
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "error", request=MagicMock(), response=MagicMock()
        )
    return resp


def _ingest_ok() -> MagicMock:
    return _make_response(202, {"status": "accepted"})


def _itunes_response(results: list[dict]) -> dict:
    """Формирует структуру ответа iTunes Search API."""
    return {"results": results}


# ──────────────────────────────────────────────
# Тесты search_app_store
# ──────────────────────────────────────────────

class TestSearchAppStore:
    """Тесты функции поиска в App Store."""

    def test_app_store_returns_empty_on_error(self):
        """При network error → пустой список, без исключения."""
        with patch("httpx.get", side_effect=Exception("connection refused")):
            result = search_app_store("MyApp")
        assert result == []

    def test_app_store_returns_empty_on_timeout(self):
        """При таймауте → пустой список."""
        with patch("httpx.get", side_effect=httpx.TimeoutException("timeout")):
            result = search_app_store("MyApp")
        assert result == []

    def test_app_store_returns_empty_on_http_error(self):
        """При HTTP 4xx/5xx → пустой список."""
        resp = _make_response(503)
        with patch("httpx.get", return_value=resp):
            result = search_app_store("MyApp")
        assert result == []

    def test_app_store_parses_results(self):
        """Успешный ответ iTunes API → корректный маппинг полей."""
        mock_response = {
            "results": [
                {
                    "trackId": 123456,
                    "trackName": "MyApp - Official",
                    "artistName": "MyCompany Inc.",
                    "bundleId": "com.mycompany.myapp",
                    "trackViewUrl": "https://apps.apple.com/app/id123456",
                    "averageUserRating": 4.5,
                    "userRatingCount": 1000,
                }
            ]
        }
        with patch("httpx.get") as mock_get:
            mock_get.return_value.status_code = 200
            mock_get.return_value.json.return_value = mock_response
            mock_get.return_value.raise_for_status = lambda: None
            result = search_app_store("MyApp")

        assert len(result) == 1
        assert result[0]["name"] == "MyApp - Official"
        assert result[0]["platform"] == "app_store"
        assert result[0]["app_id"] == "123456"
        assert result[0]["developer"] == "MyCompany Inc."
        assert result[0]["bundle_id"] == "com.mycompany.myapp"
        assert result[0]["url"] == "https://apps.apple.com/app/id123456"
        assert result[0]["rating"] == 4.5
        assert result[0]["reviews"] == 1000

    def test_app_store_empty_results(self):
        """Пустой results → пустой список."""
        resp_data = {"results": []}
        with patch("httpx.get") as mock_get:
            mock_get.return_value.status_code = 200
            mock_get.return_value.json.return_value = resp_data
            mock_get.return_value.raise_for_status = lambda: None
            result = search_app_store("UnknownApp")
        assert result == []

    def test_app_store_multiple_results(self):
        """Несколько результатов → все корректно маппируются."""
        mock_response = {
            "results": [
                {
                    "trackId": 111,
                    "trackName": "FakeApp 1",
                    "artistName": "Scammer Inc",
                    "bundleId": "com.scammer.fakeapp1",
                    "trackViewUrl": "https://apps.apple.com/app/id111",
                    "averageUserRating": 1.5,
                    "userRatingCount": 50,
                },
                {
                    "trackId": 222,
                    "trackName": "MyApp Official",
                    "artistName": "MyCompany Inc.",
                    "bundleId": "com.mycompany.official",
                    "trackViewUrl": "https://apps.apple.com/app/id222",
                    "averageUserRating": 4.8,
                    "userRatingCount": 5000,
                },
            ]
        }
        with patch("httpx.get") as mock_get:
            mock_get.return_value.status_code = 200
            mock_get.return_value.json.return_value = mock_response
            mock_get.return_value.raise_for_status = lambda: None
            result = search_app_store("MyApp")

        assert len(result) == 2
        assert all(r["platform"] == "app_store" for r in result)


# ──────────────────────────────────────────────
# Тесты search_google_play
# ──────────────────────────────────────────────

class TestSearchGooglePlay:
    """Тесты функции поиска в Google Play."""

    def test_google_play_returns_empty_on_error(self):
        """При любой ошибке → пустой список."""
        with patch("httpx.get", side_effect=Exception("connection error")):
            result = search_google_play("MyApp")
        assert result == []

    def test_google_play_returns_empty_on_non_200(self):
        """При HTTP != 200 → пустой список."""
        resp = MagicMock()
        resp.status_code = 403
        with patch("httpx.get", return_value=resp):
            result = search_google_play("MyApp")
        assert result == []

    def test_google_play_returns_list_on_success(self):
        """При успешном ответе возвращает список (возможно пустой)."""
        resp = MagicMock()
        resp.status_code = 200
        resp.text = ""  # нет ссылок на приложения
        with patch("httpx.get", return_value=resp):
            result = search_google_play("UnknownXYZ123")
        assert isinstance(result, list)


# ──────────────────────────────────────────────
# Тесты is_suspicious_app
# ──────────────────────────────────────────────

class TestIsSuspiciousApp:
    """Тесты функции определения подозрительности приложения."""

    def test_suspicious_app_different_developer(self):
        """Название содержит brand, developer другой → suspicious=True."""
        app = {
            "app_id": "999",
            "name": "MyApp - Clone",
            "developer": "ShadyDevs Corp",
            "bundle_id": "com.shadydevs.myapp",
            "url": "https://apps.apple.com/app/id999",
            "rating": 3.5,
            "reviews": 100,
            "platform": "app_store",
        }
        suspicious, reason = is_suspicious_app(app, "MyCompany Inc.", "MyApp")
        assert suspicious is True
        assert reason != ""

    def test_official_app_not_suspicious(self):
        """Совпадающий developer → not suspicious."""
        app = {
            "app_id": "123456",
            "name": "MyApp - Official",
            "developer": "MyCompany Inc.",
            "bundle_id": "com.mycompany.myapp",
            "url": "https://apps.apple.com/app/id123456",
            "rating": 4.5,
            "reviews": 1000,
            "platform": "app_store",
        }
        suspicious, reason = is_suspicious_app(app, "MyCompany Inc.", "MyApp")
        assert suspicious is False
        assert reason == ""

    def test_suspicious_by_bundle_id(self):
        """bundle_id содержит brand, developer другой → suspicious=True."""
        app = {
            "app_id": "555",
            "name": "Best App Ever",
            "developer": "FakeDev",
            "bundle_id": "com.fakedev.myapp.clone",
            "url": "https://apps.apple.com/app/id555",
            "rating": 3.0,
            "reviews": 200,
            "platform": "app_store",
        }
        suspicious, reason = is_suspicious_app(app, "MyCompany Inc.", "myapp")
        assert suspicious is True

    def test_suspicious_low_rating(self):
        """Рейтинг < 2.0 + brand в названии → suspicious=True."""
        app = {
            "app_id": "777",
            "name": "MyApp Unofficial",
            "developer": "Unknown",
            "bundle_id": "com.unknown.app",
            "url": "https://apps.apple.com/app/id777",
            "rating": 1.2,
            "reviews": 10,
            "platform": "app_store",
        }
        # Нет official_developer — только рейтинг проверяем
        suspicious, reason = is_suspicious_app(app, "", "MyApp")
        assert suspicious is True
        assert "1.2" in reason

    def test_no_official_developer_no_name_brand_not_suspicious(self):
        """Без official_developer и без brand в названии → not suspicious."""
        app = {
            "app_id": "888",
            "name": "SomeOtherApp",
            "developer": "AnyDev",
            "bundle_id": "com.anydev.someother",
            "url": "https://apps.apple.com/app/id888",
            "rating": 4.0,
            "reviews": 500,
            "platform": "app_store",
        }
        suspicious, reason = is_suspicious_app(app, "", "MyApp")
        assert suspicious is False

    def test_case_insensitive_brand_match(self):
        """Проверка бренда без учёта регистра."""
        app = {
            "app_id": "666",
            "name": "MYAPP - Fake",
            "developer": "BadActor",
            "bundle_id": "com.badactor.myapp",
            "url": "https://apps.apple.com/app/id666",
            "rating": 3.5,
            "reviews": 50,
            "platform": "app_store",
        }
        suspicious, reason = is_suspicious_app(app, "MyCompany Inc.", "MyApp")
        assert suspicious is True

    def test_rating_exactly_2_not_low_rating_trigger(self):
        """Рейтинг == 2.0 не должен триггерить low_rating (< 2.0 строго)."""
        app = {
            "app_id": "432",
            "name": "MyApp Something",
            "developer": "OfficialDev",
            "bundle_id": "com.officialdev.myapp",
            "url": "https://apps.apple.com/app/id432",
            "rating": 2.0,
            "reviews": 100,
            "platform": "app_store",
        }
        suspicious, reason = is_suspicious_app(app, "OfficialDev", "MyApp")
        # developer совпадает → не suspicious
        assert suspicious is False


# ──────────────────────────────────────────────
# Тесты monitor_mobile_apps
# ──────────────────────────────────────────────

class TestMonitorMobileApps:
    """Тесты основной функции мониторинга мобильных приложений."""

    def setup_method(self):
        """Очищаем кэш-файл перед каждым тестом."""
        cache_path = _get_seen_cache_path("test-mobile.com")
        if cache_path.exists():
            cache_path.unlink()

    def test_monitor_sends_event_for_suspicious(self):
        """Подозрительное приложение → событие brand_abuse отправляется."""
        fake_apps = [
            {
                "app_id": "999888",
                "name": "TestBrand Fake",
                "developer": "ShadyDev",
                "bundle_id": "com.shadydev.testbrand",
                "url": "https://apps.apple.com/app/id999888",
                "rating": 3.5,
                "reviews": 100,
                "platform": "app_store",
            }
        ]
        sent_events: list[dict] = []

        def _capture_post(url, json=None, headers=None, timeout=None):
            sent_events.append(json or {})
            return _ingest_ok()

        with patch("tasks.mobile_monitor.search_app_store", return_value=fake_apps), \
             patch("tasks.mobile_monitor.search_google_play", return_value=[]), \
             patch("httpx.post", side_effect=_capture_post):
            result = monitor_mobile_apps(
                "test-mobile.com",
                ["TestBrand"],
                "TestBrand Official Inc.",
                "http://localhost:8000",
                "secret",
            )

        assert result["suspicious"] >= 1
        assert result["sent"] >= 1
        assert len(sent_events) >= 1

        event = sent_events[0]
        assert event["event_type"] == "brand_abuse"
        assert event["severity"] == "high"
        assert event["source_name"] == "mobile_monitor"
        assert event["target_domain"] == "test-mobile.com"
        payload = event["payload"]
        assert payload["platform"] == "app_store"
        assert payload["app_id"] == "999888"

    def test_official_app_no_event(self):
        """Официальное приложение → события не отправляются."""
        official_apps = [
            {
                "app_id": "111222",
                "name": "TestBrand Official",
                "developer": "TestBrand Official Inc.",
                "bundle_id": "com.testbrand.official",
                "url": "https://apps.apple.com/app/id111222",
                "rating": 4.7,
                "reviews": 5000,
                "platform": "app_store",
            }
        ]

        with patch("tasks.mobile_monitor.search_app_store", return_value=official_apps), \
             patch("tasks.mobile_monitor.search_google_play", return_value=[]), \
             patch("httpx.post") as mock_post:
            result = monitor_mobile_apps(
                "test-mobile.com",
                ["TestBrand"],
                "TestBrand Official Inc.",
                "http://localhost:8000",
                "secret",
            )

        assert result["suspicious"] == 0
        assert result["sent"] == 0
        mock_post.assert_not_called()

    def test_deduplication_skips_seen_apps(self, tmp_path, monkeypatch):
        """Уже виденные app_id пропускаются при повторном запуске."""
        import tasks.mobile_monitor as mm

        # Подменяем _BASELINE_DIR на tmp_path
        monkeypatch.setattr(mm, "_BASELINE_DIR", tmp_path)

        already_seen_id = "as:999888"
        cache_file = tmp_path / "mobile_seen_dedup_mobile_com.json"
        cache_file.write_text(json.dumps([already_seen_id]))

        fake_apps = [
            {
                "app_id": "999888",
                "name": "TestBrand Fake",
                "developer": "ShadyDev",
                "bundle_id": "com.shadydev.testbrand",
                "url": "https://apps.apple.com/app/id999888",
                "rating": 3.5,
                "reviews": 100,
                "platform": "app_store",
            }
        ]

        with patch("tasks.mobile_monitor.search_app_store", return_value=fake_apps), \
             patch("tasks.mobile_monitor.search_google_play", return_value=[]), \
             patch("httpx.post") as mock_post:
            result = monitor_mobile_apps(
                "dedup-mobile.com",
                ["TestBrand"],
                "TestBrand Official Inc.",
                "http://localhost:8000",
                "secret",
            )

        # app_id уже был в кэше → событие не отправляем
        mock_post.assert_not_called()
        assert result["sent"] == 0

    def test_returns_correct_counters(self):
        """Счётчики app_store и google_play корректны."""
        as_apps = [
            {
                "app_id": "11",
                "name": "MyBrand App",
                "developer": "OfficialDev Inc.",
                "bundle_id": "com.official.mybrand",
                "url": "https://apps.apple.com/app/id11",
                "rating": 4.5,
                "reviews": 100,
                "platform": "app_store",
            }
        ]
        gp_apps = [
            {
                "app_id": "com.official.mybrand",
                "name": "MyBrand App",
                "developer": "",
                "bundle_id": "com.official.mybrand",
                "url": "https://play.google.com/store/apps/details?id=com.official.mybrand",
                "rating": 0,
                "reviews": 0,
                "platform": "google_play",
            }
        ]

        with patch("tasks.mobile_monitor.search_app_store", return_value=as_apps), \
             patch("tasks.mobile_monitor.search_google_play", return_value=gp_apps), \
             patch("httpx.post"):
            result = monitor_mobile_apps(
                "test-mobile2.com",
                ["MyBrand"],
                "OfficialDev Inc.",
                "http://localhost:8000",
                "secret",
            )

        assert result["app_store"] == 1
        assert result["google_play"] == 1

    def test_google_play_suspicious_sends_event(self):
        """Подозрительное приложение на Google Play → событие с platform=google_play."""
        gp_apps = [
            {
                "app_id": "com.fakeDev.mybrand",
                "name": "MyBrand Unofficial",
                "developer": "FakeDev",
                "bundle_id": "com.fakedev.mybrand",
                "url": "https://play.google.com/store/apps/details?id=com.fakedev.mybrand",
                "rating": 1.8,
                "reviews": 20,
                "platform": "google_play",
            }
        ]
        sent_events: list[dict] = []

        def _capture_post(url, json=None, headers=None, timeout=None):
            sent_events.append(json or {})
            return _ingest_ok()

        with patch("tasks.mobile_monitor.search_app_store", return_value=[]), \
             patch("tasks.mobile_monitor.search_google_play", return_value=gp_apps), \
             patch("httpx.post", side_effect=_capture_post), \
             patch("tasks.mobile_monitor._load_seen_ids", return_value=set()), \
             patch("tasks.mobile_monitor._save_seen_ids"):
            result = monitor_mobile_apps(
                "mybrand.com",
                ["MyBrand"],
                "OfficialDev Inc.",
                "http://localhost:8000",
                "secret",
            )

        assert result["suspicious"] >= 1
        gp_events = [
            e for e in sent_events
            if e.get("payload", {}).get("platform") == "google_play"
        ]
        assert len(gp_events) >= 1


# ──────────────────────────────────────────────
# Тесты API (интеграционные)
# ──────────────────────────────────────────────

class TestMobileScanAPI:
    """Интеграционные тесты API эндпоинта /scan/mobile."""

    @pytest.mark.asyncio
    async def test_mobile_scan_endpoint_returns_202(self, client, superuser_token):
        """POST /scan/mobile с валидным телом → 202 Accepted."""
        with patch("app.api.v1.endpoints.mobile_scan._MOBILE_MONITOR_AVAILABLE", True), \
             patch("app.api.v1.endpoints.mobile_scan.get_executor") as mock_exec:
            mock_exec.return_value.submit = MagicMock()

            resp = await client.post(
                "/api/v1/scan/mobile",
                json={
                    "domain": "example.com",
                    "brand_keywords": ["MyApp", "MyBrand"],
                    "official_developer": "MyCompany Inc.",
                },
                headers={"Authorization": f"Bearer {superuser_token}"},
            )

        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] == "processing"
        assert data["domain"] == "example.com"
        assert "MyApp" in data["keywords"]

    @pytest.mark.asyncio
    async def test_mobile_scan_without_keywords_returns_202(self, client, superuser_token):
        """POST /scan/mobile без keywords → 202."""
        with patch("app.api.v1.endpoints.mobile_scan._MOBILE_MONITOR_AVAILABLE", True), \
             patch("app.api.v1.endpoints.mobile_scan.get_executor") as mock_exec:
            mock_exec.return_value.submit = MagicMock()

            resp = await client.post(
                "/api/v1/scan/mobile",
                json={"domain": "mysite.org"},
                headers={"Authorization": f"Bearer {superuser_token}"},
            )

        assert resp.status_code == 202

    @pytest.mark.asyncio
    async def test_mobile_scan_422_empty_domain(self, client, superuser_token):
        """POST /scan/mobile с пустым доменом → 422."""
        resp = await client.post(
            "/api/v1/scan/mobile",
            json={"domain": "   ", "brand_keywords": []},
            headers={"Authorization": f"Bearer {superuser_token}"},
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_mobile_scan_401_without_token(self, client):
        """POST /scan/mobile без токена → 401/403."""
        resp = await client.post(
            "/api/v1/scan/mobile",
            json={"domain": "example.com"},
        )
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_mobile_scan_503_when_unavailable(self, client, superuser_token):
        """POST /scan/mobile когда воркер недоступен → 503."""
        with patch("app.api.v1.endpoints.mobile_scan._MOBILE_MONITOR_AVAILABLE", False):
            resp = await client.post(
                "/api/v1/scan/mobile",
                json={"domain": "example.com"},
                headers={"Authorization": f"Bearer {superuser_token}"},
            )
        assert resp.status_code == 503
