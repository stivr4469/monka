"""
Тесты Brand Monitor — Phase 12.B.

Покрытие:
  - is_negative_mention: каждое негативное слово → True; нейтральный текст → False
  - search_reddit: мок httpx success; timeout → []; non-200 → []
  - search_hackernews: мок httpx success; пустые hits → []
  - monitor_brand: негативные посты → события; нейтральные → 0;
                   brand_keywords пустой → использует домен без TLD
  - API: 202 accepted; 422 невалидный домен; 401 без токена

sys.path для workers добавляется в conftest.py
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest
import pytest_asyncio

from tasks.brand_monitor import (
    NEGATIVE_KEYWORDS,
    _get_seen_cache_path,
    _load_seen_urls,
    _save_seen_urls,
    is_negative_mention,
    monitor_brand,
    search_hackernews,
    search_reddit,
)


# ──────────────────────────────────────────────
# Вспомогательные фабрики mock-ответов
# ──────────────────────────────────────────────

def _make_response(status_code: int, json_body=None) -> MagicMock:
    """Создаёт mock httpx-ответа."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_body or {}
    return resp


def _ingest_ok() -> MagicMock:
    return _make_response(202, {"status": "accepted"})


def _reddit_response(posts: list[dict]) -> dict:
    """Формирует структуру ответа Reddit API."""
    return {
        "data": {
            "children": [
                {
                    "data": {
                        "title": p.get("title", ""),
                        "selftext": p.get("selftext", ""),
                        "permalink": p.get("permalink", "/r/test/comments/abc/test/"),
                        "subreddit": p.get("subreddit", "test"),
                        "created_utc": p.get("created_utc", 1716825600.0),
                    }
                }
                for p in posts
            ]
        }
    }


def _hn_response(hits: list[dict]) -> dict:
    """Формирует структуру ответа Algolia HN API."""
    return {"hits": hits}


# ──────────────────────────────────────────────
# Тесты is_negative_mention
# ──────────────────────────────────────────────

class TestIsNegativeMention:
    """Тесты определения негативных упоминаний."""

    def test_hack_keyword_detected(self):
        """'hack' в тексте → True."""
        is_neg, kw = is_negative_mention("Company was hacked last night")
        assert is_neg is True
        assert kw in ("hack", "hacked")

    def test_breach_keyword_detected(self):
        """'breach' → True."""
        is_neg, kw = is_negative_mention("data breach confirmed by vendor")
        assert is_neg is True
        assert "breach" in kw

    def test_leak_keyword_detected(self):
        """'leaked' → True."""
        is_neg, kw = is_negative_mention("Database leaked on darkweb forum")
        assert is_neg is True
        assert "leak" in kw

    def test_phishing_keyword_detected(self):
        """'phishing' → True."""
        is_neg, kw = is_negative_mention("Active phishing campaign targeting users")
        assert is_neg is True
        assert "phish" in kw

    def test_ransomware_keyword_detected(self):
        """'ransomware' → True."""
        is_neg, kw = is_negative_mention("ransomware group claims attack")
        assert is_neg is True
        assert kw == "ransomware"

    def test_malware_keyword_detected(self):
        """'malware' → True."""
        is_neg, kw = is_negative_mention("malware found in app")
        assert is_neg is True
        assert kw == "malware"

    def test_scam_keyword_detected(self):
        """'scam' → True."""
        is_neg, kw = is_negative_mention("this is a scam, avoid!")
        assert is_neg is True
        assert kw == "scam"

    def test_vulnerability_keyword_detected(self):
        """'vulnerability' → True."""
        is_neg, kw = is_negative_mention("critical vulnerability disclosed")
        assert is_neg is True
        assert kw == "vulnerability"

    def test_data_loss_two_words(self):
        """'data loss' (двусловная фраза) → True."""
        is_neg, kw = is_negative_mention("Incident: data loss reported in Q3")
        assert is_neg is True
        assert kw == "data loss"

    def test_unauthorized_keyword_detected(self):
        """'unauthorized' → True."""
        is_neg, kw = is_negative_mention("unauthorized access detected")
        assert is_neg is True
        assert kw == "unauthorized"

    def test_neutral_text_returns_false(self):
        """Нейтральный текст → (False, '')."""
        is_neg, kw = is_negative_mention("New product release scheduled for Q4")
        assert is_neg is False
        assert kw == ""

    def test_empty_string_returns_false(self):
        """Пустая строка → (False, '')."""
        is_neg, kw = is_negative_mention("")
        assert is_neg is False
        assert kw == ""

    def test_case_insensitive_detection(self):
        """Поиск не чувствителен к регистру."""
        is_neg, _ = is_negative_mention("HACKED COMPANY SERVERS DOWN")
        assert is_neg is True

    def test_returns_first_matched_keyword(self):
        """Возвращает первое совпавшее слово из NEGATIVE_KEYWORDS."""
        # Текст содержит несколько негативных слов
        is_neg, kw = is_negative_mention("hack and breach both found")
        assert is_neg is True
        # Первое по порядку в NEGATIVE_KEYWORDS — "hack"
        assert kw == "hack"


# ──────────────────────────────────────────────
# Тесты search_reddit
# ──────────────────────────────────────────────

class TestSearchReddit:
    """Тесты функции поиска в Reddit."""

    def test_success_parses_posts(self):
        """Успешный ответ Reddit API → список постов."""
        posts_data = [
            {
                "title": "CompanyX had a breach",
                "selftext": "details here",
                "permalink": "/r/netsec/comments/abc/",
                "subreddit": "netsec",
                "created_utc": 1716825600.0,
            }
        ]
        resp = _make_response(200, _reddit_response(posts_data))

        with patch("httpx.get", return_value=resp):
            result = search_reddit("CompanyX")

        assert len(result) == 1
        assert result[0]["title"] == "CompanyX had a breach"
        assert result[0]["text"] == "details here"
        assert result[0]["subreddit"] == "netsec"
        assert "https://www.reddit.com" in result[0]["url"]
        assert result[0]["created_at"] != ""

    def test_timeout_returns_empty_list(self):
        """Таймаут → пустой список, без исключения."""
        with patch("httpx.get", side_effect=httpx.TimeoutException("timeout")):
            result = search_reddit("CompanyX")

        assert result == []

    def test_non_200_status_returns_empty_list(self):
        """HTTP не-200 → пустой список."""
        resp = _make_response(429)

        with patch("httpx.get", return_value=resp):
            result = search_reddit("CompanyX")

        assert result == []

    def test_network_error_returns_empty_list(self):
        """Сетевая ошибка → пустой список, без исключения."""
        with patch("httpx.get", side_effect=Exception("connection refused")):
            result = search_reddit("CompanyX")

        assert result == []

    def test_empty_children_returns_empty_list(self):
        """Пустой список children → пустой список."""
        resp = _make_response(200, {"data": {"children": []}})

        with patch("httpx.get", return_value=resp):
            result = search_reddit("CompanyX")

        assert result == []


# ──────────────────────────────────────────────
# Тесты search_hackernews
# ──────────────────────────────────────────────

class TestSearchHackerNews:
    """Тесты функции поиска в Hacker News."""

    def test_success_parses_hits(self):
        """Успешный ответ Algolia API → список постов."""
        hits = [
            {
                "objectID": "12345",
                "title": "CompanyX API exposed credentials",
                "url": "https://blog.example.com/companyx-leak",
                "created_at_i": 1716825600,
                "points": 42,
            }
        ]
        resp = _make_response(200, _hn_response(hits))

        with patch("httpx.get", return_value=resp):
            result = search_hackernews("CompanyX")

        assert len(result) == 1
        assert result[0]["title"] == "CompanyX API exposed credentials"
        assert result[0]["url"] == "https://blog.example.com/companyx-leak"
        assert result[0]["hn_id"] == "12345"
        assert result[0]["points"] == 42
        assert result[0]["created_at"] != ""

    def test_empty_hits_returns_empty_list(self):
        """Пустой hits → пустой список."""
        resp = _make_response(200, _hn_response([]))

        with patch("httpx.get", return_value=resp):
            result = search_hackernews("CompanyX")

        assert result == []

    def test_timeout_returns_empty_list(self):
        """Таймаут → пустой список."""
        with patch("httpx.get", side_effect=httpx.TimeoutException("timeout")):
            result = search_hackernews("CompanyX")

        assert result == []

    def test_non_200_returns_empty_list(self):
        """HTTP не-200 → пустой список."""
        resp = _make_response(503)

        with patch("httpx.get", return_value=resp):
            result = search_hackernews("CompanyX")

        assert result == []

    def test_hit_without_url_uses_hn_link(self):
        """Если у hit нет url — генерируем ссылку на HN item."""
        hits = [
            {
                "objectID": "99999",
                "title": "Security alert",
                "url": None,
                "created_at_i": 1716825600,
                "points": 10,
            }
        ]
        resp = _make_response(200, _hn_response(hits))

        with patch("httpx.get", return_value=resp):
            result = search_hackernews("SecurityAlert")

        assert len(result) == 1
        assert "news.ycombinator.com/item?id=99999" in result[0]["url"]


# ──────────────────────────────────────────────
# Тесты monitor_brand
# ──────────────────────────────────────────────

class TestMonitorBrand:
    """Тесты основной функции мониторинга бренда."""

    def setup_method(self):
        """Очищаем кэш-файл перед каждым тестом."""
        cache_path = _get_seen_cache_path("test-example.com")
        if cache_path.exists():
            cache_path.unlink()

    def test_negative_posts_send_events(self):
        """Посты с негативными ключевыми словами → события отправляются."""
        # Reddit возвращает пост с "breach"
        reddit_result = [
            {
                "title": "example breach confirmed",
                "text": "details about the breach",
                "url": "https://www.reddit.com/r/netsec/comments/abc/",
                "subreddit": "netsec",
                "created_at": "2024-05-01T10:00:00+00:00",
            }
        ]
        # HN возвращает пустой список
        hn_result: list[dict] = []

        sent_events: list[dict] = []

        def _capture_post(url, json=None, headers=None, timeout=None):
            sent_events.append(json or {})
            return _ingest_ok()

        with patch("tasks.brand_monitor.search_reddit", return_value=reddit_result), \
             patch("tasks.brand_monitor.search_hackernews", return_value=hn_result), \
             patch("httpx.post", side_effect=_capture_post), \
             patch("time.sleep"):
            result = monitor_brand(
                "test-example.com",
                ["TestBrand"],
                "http://localhost:8000",
                "secret",
            )

        assert result["negative"] >= 1
        assert result["sent"] >= 1
        assert len(sent_events) >= 1
        event = sent_events[0]
        assert event["event_type"] == "forum_mention"
        assert event["severity"] == "medium"
        assert event["source_type"] == "osint"
        assert event["source_name"] == "brand_monitor"
        assert event["target_domain"] == "test-example.com"
        payload = event["payload"]
        assert payload["platform"] == "reddit"
        assert payload["sentiment"] == "negative"
        assert "matched_keyword" in payload

    def test_neutral_posts_send_no_events(self):
        """Нейтральные посты → 0 событий отправлено."""
        reddit_result = [
            {
                "title": "Great product launch event",
                "text": "Company announces new features",
                "url": "https://www.reddit.com/r/tech/comments/xyz/",
                "subreddit": "tech",
                "created_at": "2024-05-01T10:00:00+00:00",
            }
        ]
        hn_result: list[dict] = []

        with patch("tasks.brand_monitor.search_reddit", return_value=reddit_result), \
             patch("tasks.brand_monitor.search_hackernews", return_value=hn_result), \
             patch("httpx.post") as mock_post, \
             patch("time.sleep"):
            result = monitor_brand(
                "test-example.com",
                ["TestBrand"],
                "http://localhost:8000",
                "secret",
            )

        assert result["negative"] == 0
        assert result["sent"] == 0
        mock_post.assert_not_called()

    def test_empty_brand_keywords_uses_domain_without_tld(self):
        """Пустой brand_keywords → используется имя домена без TLD как ключевое слово."""
        called_keywords: list[str] = []

        def _capture_reddit(brand, limit=25):
            called_keywords.append(brand)
            return []

        def _capture_hn(brand):
            called_keywords.append(brand)
            return []

        with patch("tasks.brand_monitor.search_reddit", side_effect=_capture_reddit), \
             patch("tasks.brand_monitor.search_hackernews", side_effect=_capture_hn), \
             patch("time.sleep"):
            monitor_brand(
                "mycompany.com",
                [],
                "http://localhost:8000",
                "secret",
            )

        # Должен использовать "mycompany" (без ".com")
        assert "mycompany" in called_keywords

    def test_hn_negative_post_sends_event(self):
        """Негативный пост в HN → событие с platform=hackernews."""
        reddit_result: list[dict] = []
        hn_result = [
            {
                "title": "Hacker exploits vulnerability in TestCo API",
                "url": "https://news.ycombinator.com/item?id=11111",
                "hn_id": "11111",
                "created_at": "2024-05-01T10:00:00+00:00",
                "points": 150,
            }
        ]

        sent_events: list[dict] = []

        def _capture_post(url, json=None, headers=None, timeout=None):
            sent_events.append(json or {})
            return _ingest_ok()

        with patch("tasks.brand_monitor.search_reddit", return_value=reddit_result), \
             patch("tasks.brand_monitor.search_hackernews", return_value=hn_result), \
             patch("httpx.post", side_effect=_capture_post), \
             patch("tasks.brand_monitor._load_seen_urls", return_value=set()), \
             patch("tasks.brand_monitor._save_seen_urls"), \
             patch("time.sleep"):
            result = monitor_brand(
                "testco.com",
                ["TestCo"],
                "http://localhost:8000",
                "secret",
            )

        assert result["negative"] >= 1
        hn_events = [e for e in sent_events if e.get("payload", {}).get("platform") == "hackernews"]
        assert len(hn_events) >= 1

    def test_deduplication_skips_seen_urls(self, tmp_path, monkeypatch):
        """Уже виденные URL пропускаются при повторном запуске."""
        # Патчим путь к кэш-файлу на tmp_path
        cache_file = tmp_path / "brand_seen_dedup_test.json"
        already_seen_url = "https://www.reddit.com/r/netsec/comments/dup/"

        # Предзаполняем кэш
        cache_file.write_text(json.dumps([already_seen_url]))

        def _fake_cache_path(domain):
            return cache_file

        monkeypatch.setattr("tasks.brand_monitor._get_seen_cache_path", _fake_cache_path)

        reddit_result = [
            {
                "title": "This is a breach event",
                "text": "leaked data",
                "url": already_seen_url,
                "subreddit": "netsec",
                "created_at": "2024-05-01T10:00:00+00:00",
            }
        ]

        with patch("tasks.brand_monitor.search_reddit", return_value=reddit_result), \
             patch("tasks.brand_monitor.search_hackernews", return_value=[]), \
             patch("httpx.post") as mock_post, \
             patch("time.sleep"):
            result = monitor_brand(
                "dedup-test.com",
                ["DeduTest"],
                "http://localhost:8000",
                "secret",
            )

        # URL уже был в кэше — событие не отправляем
        mock_post.assert_not_called()
        assert result["sent"] == 0

    def test_domain_with_multiple_parts_strips_tld(self):
        """Домен с несколькими частями: my.company.io → my.company."""
        called_keywords: list[str] = []

        def _capture_reddit(brand, limit=25):
            called_keywords.append(brand)
            return []

        def _capture_hn(brand):
            called_keywords.append(brand)
            return []

        with patch("tasks.brand_monitor.search_reddit", side_effect=_capture_reddit), \
             patch("tasks.brand_monitor.search_hackernews", side_effect=_capture_hn), \
             patch("time.sleep"):
            monitor_brand(
                "my.company.io",
                [],
                "http://localhost:8000",
                "secret",
            )

        assert "my.company" in called_keywords


# ──────────────────────────────────────────────
# Тесты API (интеграционные)
# ──────────────────────────────────────────────

class TestBrandScanAPI:
    """Интеграционные тесты API эндпоинта /scan/brand."""

    @pytest.mark.asyncio
    async def test_202_accepted_with_valid_domain(self, client, superuser_token):
        """POST /scan/brand с валидным доменом → 202 Accepted."""
        with patch("app.api.v1.endpoints.brand_scan._BRAND_MONITOR_AVAILABLE", True), \
             patch("app.api.v1.endpoints.brand_scan.monitor_brand") as mock_monitor, \
             patch("app.api.v1.endpoints.brand_scan.get_executor") as mock_exec:
            mock_exec.return_value.submit = MagicMock()

            resp = await client.post(
                "/api/v1/scan/brand",
                json={"domain": "example.com", "brand_keywords": ["ExampleCo"]},
                headers={"Authorization": f"Bearer {superuser_token}"},
            )

        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] == "processing"
        assert data["domain"] == "example.com"
        assert "ExampleCo" in data["keywords"]

    @pytest.mark.asyncio
    async def test_202_without_brand_keywords(self, client, superuser_token):
        """POST /scan/brand без brand_keywords → 202, ключевые слова пустые."""
        with patch("app.api.v1.endpoints.brand_scan._BRAND_MONITOR_AVAILABLE", True), \
             patch("app.api.v1.endpoints.brand_scan.get_executor") as mock_exec:
            mock_exec.return_value.submit = MagicMock()

            resp = await client.post(
                "/api/v1/scan/brand",
                json={"domain": "mysite.org"},
                headers={"Authorization": f"Bearer {superuser_token}"},
            )

        assert resp.status_code == 202

    @pytest.mark.asyncio
    async def test_422_with_empty_domain(self, client, superuser_token):
        """POST /scan/brand с пустым доменом → 422 Unprocessable Entity."""
        resp = await client.post(
            "/api/v1/scan/brand",
            json={"domain": "   ", "brand_keywords": []},
            headers={"Authorization": f"Bearer {superuser_token}"},
        )

        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_401_without_token(self, client):
        """POST /scan/brand без токена → 401 Unauthorized."""
        resp = await client.post(
            "/api/v1/scan/brand",
            json={"domain": "example.com"},
        )

        # HTTPBearer вернёт 403 при отсутствии заголовка или 401 при невалидном
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_503_when_monitor_unavailable(self, client, superuser_token):
        """POST /scan/brand когда воркер недоступен → 503 Service Unavailable."""
        with patch("app.api.v1.endpoints.brand_scan._BRAND_MONITOR_AVAILABLE", False):
            resp = await client.post(
                "/api/v1/scan/brand",
                json={"domain": "example.com"},
                headers={"Authorization": f"Bearer {superuser_token}"},
            )

        assert resp.status_code == 503
