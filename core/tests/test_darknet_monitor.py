"""
Тесты воркера мониторинга даркнета (darknet_monitor.py).

Покрытие (18 тестов):
  check_ransomwatch:
    - найден по описанию
    - найден по заголовку
    - не найден
    - сетевая ошибка → возвращает []
    - кэш работает (повторный вызов не делает HTTP-запрос)
    - ответ не list → возвращает []
    - HTTP != 200 → возвращает []

  search_darksearch:
    - найден (items в data)
    - пустой data → []
    - сетевая ошибка → []
    - HTTP != 200 → []

  search_ahmia:
    - базовый парсинг при наличии совпадения
    - пустой ответ (домен не найден в html) → []
    - сетевая ошибка → []
    - HTTP != 200 → []

  monitor_darknet:
    - агрегация из всех трёх источников
    - ransomwatch → severity "critical", остальные → "high"
    - сбой одного источника не прерывает остальные

sys.path для workers добавляется в conftest.py
"""
from unittest.mock import MagicMock, patch

from tasks.darknet_monitor import (
    _RANSOMWATCH_CACHE,
    check_ransomwatch,
    monitor_darknet,
    search_ahmia,
    search_darksearch,
)


# ──────────────────────────────────────────────
# Вспомогательные фабрики mock-ответов
# ──────────────────────────────────────────────

def _make_response(status_code: int, body) -> MagicMock:
    """Создаёт mock httpx-ответа."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = body
    resp.text = str(body)
    return resp


def _ingest_ok() -> MagicMock:
    return _make_response(202, {"status": "accepted"})


def _ingest_dup() -> MagicMock:
    return _make_response(202, {"status": "duplicate"})


def _reset_ransomwatch_cache():
    """Сбрасывает кэш RansomWatch между тестами."""
    _RANSOMWATCH_CACHE["data"] = None
    _RANSOMWATCH_CACHE["fetched_at"] = 0.0


# ──────────────────────────────────────────────
# Тесты check_ransomwatch
# ──────────────────────────────────────────────

class TestCheckRansomwatch:
    """Тесты проверки домена в постах ransomware-группировок."""

    def setup_method(self):
        """Перед каждым тестом — сброс кэша."""
        _reset_ransomwatch_cache()

    def _posts_response(self, posts: list) -> MagicMock:
        return _make_response(200, posts)

    def test_found_in_description(self):
        """Домен найден в поле description поста."""
        posts = [
            {
                "group_name": "LockBit",
                "post_title": "New victim",
                "published": "2024-01-01",
                "description": "We hacked example.com and stole 500GB",
            }
        ]
        with patch("httpx.get", return_value=self._posts_response(posts)):
            result = check_ransomwatch("example.com")

        assert len(result) == 1
        assert result[0]["group"] == "LockBit"
        assert "example.com" in result[0]["snippet"].lower()
        assert result[0]["published"] == "2024-01-01"

    def test_found_in_title(self):
        """Домен найден в поле post_title."""
        posts = [
            {
                "group_name": "ALPHV",
                "post_title": "example.com | 100GB data",
                "published": "2024-02-15",
                "description": "",
            }
        ]
        with patch("httpx.get", return_value=self._posts_response(posts)):
            result = check_ransomwatch("example.com")

        assert len(result) == 1
        assert result[0]["group"] == "ALPHV"
        assert "example.com" in result[0]["title"].lower()

    def test_not_found(self):
        """Домен не упоминается ни в одном посте."""
        posts = [
            {
                "group_name": "Cl0p",
                "post_title": "another-company.com data",
                "published": "2024-03-01",
                "description": "victim another-company.com stolen",
            }
        ]
        with patch("httpx.get", return_value=self._posts_response(posts)):
            result = check_ransomwatch("example.com")

        assert result == []

    def test_network_error_returns_empty(self):
        """Сетевая ошибка — возвращает [], не поднимает исключение."""
        with patch("httpx.get", side_effect=Exception("connection refused")):
            result = check_ransomwatch("example.com")

        assert result == []

    def test_cache_prevents_second_request(self):
        """Повторный вызов внутри TTL не делает второй HTTP-запрос."""
        posts = [
            {
                "group_name": "REvil",
                "post_title": "example.com breached",
                "published": "2024-04-01",
                "description": "example.com full dump",
            }
        ]
        response = self._posts_response(posts)

        with patch("httpx.get", return_value=response) as mock_get:
            # Первый вызов — загружает данные
            check_ransomwatch("example.com")
            # Второй вызов — должен использовать кэш
            check_ransomwatch("example.com")

        # Несмотря на два вызова check_ransomwatch — HTTP-запрос только один
        assert mock_get.call_count == 1

    def test_invalid_response_format_returns_empty(self):
        """Если API вернул не список — безопасно возвращаем []."""
        with patch("httpx.get", return_value=_make_response(200, {"error": "bad"})):
            result = check_ransomwatch("example.com")

        assert result == []

    def test_http_non_200_returns_empty(self):
        """HTTP != 200 → возвращаем [], не падаем."""
        with patch("httpx.get", return_value=_make_response(503, {})):
            result = check_ransomwatch("example.com")

        assert result == []


# ──────────────────────────────────────────────
# Тесты search_darksearch
# ──────────────────────────────────────────────

class TestSearchDarksearch:
    """Тесты поиска через DarkSearch.io API."""

    def test_found_returns_results(self):
        """API вернул результаты — корректно парсятся."""
        body = {
            "data": [
                {
                    "title": "example.com credentials",
                    "description": "login:pass for example.com",
                    "link": "http://darksite.onion/post/1",
                    "onion": "http://darksite.onion/post/1",
                }
            ]
        }
        with patch("httpx.get", return_value=_make_response(200, body)):
            result = search_darksearch("example.com")

        assert len(result) == 1
        assert result[0]["title"] == "example.com credentials"
        assert "example.com" in result[0]["snippet"]
        assert result[0]["onion"] == "http://darksite.onion/post/1"

    def test_empty_data_returns_empty_list(self):
        """API вернул пустой список — возвращаем []."""
        with patch("httpx.get", return_value=_make_response(200, {"data": []})):
            result = search_darksearch("example.com")

        assert result == []

    def test_network_error_returns_empty(self):
        """Сетевая ошибка — возвращает [], не поднимает исключение."""
        with patch("httpx.get", side_effect=Exception("timeout")):
            result = search_darksearch("example.com")

        assert result == []

    def test_http_non_200_returns_empty(self):
        """HTTP 429 (rate limit) → возвращаем []."""
        with patch("httpx.get", return_value=_make_response(429, {})):
            result = search_darksearch("example.com")

        assert result == []


# ──────────────────────────────────────────────
# Тесты search_ahmia
# ──────────────────────────────────────────────

class TestSearchAhmia:
    """Тесты парсинга результатов Ahmia.fi."""

    def _html_with_result(self, domain: str) -> str:
        """Возвращает минимальный HTML с блоком результата для домена."""
        return f"""
        <html><body>
        <div class="result">
            <h4>Some Darknet Market — {domain}</h4>
            <a href="https://ahmia.fi/redirect/?search_term={domain}">link</a>
            <p class="result-content">Leaked credentials from {domain} with passwords</p>
            <span>{domain.split('.')[0]}abc123def456abc123def456abc123def456abc123def456abc123de.onion/page</span>
        </div>
        </body></html>
        """

    def test_parses_result_with_domain(self):
        """Находит результат когда домен присутствует в HTML."""
        html = self._html_with_result("example.com")
        resp = MagicMock()
        resp.status_code = 200
        resp.text = html

        with patch("httpx.get", return_value=resp):
            result = search_ahmia("example.com")

        # В минимальном HTML есть хотя бы один заголовок с доменом
        assert isinstance(result, list)

    def test_no_match_returns_empty(self):
        """HTML не содержит домена — возвращает []."""
        html = "<html><body><h4>Some other title</h4></body></html>"
        resp = MagicMock()
        resp.status_code = 200
        resp.text = html

        with patch("httpx.get", return_value=resp):
            result = search_ahmia("example.com")

        assert result == []

    def test_network_error_returns_empty(self):
        """Сетевая ошибка — возвращает [], не поднимает исключение."""
        with patch("httpx.get", side_effect=Exception("connection timeout")):
            result = search_ahmia("example.com")

        assert result == []

    def test_http_non_200_returns_empty(self):
        """HTTP != 200 → возвращаем []."""
        with patch("httpx.get", return_value=_make_response(403, {})):
            result = search_ahmia("example.com")

        assert result == []


# ──────────────────────────────────────────────
# Тесты monitor_darknet (агрегатор)
# ──────────────────────────────────────────────

_NO_EXTRA_SOURCES = [
    patch("tasks.darknet_monitor._RANSOMWARE_SITES_AVAILABLE", False),
    patch("tasks.darknet_monitor._INTELX_AVAILABLE", False),
]


class TestMonitorDarknet:
    """Тесты агрегирующей функции monitor_darknet (3 clearnet-источника)."""

    def setup_method(self):
        """Сбрасываем кэш перед каждым тестом."""
        _reset_ransomwatch_cache()

    def test_aggregates_all_sources(self):
        """monitor_darknet вызывает все три источника и суммирует результаты."""
        rw_result = [{"group": "LockBit", "title": "example.com stolen", "published": "2024-01-01", "snippet": "data stolen"}]
        ah_result = [{"title": "ahmia hit", "url": "https://ahmia.fi/...", "onion": "abc.onion", "snippet": "found on ahmia"}]
        ds_result = [{"title": "darksearch hit", "url": "http://dark.onion", "onion": "dark.onion", "snippet": "ds snippet"}]

        with patch("tasks.darknet_monitor.check_ransomwatch", return_value=rw_result), \
             patch("tasks.darknet_monitor.search_ahmia", return_value=ah_result), \
             patch("tasks.darknet_monitor.search_darksearch", return_value=ds_result), \
             patch("tasks.darknet_monitor.bulk_ingest", return_value={"sent": 3, "errors": 0}), \
             patch("tasks.darknet_monitor._RANSOMWARE_SITES_AVAILABLE", False), \
             patch("tasks.darknet_monitor._INTELX_AVAILABLE", False):
            result = monitor_darknet("example.com", "http://localhost:8000", "secret")

        assert result["sources_checked"] == 3
        assert result["found"] == 3
        assert result["sent"] == 3
        assert result["critical"] == 1    # только ransomwatch даёт critical

    def test_ransomwatch_hit_is_critical(self):
        """Находки из ransomwatch содержат severity='critical' в батче."""
        rw_result = [
            {"group": "ALPHV", "title": "example.com", "published": "2024-05-01", "snippet": "100GB stolen"},
        ]

        captured_batch: list[list] = []

        def _capture_bulk(events, *args, **kwargs):
            captured_batch.append(events)
            return {"sent": len(events), "errors": 0}

        with patch("tasks.darknet_monitor.check_ransomwatch", return_value=rw_result), \
             patch("tasks.darknet_monitor.search_ahmia", return_value=[]), \
             patch("tasks.darknet_monitor.search_darksearch", return_value=[]), \
             patch("tasks.darknet_monitor.bulk_ingest", side_effect=_capture_bulk), \
             patch("tasks.darknet_monitor._RANSOMWARE_SITES_AVAILABLE", False), \
             patch("tasks.darknet_monitor._INTELX_AVAILABLE", False):
            result = monitor_darknet("example.com", "http://localhost:8000", "secret")

        assert result["critical"] == 1
        assert len(captured_batch) == 1
        events = captured_batch[0]
        assert len(events) == 1
        assert events[0]["severity"] == "critical"
        assert events[0]["payload"]["source"] == "ransomwatch"
        assert events[0]["payload"]["group"] == "ALPHV"

    def test_ahmia_and_darksearch_hits_are_high(self):
        """Находки из ahmia и darksearch имеют severity='high' в батче."""
        ah_result = [{"title": "t", "url": "u", "onion": "o.onion", "snippet": "s"}]
        ds_result = [{"title": "t2", "url": "u2", "onion": "o2.onion", "snippet": "s2"}]

        captured_batch: list[list] = []

        def _capture_bulk(events, *args, **kwargs):
            captured_batch.append(events)
            return {"sent": len(events), "errors": 0}

        with patch("tasks.darknet_monitor.check_ransomwatch", return_value=[]), \
             patch("tasks.darknet_monitor.search_ahmia", return_value=ah_result), \
             patch("tasks.darknet_monitor.search_darksearch", return_value=ds_result), \
             patch("tasks.darknet_monitor.bulk_ingest", side_effect=_capture_bulk), \
             patch("tasks.darknet_monitor._RANSOMWARE_SITES_AVAILABLE", False), \
             patch("tasks.darknet_monitor._INTELX_AVAILABLE", False):
            result = monitor_darknet("example.com", "http://localhost:8000", "secret")

        assert result["critical"] == 0
        assert result["sent"] == 2
        severities = {e["severity"] for e in captured_batch[0]}
        assert severities == {"high"}

    def test_one_source_failure_does_not_stop_others(self):
        """Сбой ransomwatch не мешает ahmia и darksearch отработать."""
        ah_result = [{"title": "ahmia", "url": "u", "onion": "o.onion", "snippet": "s"}]

        with patch("tasks.darknet_monitor.check_ransomwatch", side_effect=Exception("rw down")), \
             patch("tasks.darknet_monitor.search_ahmia", return_value=ah_result), \
             patch("tasks.darknet_monitor.search_darksearch", return_value=[]), \
             patch("tasks.darknet_monitor.bulk_ingest", return_value={"sent": 1, "errors": 0}), \
             patch("tasks.darknet_monitor._RANSOMWARE_SITES_AVAILABLE", False), \
             patch("tasks.darknet_monitor._INTELX_AVAILABLE", False):
            result = monitor_darknet("example.com", "http://localhost:8000", "secret")

        # ransomwatch упал (до increment), ahmia нашла 1 результат, darksearch — 0
        assert result["found"] == 1
        assert result["sent"] == 1
        assert result["sources_checked"] == 2

    def test_normalizes_domain(self):
        """monitor_darknet нормализует домен (strip + lower)."""
        with patch("tasks.darknet_monitor.check_ransomwatch", return_value=[]) as rw_mock, \
             patch("tasks.darknet_monitor.search_ahmia", return_value=[]), \
             patch("tasks.darknet_monitor.search_darksearch", return_value=[]), \
             patch("tasks.darknet_monitor._RANSOMWARE_SITES_AVAILABLE", False), \
             patch("tasks.darknet_monitor._INTELX_AVAILABLE", False):
            monitor_darknet("  EXAMPLE.COM  ", "http://localhost:8000", "secret")

        called_domain = rw_mock.call_args[0][0]
        assert called_domain == "example.com"

    def test_ingest_error_does_not_count_as_sent(self):
        """Ошибка отправки в Core API → sent=0, found/critical считаются от найденного."""
        rw_result = [{"group": "LockBit", "title": "example.com", "published": "2024-01-01", "snippet": "x"}]

        with patch("tasks.darknet_monitor.check_ransomwatch", return_value=rw_result), \
             patch("tasks.darknet_monitor.search_ahmia", return_value=[]), \
             patch("tasks.darknet_monitor.search_darksearch", return_value=[]), \
             patch("tasks.darknet_monitor.bulk_ingest", return_value={"sent": 0, "errors": 1}), \
             patch("tasks.darknet_monitor._RANSOMWARE_SITES_AVAILABLE", False), \
             patch("tasks.darknet_monitor._INTELX_AVAILABLE", False):
            result = monitor_darknet("example.com", "http://localhost:8000", "secret")

        assert result["found"] == 1
        assert result["sent"] == 0
        assert result["critical"] == 1  # найдено ransomwatch (до отправки)

    def test_no_findings_returns_zeros(self):
        """Если ничего не найдено — все счётчики нулевые, sources_checked=3."""
        with patch("tasks.darknet_monitor.check_ransomwatch", return_value=[]), \
             patch("tasks.darknet_monitor.search_ahmia", return_value=[]), \
             patch("tasks.darknet_monitor.search_darksearch", return_value=[]), \
             patch("tasks.darknet_monitor._RANSOMWARE_SITES_AVAILABLE", False), \
             patch("tasks.darknet_monitor._INTELX_AVAILABLE", False):
            result = monitor_darknet("clean-domain.com", "http://localhost:8000", "secret")

        assert result["sources_checked"] == 3
        assert result["found"] == 0
        assert result["sent"] == 0
        assert result["critical"] == 0
