"""
Тесты воркера мониторинга Telegram-каналов.

Покрытие:
  - fetch_channel_posts: успешный парсинг HTML, сетевая ошибка,
                         пустая страница, таймаут
  - scan_channel: совпадение по domain/email/url, нет совпадений,
                  duplicate от Core API, ingest ошибка
  - monitor_telegram_channels: агрегация результатов,
                                 extra_channels дедупликация,
                                 один канал падает → остальные продолжают

sys.path для workers добавляется в conftest.py
"""

from unittest.mock import MagicMock, patch

import httpx

from tasks.telegram_monitor import (
    DEFAULT_LEAK_CHANNELS,
    _build_domain_patterns,
    _find_match_type,
    _parse_posts,
    _send_ingest_event,
    _strip_html,
    fetch_channel_posts,
    monitor_telegram_channels,
    scan_channel,
)


# ──────────────────────────────────────────────
# Вспомогательные фабрики mock-ответов
# ──────────────────────────────────────────────

def _make_response(status_code: int, text: str = "", json_body=None) -> MagicMock:
    """Создаёт mock httpx-ответа."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.json.return_value = json_body or {}
    return resp


def _ingest_ok() -> MagicMock:
    return _make_response(202, json_body={"status": "accepted"})


def _ingest_dup() -> MagicMock:
    return _make_response(202, json_body={"status": "duplicate"})


# HTML-фрагмент одного поста — максимально приближен к реальному t.me/s
_SAMPLE_POST_HTML = """
<div class="tgme_widget_message_wrap js-widget_message_wrap">
  <div class="tgme_widget_message">
    <div class="tgme_widget_message_text js-message_text">
      Leaked database: admin@example.com passwords exposed
    </div>
    <div class="tgme_widget_message_footer">
      <a href="https://t.me/leakbase_io/1234">
        <time datetime="2024-05-01T10:00:00+00:00">May 1</time>
      </a>
    </div>
  </div>
</div>
"""

# HTML-фрагмент поста с URL-упоминанием домена
_SAMPLE_URL_POST_HTML = """
<div class="tgme_widget_message_wrap js-widget_message_wrap">
  <div class="tgme_widget_message">
    <div class="tgme_widget_message_text js-message_text">
      Database dump from https://example.com/api/users is online
    </div>
    <div class="tgme_widget_message_footer">
      <a href="https://t.me/darkwebinformer/5678">
        <time datetime="2024-05-02T15:30:00+00:00">May 2</time>
      </a>
    </div>
  </div>
</div>
"""

# HTML-фрагмент без упоминания тестового домена
_SAMPLE_NO_MATCH_HTML = """
<div class="tgme_widget_message_wrap js-widget_message_wrap">
  <div class="tgme_widget_message">
    <div class="tgme_widget_message_text js-message_text">
      New breach at google.com and microsoft.com — 10M records
    </div>
    <div class="tgme_widget_message_footer">
      <a href="https://t.me/breachforums_com/9999">
        <time datetime="2024-05-03T08:00:00+00:00">May 3</time>
      </a>
    </div>
  </div>
</div>
"""


# ──────────────────────────────────────────────
# Юнит-тесты вспомогательных функций
# ──────────────────────────────────────────────

class TestStripHtml:
    """Тесты очистки HTML-разметки."""

    def test_removes_tags(self):
        assert _strip_html("<b>hello</b>") == "hello"

    def test_decodes_entities(self):
        assert "&amp;" not in _strip_html("&amp;")
        assert ">" in _strip_html("a &gt; b")

    def test_empty_string(self):
        assert _strip_html("") == ""

    def test_nested_tags(self):
        result = _strip_html("<a href='x'><b>text</b></a>")
        assert "text" in result
        assert "<" not in result


class TestBuildDomainPatterns:
    """Тесты regex-паттернов совпадения домена."""

    def test_email_match(self):
        patterns = _build_domain_patterns("example.com")
        assert _find_match_type("user@example.com info", patterns) == "email"

    def test_url_match(self):
        patterns = _build_domain_patterns("example.com")
        assert _find_match_type("https://example.com/login leak", patterns) == "url"

    def test_subdomain_url_match(self):
        patterns = _build_domain_patterns("example.com")
        assert _find_match_type("api.example.com credentials", patterns) is not None

    def test_domain_direct_match(self):
        patterns = _build_domain_patterns("example.com")
        assert _find_match_type("dump of example.com found", patterns) == "domain"

    def test_no_match_other_domain(self):
        patterns = _build_domain_patterns("example.com")
        assert _find_match_type("data from google.com breach", patterns) is None

    def test_dots_in_domain_escaped(self):
        """Точки в домене не должны матчить произвольный символ."""
        patterns = _build_domain_patterns("example.com")
        assert _find_match_type("exampleXcom nothing", patterns) is None

    def test_email_takes_priority_over_domain(self):
        """Email-паттерн специфичнее, должен матчиться первым."""
        patterns = _build_domain_patterns("example.com")
        match = _find_match_type("admin@example.com and example.com here", patterns)
        assert match == "email"


# ──────────────────────────────────────────────
# Тесты _parse_posts
# ──────────────────────────────────────────────

class TestParsePosts:
    """Тесты HTML-парсера постов."""

    def test_parses_email_post(self):
        posts = _parse_posts(_SAMPLE_POST_HTML, "leakbase_io")
        assert len(posts) >= 1
        post = posts[0]
        assert "example.com" in post["text"]
        assert post["channel"] == "leakbase_io"

    def test_parses_url_and_date(self):
        posts = _parse_posts(_SAMPLE_URL_POST_HTML, "darkwebinformer")
        assert len(posts) >= 1
        post = posts[0]
        assert "2024-05-02" in post["date"]
        assert "t.me/darkwebinformer/5678" in post["url"]

    def test_empty_html_returns_empty_list(self):
        posts = _parse_posts("", "testchannel")
        assert posts == []

    def test_channel_name_preserved(self):
        posts = _parse_posts(_SAMPLE_POST_HTML, "my_channel")
        for post in posts:
            assert post["channel"] == "my_channel"

    def test_multiple_posts_parsed(self):
        combined = _SAMPLE_POST_HTML + _SAMPLE_URL_POST_HTML + _SAMPLE_NO_MATCH_HTML
        posts = _parse_posts(combined, "test")
        assert len(posts) >= 2


# ──────────────────────────────────────────────
# Тесты fetch_channel_posts
# ──────────────────────────────────────────────

class TestFetchChannelPosts:
    """Тесты загрузки постов из канала."""

    def test_success_parses_posts(self):
        """Успешный ответ: парсит HTML-фрагмент с постом."""
        html_body = _SAMPLE_POST_HTML
        resp = _make_response(200, text=html_body)

        with patch("httpx.get", return_value=resp):
            posts = fetch_channel_posts("leakbase_io")

        assert isinstance(posts, list)
        # Проверяем что парсер нашёл хотя бы один пост с содержимым
        assert any("example.com" in p["text"] for p in posts)

    def test_network_error_returns_empty(self):
        """Ошибка сети — возвращает [], не падает."""
        with patch("httpx.get", side_effect=Exception("connection refused")):
            posts = fetch_channel_posts("some_channel")

        assert posts == []

    def test_empty_page_returns_empty_list(self):
        """Страница без постов — возвращает пустой список."""
        resp = _make_response(200, text="<html><body>No posts here</body></html>")

        with patch("httpx.get", return_value=resp):
            posts = fetch_channel_posts("empty_channel")

        assert posts == []

    def test_timeout_returns_empty(self):
        """Таймаут httpx — возвращает [], не падает."""
        with patch("httpx.get", side_effect=httpx.TimeoutException("timeout")):
            posts = fetch_channel_posts("slow_channel")

        assert posts == []

    def test_non_200_status_returns_empty(self):
        """HTTP 404/403 — возвращает []."""
        resp = _make_response(404)

        with patch("httpx.get", return_value=resp):
            posts = fetch_channel_posts("private_channel")

        assert posts == []

    def test_limit_respected(self):
        """Количество возвращаемых постов не превышает limit."""
        # Создаём страницу с 5 постами
        many_posts = _SAMPLE_POST_HTML * 5
        resp = _make_response(200, text=many_posts)

        with patch("httpx.get", return_value=resp):
            posts = fetch_channel_posts("big_channel", limit=2)

        assert len(posts) <= 2


# ──────────────────────────────────────────────
# Тесты scan_channel
# ──────────────────────────────────────────────

class TestScanChannel:
    """Тесты сканирования одного канала."""

    def _post_page(self, text_content: str, channel: str = "testchannel", post_id: int = 100) -> str:
        """Генерирует HTML-страницу с одним постом."""
        return f"""
        <div class="tgme_widget_message_wrap js-widget_message_wrap">
          <div class="tgme_widget_message">
            <div class="tgme_widget_message_text js-message_text">
              {text_content}
            </div>
            <div class="tgme_widget_message_footer">
              <a href="https://t.me/{channel}/{post_id}">
                <time datetime="2024-05-01T12:00:00+00:00">May 1</time>
              </a>
            </div>
          </div>
        </div>
        """

    def test_domain_match_sends_event(self):
        """Прямое совпадение домена — событие отправлено."""
        html_body = self._post_page("credentials from example.com database exposed")
        fetch_resp = _make_response(200, text=html_body)

        with patch("httpx.get", return_value=fetch_resp), \
             patch("httpx.post", return_value=_ingest_ok()):
            result = scan_channel("testchannel", "example.com", "http://localhost:8000", "secret")

        assert result["matched"] >= 1
        assert result["sent"] >= 1
        assert result["channel"] == "testchannel"

    def test_email_match_detected(self):
        """Совпадение по email-паттерну."""
        html_body = self._post_page("leaked: admin@example.com password:qwerty123")
        fetch_resp = _make_response(200, text=html_body)

        # Захватываем payload для проверки match_type
        posted_events: list[dict] = []
        def _capture_post(url, json=None, headers=None, timeout=None):
            posted_events.append(json or {})
            return _ingest_ok()

        with patch("httpx.get", return_value=fetch_resp), \
             patch("httpx.post", side_effect=_capture_post):
            result = scan_channel("testchannel", "example.com", "http://localhost:8000", "secret")

        assert result["matched"] >= 1
        assert any(e.get("payload", {}).get("match_type") == "email" for e in posted_events)

    def test_url_match_detected(self):
        """Совпадение по URL-паттерну."""
        html_body = self._post_page("database at https://example.com/users is leaked")
        fetch_resp = _make_response(200, text=html_body)

        posted_events: list[dict] = []
        def _capture_post(url, json=None, headers=None, timeout=None):
            posted_events.append(json or {})
            return _ingest_ok()

        with patch("httpx.get", return_value=fetch_resp), \
             patch("httpx.post", side_effect=_capture_post):
            result = scan_channel("testchannel", "example.com", "http://localhost:8000", "secret")

        assert result["matched"] >= 1
        assert any(e.get("payload", {}).get("match_type") == "url" for e in posted_events)

    def test_no_match_returns_zero(self):
        """Пост без упоминания домена — matched=0, sent=0."""
        html_body = self._post_page("breach at google.com and facebook.com found")
        fetch_resp = _make_response(200, text=html_body)

        with patch("httpx.get", return_value=fetch_resp), \
             patch("httpx.post") as mock_post:
            result = scan_channel("testchannel", "example.com", "http://localhost:8000", "secret")

        assert result["matched"] == 0
        assert result["sent"] == 0
        mock_post.assert_not_called()

    def test_duplicate_response_counts_as_sent(self):
        """Ответ 'duplicate' от Core API считается успешной доставкой (sent=1)."""
        html_body = self._post_page("example.com leak posted again")
        fetch_resp = _make_response(200, text=html_body)

        with patch("httpx.get", return_value=fetch_resp), \
             patch("httpx.post", return_value=_ingest_dup()):
            result = scan_channel("testchannel", "example.com", "http://localhost:8000", "secret")

        assert result["sent"] >= 1

    def test_ingest_error_matched_but_not_sent(self):
        """Ошибка ingest — matched увеличивается, sent остаётся 0, не падает."""
        html_body = self._post_page("example.com passwords found online")
        fetch_resp = _make_response(200, text=html_body)

        with patch("httpx.get", return_value=fetch_resp), \
             patch("httpx.post", side_effect=Exception("core api down")):
            result = scan_channel("testchannel", "example.com", "http://localhost:8000", "secret")

        assert result["matched"] >= 1
        assert result["sent"] == 0

    def test_event_payload_structure(self):
        """Проверяем структуру payload отправляемого события."""
        html_body = self._post_page("example.com data breach occurred", channel="testchannel", post_id=42)
        fetch_resp = _make_response(200, text=html_body)

        posted_events: list[dict] = []
        def _capture_post(url, json=None, headers=None, timeout=None):
            posted_events.append(json or {})
            return _ingest_ok()

        with patch("httpx.get", return_value=fetch_resp), \
             patch("httpx.post", side_effect=_capture_post):
            scan_channel("testchannel", "example.com", "http://localhost:8000", "secret")

        assert len(posted_events) >= 1
        event = posted_events[0]
        assert event["event_type"] == "telegram_leak"
        assert event["severity"] == "high"
        assert event["source_type"] == "telegram_monitor"
        assert event["target_domain"] == "example.com"
        payload = event["payload"]
        assert "channel" in payload
        assert payload["channel"] == "@testchannel"
        assert "snippet" in payload
        assert "match_type" in payload
        assert "post_date" in payload


# ──────────────────────────────────────────────
# Тесты monitor_telegram_channels
# ──────────────────────────────────────────────

class TestMonitorTelegramChannels:
    """Тесты агрегирующей функции мониторинга всех каналов."""

    def _mock_scan(self, channel, domain, core_api_url, internal_secret):
        """Возвращает успешный результат с 5 проверенными и 1 совпадением."""
        return {
            "channel": channel,
            "posts_checked": 5,
            "matched": 1,
            "sent": 1,
        }

    def test_aggregates_results_across_channels(self):
        """monitor_telegram_channels суммирует результаты всех каналов."""
        num_channels = len(DEFAULT_LEAK_CHANNELS)

        with patch("tasks.telegram_monitor.scan_channel", side_effect=self._mock_scan), \
             patch("time.sleep"):
            result = monitor_telegram_channels(
                "example.com",
                "http://localhost:8000",
                "secret",
            )

        assert result["channels_checked"] == num_channels
        assert result["total_posts"] == num_channels * 5
        assert result["matched"] == num_channels
        assert result["sent"] == num_channels
        assert result["errors"] == 0

    def test_extra_channels_added_and_deduplicated(self):
        """extra_channels добавляются в список; дублирующиеся каналы пропускаются."""
        # Дублируем первый дефолтный канал + добавляем новый
        first_default = DEFAULT_LEAK_CHANNELS[0]
        extra = [first_default, "mychannel"]  # first_default — дубликат

        called_channels: list[str] = []

        def _mock_scan_capture(channel, domain, core_api_url, internal_secret):
            called_channels.append(channel)
            return {"channel": channel, "posts_checked": 3, "matched": 0, "sent": 0}

        with patch("tasks.telegram_monitor.scan_channel", side_effect=_mock_scan_capture), \
             patch("time.sleep"):
            result = monitor_telegram_channels(
                "example.com",
                "http://localhost:8000",
                "secret",
                extra_channels=extra,
            )

        # Дубликат первого дефолтного канала должен быть отфильтрован
        assert called_channels.count(first_default) == 1
        # Новый канал должен быть добавлен
        assert "mychannel" in called_channels
        # Всего = DEFAULT + 1 новый (без дубликата)
        expected_count = len(DEFAULT_LEAK_CHANNELS) + 1
        assert result["channels_checked"] == expected_count

    def test_one_channel_error_others_continue(self):
        """Если один канал падает с исключением, остальные продолжают работу."""
        fail_channel = DEFAULT_LEAK_CHANNELS[0]

        def _mock_scan_with_failure(channel, domain, core_api_url, internal_secret):
            if channel == fail_channel:
                raise RuntimeError("channel unavailable")
            return {"channel": channel, "posts_checked": 2, "matched": 0, "sent": 0}

        with patch("tasks.telegram_monitor.scan_channel", side_effect=_mock_scan_with_failure), \
             patch("time.sleep"):
            result = monitor_telegram_channels(
                "example.com",
                "http://localhost:8000",
                "secret",
            )

        # Один канал упал — errors=1, остальные прошли
        assert result["errors"] == 1
        assert result["channels_checked"] == len(DEFAULT_LEAK_CHANNELS) - 1

    def test_domain_normalized_before_scan(self):
        """Домен нормализуется (strip + lower) до передачи в scan_channel."""
        called_domains: list[str] = []

        def _mock_scan_capture(channel, domain, core_api_url, internal_secret):
            called_domains.append(domain)
            return {"channel": channel, "posts_checked": 0, "matched": 0, "sent": 0}

        with patch("tasks.telegram_monitor.scan_channel", side_effect=_mock_scan_capture), \
             patch("time.sleep"):
            monitor_telegram_channels(
                "  EXAMPLE.COM  ",
                "http://localhost:8000",
                "secret",
            )

        # Все вызовы должны получить нормализованный домен
        assert all(d == "example.com" for d in called_domains)

    def test_rate_limit_sleep_between_channels(self):
        """Между каналами должна быть пауза time.sleep (rate limiting)."""
        with patch("tasks.telegram_monitor.scan_channel", side_effect=self._mock_scan), \
             patch("time.sleep") as mock_sleep:
            monitor_telegram_channels(
                "example.com",
                "http://localhost:8000",
                "secret",
            )

        # Пауза вызывается между каналами: N-1 раз для N каналов
        expected_sleeps = len(DEFAULT_LEAK_CHANNELS) - 1
        assert mock_sleep.call_count == expected_sleeps

    def test_empty_extra_channels_ignored(self):
        """Пустой список extra_channels не влияет на количество каналов."""
        with patch("tasks.telegram_monitor.scan_channel", side_effect=self._mock_scan), \
             patch("time.sleep"):
            result_without = monitor_telegram_channels(
                "example.com", "http://localhost:8000", "secret"
            )
            result_with_empty = monitor_telegram_channels(
                "example.com", "http://localhost:8000", "secret", extra_channels=[]
            )

        assert result_without["channels_checked"] == result_with_empty["channels_checked"]

    def test_at_prefix_stripped_from_extra_channels(self):
        """@ в начале названия канала в extra_channels убирается при дедупликации."""
        called_channels: list[str] = []

        def _mock_scan_capture(channel, domain, core_api_url, internal_secret):
            called_channels.append(channel)
            return {"channel": channel, "posts_checked": 0, "matched": 0, "sent": 0}

        with patch("tasks.telegram_monitor.scan_channel", side_effect=_mock_scan_capture), \
             patch("time.sleep"):
            monitor_telegram_channels(
                "example.com",
                "http://localhost:8000",
                "secret",
                extra_channels=["@newchannel"],
            )

        # Канал должен быть добавлен без @
        assert "newchannel" in called_channels
        assert "@newchannel" not in called_channels


# ──────────────────────────────────────────────
# Тесты _send_ingest_event
# ──────────────────────────────────────────────

class TestSendIngestEvent:
    """Тесты утилиты отправки событий в Core API."""

    def test_accepted_returns_true(self):
        with patch("httpx.post", return_value=_ingest_ok()):
            ok = _send_ingest_event("http://localhost/ingest", {}, {"event_type": "telegram_leak"})
        assert ok is True

    def test_duplicate_returns_true(self):
        with patch("httpx.post", return_value=_ingest_dup()):
            ok = _send_ingest_event("http://localhost/ingest", {}, {"event_type": "telegram_leak"})
        assert ok is True

    def test_network_error_returns_false(self):
        with patch("httpx.post", side_effect=Exception("network down")):
            ok = _send_ingest_event("http://localhost/ingest", {}, {"event_type": "telegram_leak"})
        assert ok is False

    def test_error_status_returns_false(self):
        resp = _make_response(500, json_body={"status": "error"})
        with patch("httpx.post", return_value=resp):
            ok = _send_ingest_event("http://localhost/ingest", {}, {"event_type": "telegram_leak"})
        assert ok is False
