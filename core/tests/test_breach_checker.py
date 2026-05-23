"""
Тесты воркера проверки email по базам утечек.

Все внешние HTTP-запросы мокируются через unittest.mock.patch.
sys.path для workers добавляется в conftest.py.
"""
import json
from unittest.mock import MagicMock, call, patch

import pytest

# conftest.py добавляет workers/ в sys.path
from tasks.breach_checker import (
    COMMON_EMAIL_PREFIXES,
    HIBP_RATE_LIMIT_SECONDS,
    _build_hibp_headers,
    _extract_emails_from_payload,
    _is_valid_email,
    check_domain_emails,
    check_email_hibp,
    check_email_leakcheck,
    discover_and_check,
)


# ── Вспомогательные функции ────────────────────────────────────────────────

def _make_response(status_code: int, body: object) -> MagicMock:
    """Создаёт фиктивный httpx.Response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = body
    return resp


def _make_ingest_ok() -> MagicMock:
    """POST /ingest → accepted."""
    return _make_response(202, {"status": "accepted"})


def _make_ingest_dup() -> MagicMock:
    """POST /ingest → duplicate."""
    return _make_response(202, {"status": "duplicate"})


# ── check_email_hibp ──────────────────────────────────────────────────────

class TestCheckEmailHibp:

    def test_email_found_returns_breached_true(self):
        """HIBP возвращает список утечек → breached=True."""
        breaches = [
            {"Name": "Adobe", "Domain": "adobe.com"},
            {"Name": "LinkedIn", "Domain": "linkedin.com"},
        ]
        with patch("httpx.get", return_value=_make_response(200, breaches)):
            result = check_email_hibp("user@example.com", api_key="test-key")

        assert result["breached"] is True
        assert result["email"] == "user@example.com"
        assert "Adobe" in result["breaches"]
        assert "LinkedIn" in result["breaches"]
        assert result["error"] is None

    def test_email_not_found_returns_breached_false(self):
        """HIBP 404 → email чист."""
        with patch("httpx.get", return_value=_make_response(404, {})):
            result = check_email_hibp("clean@example.com", api_key="test-key")

        assert result["breached"] is False
        assert result["breaches"] == []
        assert result["error"] is None

    def test_no_api_key_returns_unauthorized(self):
        """Без ключа HIBP возвращает 401 → graceful degradation."""
        with patch("httpx.get", return_value=_make_response(401, {})):
            result = check_email_hibp("user@example.com", api_key="")

        assert result["breached"] is False
        assert result["error"] == "unauthorized"
        assert result["breaches"] == []

    def test_rate_limit_returns_rate_limit_error(self):
        """429 от HIBP → error='rate_limit'."""
        with patch("httpx.get", return_value=_make_response(429, {})):
            result = check_email_hibp("user@example.com", api_key="key")

        assert result["breached"] is False
        assert result["error"] == "rate_limit"

    def test_network_error_returns_gracefully(self):
        """Сетевая ошибка не должна бросать исключение."""
        with patch("httpx.get", side_effect=ConnectionError("connection refused")):
            result = check_email_hibp("user@example.com", api_key="key")

        assert result["breached"] is False
        assert result["error"] == "network_error"
        assert result["breaches"] == []

    def test_empty_breach_list_returns_not_breached(self):
        """HIBP возвращает пустой список → breached=False."""
        with patch("httpx.get", return_value=_make_response(200, [])):
            result = check_email_hibp("user@example.com", api_key="key")

        assert result["breached"] is False
        assert result["breaches"] == []

    def test_hibp_headers_include_api_key(self):
        """При наличии ключа заголовок hibp-api-key присутствует."""
        headers = _build_hibp_headers("my-secret-key")
        assert headers["hibp-api-key"] == "my-secret-key"
        assert headers["User-Agent"] == "EASM-Platform/1.0"

    def test_hibp_headers_without_key(self):
        """Без ключа заголовок hibp-api-key отсутствует."""
        headers = _build_hibp_headers("")
        assert "hibp-api-key" not in headers
        assert "User-Agent" in headers

    def test_unexpected_http_status(self):
        """Неизвестный HTTP статус — возвращаем error с кодом."""
        with patch("httpx.get", return_value=_make_response(503, {})):
            result = check_email_hibp("user@example.com", api_key="key")

        assert result["breached"] is False
        assert result["error"] == "http_503"


# ── check_email_leakcheck ─────────────────────────────────────────────────

class TestCheckEmailLeakcheck:

    def test_email_found_returns_found_count(self):
        """LeakCheck возвращает found > 0 → корректный словарь."""
        body = {"success": True, "found": 3, "sources": ["Source1", "Source2", "Source3"]}
        with patch("httpx.get", return_value=_make_response(200, body)):
            result = check_email_leakcheck("user@example.com")

        assert result["found"] == 3
        assert result["email"] == "user@example.com"
        assert len(result["sources"]) == 3
        assert result["error"] is None

    def test_email_not_found_returns_zero(self):
        """LeakCheck found=0 → чисто."""
        body = {"success": True, "found": 0, "sources": []}
        with patch("httpx.get", return_value=_make_response(200, body)):
            result = check_email_leakcheck("clean@example.com")

        assert result["found"] == 0
        assert result["sources"] == []
        assert result["error"] is None

    def test_network_error_handled_gracefully(self):
        """Сетевая ошибка LeakCheck не бросает исключение."""
        with patch("httpx.get", side_effect=TimeoutError("timeout")):
            result = check_email_leakcheck("user@example.com")

        assert result["found"] == 0
        assert result["error"] == "network_error"

    def test_api_error_success_false(self):
        """LeakCheck success=False → error в ответе."""
        body = {"success": False, "error": "Too many requests"}
        with patch("httpx.get", return_value=_make_response(200, body)):
            result = check_email_leakcheck("user@example.com")

        assert result["found"] == 0
        assert result["error"] == "Too many requests"

    def test_http_non_200_handled(self):
        """HTTP 500 от LeakCheck → error с кодом."""
        with patch("httpx.get", return_value=_make_response(500, {})):
            result = check_email_leakcheck("user@example.com")

        assert result["found"] == 0
        assert result["error"] == "http_500"


# ── check_domain_emails ───────────────────────────────────────────────────

class TestCheckDomainEmails:

    def test_breach_detected_sends_ingest_event(self):
        """При нахождении утечки через HIBP событие отправляется в Core API."""
        hibp_resp = {"email": "user@example.com", "breached": True, "breaches": ["Adobe"], "error": None}
        lc_resp = {"email": "user@example.com", "found": 0, "sources": [], "error": None}

        with patch("tasks.breach_checker.check_email_hibp", return_value=hibp_resp), \
             patch("tasks.breach_checker.check_email_leakcheck", return_value=lc_resp), \
             patch("httpx.post", return_value=_make_ingest_ok()), \
             patch("time.sleep"):
            result = check_domain_emails(
                domain="example.com",
                emails=["user@example.com"],
                core_api_url="http://localhost:8000",
                internal_secret="secret",
            )

        assert result["checked"] == 1
        assert result["breached"] == 1
        assert result["sent"] == 1
        assert result["errors"] == 0

    def test_no_breach_no_event_sent(self):
        """Если утечек нет — никаких событий."""
        hibp_resp = {"email": "clean@example.com", "breached": False, "breaches": [], "error": None}
        lc_resp = {"email": "clean@example.com", "found": 0, "sources": [], "error": None}

        with patch("tasks.breach_checker.check_email_hibp", return_value=hibp_resp), \
             patch("tasks.breach_checker.check_email_leakcheck", return_value=lc_resp), \
             patch("httpx.post") as mock_post, \
             patch("time.sleep"):
            result = check_domain_emails(
                domain="example.com",
                emails=["clean@example.com"],
                core_api_url="http://localhost:8000",
                internal_secret="secret",
            )

        mock_post.assert_not_called()
        assert result["sent"] == 0
        assert result["breached"] == 0

    def test_leakcheck_breach_also_sends_event(self):
        """Утечка только в LeakCheck — событие тоже отправляется."""
        hibp_resp = {"email": "user@example.com", "breached": False, "breaches": [], "error": "unauthorized"}
        lc_resp = {"email": "user@example.com", "found": 2, "sources": ["LeakSource"], "error": None}

        with patch("tasks.breach_checker.check_email_hibp", return_value=hibp_resp), \
             patch("tasks.breach_checker.check_email_leakcheck", return_value=lc_resp), \
             patch("httpx.post", return_value=_make_ingest_ok()), \
             patch("time.sleep"):
            result = check_domain_emails(
                domain="example.com",
                emails=["user@example.com"],
                core_api_url="http://localhost:8000",
                internal_secret="secret",
            )

        assert result["breached"] == 1
        assert result["sent"] == 1

    def test_empty_email_list_returns_zeros(self):
        """Пустой список → нулевая статистика без HTTP-запросов."""
        with patch("httpx.get") as mock_get, patch("httpx.post") as mock_post:
            result = check_domain_emails(
                domain="example.com",
                emails=[],
                core_api_url="http://localhost:8000",
                internal_secret="secret",
            )

        assert result == {"checked": 0, "breached": 0, "sent": 0, "errors": 0}
        mock_get.assert_not_called()
        mock_post.assert_not_called()

    def test_duplicate_emails_deduplicated(self):
        """Одинаковые email в списке проверяются только один раз."""
        hibp_resp = {"email": "user@example.com", "breached": False, "breaches": [], "error": None}
        lc_resp = {"email": "user@example.com", "found": 0, "sources": [], "error": None}

        with patch("tasks.breach_checker.check_email_hibp", return_value=hibp_resp) as mock_hibp, \
             patch("tasks.breach_checker.check_email_leakcheck", return_value=lc_resp), \
             patch("time.sleep"):
            result = check_domain_emails(
                domain="example.com",
                emails=["user@example.com", "USER@EXAMPLE.COM", "user@example.com"],
                core_api_url="http://localhost:8000",
                internal_secret="secret",
            )

        # Только один уникальный email
        assert mock_hibp.call_count == 1
        assert result["checked"] == 1

    def test_ingest_error_counted_in_errors(self):
        """Ошибка при отправке в ingest → счётчик errors увеличивается."""
        hibp_resp = {"email": "user@example.com", "breached": True, "breaches": ["Adobe"], "error": None}
        lc_resp = {"email": "user@example.com", "found": 0, "sources": [], "error": None}

        with patch("tasks.breach_checker.check_email_hibp", return_value=hibp_resp), \
             patch("tasks.breach_checker.check_email_leakcheck", return_value=lc_resp), \
             patch("httpx.post", side_effect=ConnectionError("network error")), \
             patch("time.sleep"):
            result = check_domain_emails(
                domain="example.com",
                emails=["user@example.com"],
                core_api_url="http://localhost:8000",
                internal_secret="secret",
            )

        assert result["errors"] >= 1
        assert result["sent"] == 0

    def test_rate_limit_triggers_retry(self):
        """При 429 от HIBP воркер делает паузу и повторный запрос."""
        rate_limit_resp = {"email": "user@example.com", "breached": False, "breaches": [], "error": "rate_limit"}
        clean_resp = {"email": "user@example.com", "breached": False, "breaches": [], "error": None}
        lc_resp = {"email": "user@example.com", "found": 0, "sources": [], "error": None}

        # Первый вызов — rate_limit, второй — чисто
        hibp_side_effects = [rate_limit_resp, clean_resp]

        with patch("tasks.breach_checker.check_email_hibp", side_effect=hibp_side_effects), \
             patch("tasks.breach_checker.check_email_leakcheck", return_value=lc_resp), \
             patch("time.sleep") as mock_sleep:
            result = check_domain_emails(
                domain="example.com",
                emails=["user@example.com"],
                core_api_url="http://localhost:8000",
                internal_secret="secret",
            )

        # sleep должен был вызываться (rate limit + retry)
        assert mock_sleep.call_count >= 2
        assert result["checked"] == 1


# ── discover_and_check ────────────────────────────────────────────────────

class TestDiscoverAndCheck:

    def test_generates_pattern_emails(self):
        """discover_and_check создаёт типичные email-паттерны для домена."""
        hibp_resp = {"email": "x", "breached": False, "breaches": [], "error": None}
        lc_resp = {"email": "x", "found": 0, "sources": [], "error": None}

        checked_emails: list[str] = []

        def fake_check(email, api_key=""):
            checked_emails.append(email)
            return {**hibp_resp, "email": email}

        with patch("tasks.breach_checker.check_email_hibp", side_effect=fake_check), \
             patch("tasks.breach_checker.check_email_leakcheck", return_value=lc_resp), \
             patch("tasks.breach_checker._collect_emails_from_core", return_value=[]), \
             patch("time.sleep"):
            result = discover_and_check(
                domain="example.com",
                core_api_url="http://localhost:8000",
                internal_secret="secret",
            )

        # Должны быть проверены все паттерны
        assert result["emails_discovered"] >= len(COMMON_EMAIL_PREFIXES)
        for prefix in COMMON_EMAIL_PREFIXES:
            assert any(f"{prefix}@example.com" in e for e in checked_emails)

    def test_merges_logs_and_patterns(self):
        """Адреса из stealer-логов добавляются к паттернам без дублей."""
        hibp_resp = {"email": "x", "breached": False, "breaches": [], "error": None}
        lc_resp = {"email": "x", "found": 0, "sources": [], "error": None}

        stealer_emails = ["leaked@example.com", "another@example.com"]

        with patch("tasks.breach_checker.check_email_hibp", return_value=hibp_resp), \
             patch("tasks.breach_checker.check_email_leakcheck", return_value=lc_resp), \
             patch("tasks.breach_checker._collect_emails_from_core", return_value=stealer_emails), \
             patch("time.sleep"):
            result = discover_and_check(
                domain="example.com",
                core_api_url="http://localhost:8000",
                internal_secret="secret",
            )

        # Общее число = паттерны + stealer - дубли
        assert result["emails_discovered"] >= len(COMMON_EMAIL_PREFIXES) + len(stealer_emails)

    def test_returns_emails_discovered_field(self):
        """Результат содержит поле emails_discovered."""
        hibp_resp = {"email": "x", "breached": False, "breaches": [], "error": None}
        lc_resp = {"email": "x", "found": 0, "sources": [], "error": None}

        with patch("tasks.breach_checker.check_email_hibp", return_value=hibp_resp), \
             patch("tasks.breach_checker.check_email_leakcheck", return_value=lc_resp), \
             patch("tasks.breach_checker._collect_emails_from_core", return_value=[]), \
             patch("time.sleep"):
            result = discover_and_check(
                domain="example.com",
                core_api_url="http://localhost:8000",
                internal_secret="secret",
            )

        assert "emails_discovered" in result
        assert isinstance(result["emails_discovered"], int)


# ── Утилиты ───────────────────────────────────────────────────────────────

class TestUtilities:

    def test_is_valid_email_valid_cases(self):
        """Корректные email-адреса проходят валидацию."""
        valid = ["user@example.com", "admin@sub.domain.org", "test+tag@company.io"]
        for e in valid:
            assert _is_valid_email(e), f"Должен быть валидным: {e}"

    def test_is_valid_email_invalid_cases(self):
        """Некорректные строки не проходят валидацию."""
        invalid = ["notanemail", "@nodomain.com", "noatsign", "user@", ""]
        for e in invalid:
            assert not _is_valid_email(e), f"Не должен быть валидным: {e}"

    def test_extract_emails_from_nested_payload(self):
        """_extract_emails_from_payload находит email в глубоко вложенных структурах."""
        payload = {
            "url": "https://example.com",
            "credentials": [
                {"login": "user@example.com", "password": "x"},
                {"login": "other@google.com", "password": "y"},
                {"login": "admin@example.com", "notes": {"contact": "contact@example.com"}},
            ],
        }
        emails = _extract_emails_from_payload(payload, "example.com")
        assert "user@example.com" in emails
        assert "admin@example.com" in emails
        assert "contact@example.com" in emails
        # Email чужого домена не должен попасть
        assert "other@google.com" not in emails

    def test_extract_emails_deduplication_not_required_from_extract(self):
        """Функция может вернуть дубли — дедупликация на уровне check_domain_emails."""
        payload = {
            "field1": "user@example.com",
            "field2": "user@example.com",
        }
        emails = _extract_emails_from_payload(payload, "example.com")
        # Хотя бы один instance должен быть найден
        assert "user@example.com" in emails

    def test_hibp_rate_limit_constant_value(self):
        """Rate limit константа не должна быть меньше требуемого HIBP значения."""
        assert HIBP_RATE_LIMIT_SECONDS >= 1.5
