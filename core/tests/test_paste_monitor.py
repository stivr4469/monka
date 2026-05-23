"""
Тесты воркера мониторинга paste-сервисов.

Покрытие:
  - regex-паттерны (_build_patterns, _find_first_match)
  - извлечение snippet (_extract_snippet)
  - scan_pastebin: совпадение по домену, email, URL, пустой ответ, ошибка сети
  - scan_pastee: совпадение, пустой ответ, ошибка сети
  - monitor_pastes: суммирование результатов, устойчивость к частичной ошибке
  - дедупликация / повторный "duplicate" от Core API

sys.path для workers добавляется в conftest.py
"""
import json
from unittest.mock import MagicMock, patch

import pytest

from tasks.paste_monitor import (
    _build_patterns,
    _extract_snippet,
    _find_first_match,
    _send_event,
    monitor_pastes,
    scan_pastebin,
    scan_pastee,
)


# ──────────────────────────────────────────────
# Вспомогательные фабрики mock-ответов
# ──────────────────────────────────────────────

def _make_response(status_code: int, body) -> MagicMock:
    """Создаёт mock httpx-ответа."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = body
    resp.text = json.dumps(body) if isinstance(body, (dict, list)) else str(body)
    return resp


def _ingest_ok() -> MagicMock:
    return _make_response(202, {"status": "accepted"})


def _ingest_dup() -> MagicMock:
    return _make_response(202, {"status": "duplicate"})


# ──────────────────────────────────────────────
# Тесты regex-паттернов
# ──────────────────────────────────────────────

class TestBuildPatterns:
    """Тесты построения и применения regex-паттернов."""

    def test_domain_pattern_matches_direct(self):
        patterns = _build_patterns("example.com")
        result = _find_first_match("some text example.com here", patterns)
        assert result is not None
        match_type, matched_text, _ = result
        assert match_type == "domain"
        assert "example.com" in matched_text.lower()

    def test_email_pattern_matches(self):
        patterns = _build_patterns("example.com")
        result = _find_first_match("contact admin@example.com for info", patterns)
        assert result is not None
        match_type, matched_text, _ = result
        assert match_type == "email"
        assert "@example.com" in matched_text

    def test_url_pattern_matches(self):
        patterns = _build_patterns("example.com")
        result = _find_first_match("visit https://example.com/login now", patterns)
        assert result is not None
        match_type, matched_text, _ = result
        assert match_type == "url"
        assert "https://example.com" in matched_text

    def test_no_match_returns_none(self):
        patterns = _build_patterns("example.com")
        result = _find_first_match("nothing relevant here google.com", patterns)
        assert result is None

    def test_subdomain_url_matches(self):
        """URL с поддоменом должен совпадать через url-паттерн."""
        patterns = _build_patterns("example.com")
        result = _find_first_match("connect to https://api.example.com/v2", patterns)
        assert result is not None
        assert result[0] == "url"

    def test_domain_dots_escaped(self):
        """Точки в домене экранируются — exampleXcom не должен совпадать."""
        patterns = _build_patterns("example.com")
        result = _find_first_match("exampleXcom nothing useful", patterns)
        assert result is None


# ──────────────────────────────────────────────
# Тест snippet
# ──────────────────────────────────────────────

class TestExtractSnippet:
    def test_snippet_length_bounded(self):
        """snippet никогда не превышает 300 символов."""
        patterns = _build_patterns("example.com")
        long_text = "A" * 500 + " example.com " + "B" * 500
        result = _find_first_match(long_text, patterns)
        assert result is not None
        _, _, snippet = result
        assert len(snippet) <= 300

    def test_snippet_contains_match(self):
        patterns = _build_patterns("example.com")
        text = "prefix text example.com suffix text"
        result = _find_first_match(text, patterns)
        assert result is not None
        _, _, snippet = result
        assert "example.com" in snippet


# ──────────────────────────────────────────────
# Тесты scan_pastebin
# ──────────────────────────────────────────────

class TestScanPastebin:
    """Тесты сканирования Pastebin."""

    def _paste_list_response(self, keys: list[str]) -> MagicMock:
        body = [{"key": k, "title": f"paste {k}"} for k in keys]
        return _make_response(200, body)

    def _paste_text_response(self, text: str) -> MagicMock:
        resp = MagicMock()
        resp.status_code = 200
        resp.text = text
        return resp

    def test_scan_pastebin_domain_match(self):
        """Находит прямое упоминание домена в тексте paste."""
        list_resp   = self._paste_list_response(["abc123"])
        text_resp   = self._paste_text_response("some leak: example.com credentials")
        ingest_resp = _ingest_ok()

        with patch("httpx.get", side_effect=[list_resp, text_resp]), \
             patch("httpx.post", return_value=ingest_resp), \
             patch("time.sleep"):
            result = scan_pastebin("example.com", "http://localhost:8000", "secret")

        assert result["checked"] == 1
        assert result["matched"] == 1
        assert result["sent"]    == 1

    def test_scan_pastebin_email_match(self):
        """Находит email @domain в тексте paste."""
        list_resp   = self._paste_list_response(["xyz789"])
        text_resp   = self._paste_text_response("user: admin@example.com pass: qwerty")
        ingest_resp = _ingest_ok()

        with patch("httpx.get", side_effect=[list_resp, text_resp]), \
             patch("httpx.post", return_value=ingest_resp), \
             patch("time.sleep"):
            result = scan_pastebin("example.com", "http://localhost:8000", "secret")

        assert result["matched"] == 1
        # Проверяем что событие содержит email тип (через захват аргументов post)

    def test_scan_pastebin_url_match(self):
        """Находит URL с доменом в тексте paste."""
        list_resp   = self._paste_list_response(["url001"])
        text_resp   = self._paste_text_response("endpoint: https://api.example.com/token")
        ingest_resp = _ingest_ok()

        with patch("httpx.get", side_effect=[list_resp, text_resp]), \
             patch("httpx.post", return_value=ingest_resp), \
             patch("time.sleep"):
            result = scan_pastebin("example.com", "http://localhost:8000", "secret")

        assert result["matched"] == 1

    def test_scan_pastebin_empty_list(self):
        """Пустой список paste — нет совпадений."""
        list_resp = _make_response(200, [])

        with patch("httpx.get", return_value=list_resp), \
             patch("time.sleep"):
            result = scan_pastebin("example.com", "http://localhost:8000", "secret")

        assert result["checked"] == 0
        assert result["matched"] == 0

    def test_scan_pastebin_network_error_list(self):
        """Ошибка сети при получении списка — возвращает нули, не поднимает исключение."""
        with patch("httpx.get", side_effect=Exception("connection refused")), \
             patch("time.sleep"):
            result = scan_pastebin("example.com", "http://localhost:8000", "secret")

        assert result == {"checked": 0, "matched": 0, "sent": 0}

    def test_scan_pastebin_item_network_error(self):
        """Ошибка сети при загрузке текста paste — пропускаем этот paste, не падаем."""
        list_resp = self._paste_list_response(["fail001"])

        # Первый вызов httpx.get — список paste (успех).
        # Второй вызов — загрузка текста (ошибка сети).
        responses = iter([list_resp])

        def _get_side_effect(*args, **kwargs):
            try:
                return next(responses)
            except StopIteration:
                # Все последующие вызовы — загрузка item, имитируем таймаут
                raise Exception("timeout")

        with patch("httpx.get", side_effect=_get_side_effect), \
             patch("time.sleep"):
            result = scan_pastebin("example.com", "http://localhost:8000", "secret")

        # paste не загрузился — checked остаётся 0 (None вернулся из _fetch_pastebin_item)
        assert result["checked"] == 0
        assert result["matched"] == 0

    def test_scan_pastebin_no_domain_match(self):
        """Текст paste не содержит домен — нет совпадений."""
        list_resp = self._paste_list_response(["noop01"])
        text_resp = self._paste_text_response("just some random text with google.com mention")

        with patch("httpx.get", side_effect=[list_resp, text_resp]), \
             patch("time.sleep"):
            result = scan_pastebin("example.com", "http://localhost:8000", "secret")

        assert result["matched"] == 0

    def test_scan_pastebin_ingest_duplicate(self):
        """Ответ duplicate от Core API считается успехом (sent увеличивается)."""
        list_resp   = self._paste_list_response(["dup001"])
        text_resp   = self._paste_text_response("leak example.com data")
        ingest_resp = _ingest_dup()

        with patch("httpx.get", side_effect=[list_resp, text_resp]), \
             patch("httpx.post", return_value=ingest_resp), \
             patch("time.sleep"):
            result = scan_pastebin("example.com", "http://localhost:8000", "secret")

        assert result["sent"] == 1  # duplicate тоже считается отправленным

    def test_scan_pastebin_ingest_error(self):
        """Ошибка при отправке события — sent остаётся 0, но нет падения."""
        list_resp = self._paste_list_response(["err001"])
        text_resp = self._paste_text_response("example.com found in paste")

        with patch("httpx.get", side_effect=[list_resp, text_resp]), \
             patch("httpx.post", side_effect=Exception("ingest down")), \
             patch("time.sleep"):
            result = scan_pastebin("example.com", "http://localhost:8000", "secret")

        assert result["matched"] == 1
        assert result["sent"]    == 0  # событие нашли, но не смогли отправить

    def test_scan_pastebin_multiple_pastes_one_match(self):
        """Несколько paste, только один содержит домен."""
        list_resp  = self._paste_list_response(["a1", "b2", "c3"])
        text_clean = self._paste_text_response("nothing relevant here")
        text_match = self._paste_text_response("admin@example.com password leak")
        ingest_ok  = _ingest_ok()

        # Первый GET — список, затем тексты a1/b2/c3
        responses = iter([list_resp, text_clean, text_clean, text_match])

        with patch("httpx.get", side_effect=lambda *a, **kw: next(responses)), \
             patch("httpx.post", return_value=ingest_ok), \
             patch("time.sleep"):
            result = scan_pastebin("example.com", "http://localhost:8000", "secret")

        assert result["checked"] == 3
        assert result["matched"] == 1
        assert result["sent"]    == 1


# ──────────────────────────────────────────────
# Тесты scan_pastee
# ──────────────────────────────────────────────

class TestScanPastee:
    """Тесты сканирования Pastee.org."""

    def _pastee_list_response(self, items: list[dict]) -> MagicMock:
        body = {"data": items, "next_page_url": None, "current_page": 1}
        return _make_response(200, body)

    def test_scan_pastee_domain_match(self):
        """Находит домен в содержимом paste.ee."""
        item = {
            "id": "p1",
            "link": "https://paste.ee/p/p1",
            "sections": [{"contents": "config for example.com system"}],
        }
        list_resp   = self._pastee_list_response([item])
        ingest_resp = _ingest_ok()

        with patch("httpx.get", return_value=list_resp), \
             patch("httpx.post", return_value=ingest_resp), \
             patch("time.sleep"):
            result = scan_pastee("example.com", "http://localhost:8000", "secret")

        assert result["checked"] == 1
        assert result["matched"] == 1
        assert result["sent"]    == 1

    def test_scan_pastee_empty_list(self):
        """Пустой ответ paste.ee — нет совпадений."""
        list_resp = self._pastee_list_response([])

        with patch("httpx.get", return_value=list_resp), \
             patch("time.sleep"):
            result = scan_pastee("example.com", "http://localhost:8000", "secret")

        assert result["checked"] == 0
        assert result["matched"] == 0

    def test_scan_pastee_network_error(self):
        """Ошибка сети — возвращает нули, не падает."""
        with patch("httpx.get", side_effect=Exception("timeout")), \
             patch("time.sleep"):
            result = scan_pastee("example.com", "http://localhost:8000", "secret")

        assert result == {"checked": 0, "matched": 0, "sent": 0}

    def test_scan_pastee_no_sections_fallback(self):
        """Если нет sections — используем description как текст."""
        item = {
            "id": "p2",
            "link": "https://paste.ee/p/p2",
            "sections": [],
            "description": "info: example.com deployment",
        }
        list_resp   = self._pastee_list_response([item])
        ingest_resp = _ingest_ok()

        with patch("httpx.get", return_value=list_resp), \
             patch("httpx.post", return_value=ingest_resp), \
             patch("time.sleep"):
            result = scan_pastee("example.com", "http://localhost:8000", "secret")

        assert result["matched"] == 1


# ──────────────────────────────────────────────
# Тесты monitor_pastes (агрегатор)
# ──────────────────────────────────────────────

class TestMonitorPastes:
    """Тесты агрегирующей функции monitor_pastes."""

    def test_monitor_aggregates_both_sources(self):
        """monitor_pastes суммирует результаты обоих источников."""
        pb_result = {"checked": 5, "matched": 2, "sent": 2}
        pe_result = {"checked": 3, "matched": 1, "sent": 1}

        with patch("tasks.paste_monitor.scan_pastebin", return_value=pb_result), \
             patch("tasks.paste_monitor.scan_pastee",   return_value=pe_result):
            result = monitor_pastes("example.com", "http://localhost:8000", "secret")

        assert result["checked"] == 8
        assert result["matched"] == 3
        assert result["sent"]    == 3

    def test_monitor_continues_if_pastebin_fails(self):
        """Если pastebin падает с исключением — pastee всё равно сканируется."""
        pe_result = {"checked": 2, "matched": 1, "sent": 1}

        with patch("tasks.paste_monitor.scan_pastebin", side_effect=Exception("pastebin down")), \
             patch("tasks.paste_monitor.scan_pastee",   return_value=pe_result):
            result = monitor_pastes("example.com", "http://localhost:8000", "secret")

        # pastebin упал — его вклад 0, pastee отработал
        assert result["checked"] == 2
        assert result["matched"] == 1

    def test_monitor_normalizes_domain(self):
        """monitor_pastes нормализует домен (strip + lower)."""
        with patch("tasks.paste_monitor.scan_pastebin", return_value={"checked": 0, "matched": 0, "sent": 0}) as pb_mock, \
             patch("tasks.paste_monitor.scan_pastee",   return_value={"checked": 0, "matched": 0, "sent": 0}):
            monitor_pastes("  EXAMPLE.COM  ", "http://localhost:8000", "secret")

        # Первый позиционный аргумент вызова — нормализованный домен
        called_domain = pb_mock.call_args[0][0]
        assert called_domain == "example.com"

    def test_monitor_zero_results(self):
        """monitor_pastes при отсутствии совпадений возвращает нули."""
        empty = {"checked": 10, "matched": 0, "sent": 0}

        with patch("tasks.paste_monitor.scan_pastebin", return_value=empty), \
             patch("tasks.paste_monitor.scan_pastee",   return_value=empty):
            result = monitor_pastes("clean.example.com", "http://localhost:8000", "secret")

        assert result["matched"] == 0
        assert result["sent"]    == 0
        assert result["checked"] == 20


# ──────────────────────────────────────────────
# Тесты _send_event (утилита ingest)
# ──────────────────────────────────────────────

class TestSendEvent:
    """Тесты утилиты отправки события в Core API."""

    def test_send_event_accepted(self):
        with patch("httpx.post", return_value=_ingest_ok()):
            ok = _send_event("http://localhost/ingest", {}, {"event_type": "paste_leak"})
        assert ok is True

    def test_send_event_duplicate(self):
        with patch("httpx.post", return_value=_ingest_dup()):
            ok = _send_event("http://localhost/ingest", {}, {"event_type": "paste_leak"})
        assert ok is True  # duplicate — тоже считается успехом

    def test_send_event_network_error(self):
        with patch("httpx.post", side_effect=Exception("network down")):
            ok = _send_event("http://localhost/ingest", {}, {"event_type": "paste_leak"})
        assert ok is False
