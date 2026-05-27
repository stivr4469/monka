"""
Тесты для workers/tasks/telegram_alerts.py.

Все HTTP-вызовы к Telegram API и Core API мокируются через unittest.mock
и pytest-monkeypatch — никаких реальных сетевых запросов.
"""
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import httpx

# Добавляем workers в sys.path (conftest.py делает то же, но явно дублируем для надёжности)
_workers_path = str(Path(__file__).parents[2] / "workers")
if _workers_path not in sys.path:
    sys.path.insert(0, _workers_path)

from tasks.telegram_alerts import (
    _format_alert_message,
    _rule_matches,
    _severity_gte,
    dispatch_alerts,
    send_telegram_alert,
)


# ──────────────────────────────────────────────────────────────────
# Вспомогательные фабрики
# ──────────────────────────────────────────────────────────────────

def _make_event(**kwargs: Any) -> dict:
    """Создаёт минимальное корректное событие с переопределёнными полями."""
    base = {
        "event_type": "vulnerability",
        "severity": "high",
        "source_type": "nuclei",
        "source_name": "nuclei-v3",
        "target_domain": "example.com",
        "detected_at": "2026-05-23T10:00:00",
        "payload": {
            "title": "SQL Injection",
            "url": "https://example.com/api/users",
            "tags": ["sqli", "injection"],
        },
    }
    base.update(kwargs)
    return base


def _make_rule(**kwargs: Any) -> dict:
    """Создаёт минимальное корректное правило алерта."""
    base = {
        "id": "rule-001",
        "organization_id": "org-001",
        "name": "Тестовое правило",
        "target_domain": None,
        "min_severity": "medium",
        "event_types": None,
        "telegram_chat_id": "-1001234567890",
        "is_active": True,
    }
    base.update(kwargs)
    return base


def _ok_telegram_response() -> MagicMock:
    """Мок успешного ответа Telegram API."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = 200
    resp.json.return_value = {"ok": True, "result": {"message_id": 42}}
    return resp


def _fail_telegram_response(description: str = "chat not found") -> MagicMock:
    """Мок ошибочного ответа Telegram API."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = 200  # Telegram возвращает 200 даже при ошибках
    resp.json.return_value = {"ok": False, "description": description}
    return resp


def _rules_response(rules: list[dict]) -> MagicMock:
    """Мок успешного ответа Core API /internal/alert-rules."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = 200
    resp.json.return_value = rules
    resp.raise_for_status = MagicMock()  # Не бросает исключение
    return resp


# ──────────────────────────────────────────────────────────────────
# Тест 1: _severity_gte — правильный порядок уровней
# ──────────────────────────────────────────────────────────────────

def test_severity_gte_basic():
    """Проверяет что critical >= high >= medium >= low >= info."""
    assert _severity_gte("critical", "info") is True
    assert _severity_gte("high", "medium") is True
    assert _severity_gte("medium", "medium") is True
    assert _severity_gte("low", "high") is False
    assert _severity_gte("info", "critical") is False


def test_severity_gte_unknown_returns_false():
    """Неизвестный severity не должен ломать логику."""
    assert _severity_gte("unknown", "medium") is False
    assert _severity_gte("high", "unknown") is False


# ──────────────────────────────────────────────────────────────────
# Тест 2: _rule_matches — фильтрация событий по правилу
# ──────────────────────────────────────────────────────────────────

def test_rule_matches_all_wildcards():
    """Правило без ограничений (target_domain=None, event_types=None) совпадает с любым событием."""
    rule = _make_rule(target_domain=None, event_types=None, min_severity="info")
    event = _make_event(severity="info", target_domain="any.domain.com", event_type="stealer_log")
    assert _rule_matches(rule, event) is True


def test_rule_matches_domain_filter():
    """Правило с указанным доменом не совпадает с другим доменом."""
    rule = _make_rule(target_domain="mycredit.ua")
    event_match = _make_event(target_domain="mycredit.ua")
    event_no_match = _make_event(target_domain="other.com")
    assert _rule_matches(rule, event_match) is True
    assert _rule_matches(rule, event_no_match) is False


def test_rule_matches_event_type_filter():
    """Правило с event_types=['vulnerability'] не срабатывает на stealer_log."""
    rule = _make_rule(event_types=["vulnerability"], min_severity="info")
    event_vuln = _make_event(event_type="vulnerability", severity="info")
    event_stealer = _make_event(event_type="stealer_log", severity="info")
    assert _rule_matches(rule, event_vuln) is True
    assert _rule_matches(rule, event_stealer) is False


def test_rule_matches_severity_threshold():
    """Правило с min_severity='high' не срабатывает на medium событие."""
    rule = _make_rule(min_severity="high")
    assert _rule_matches(rule, _make_event(severity="critical")) is True
    assert _rule_matches(rule, _make_event(severity="high")) is True
    assert _rule_matches(rule, _make_event(severity="medium")) is False
    assert _rule_matches(rule, _make_event(severity="low")) is False


# ──────────────────────────────────────────────────────────────────
# Тест 3: _format_alert_message — формат сообщения
# ──────────────────────────────────────────────────────────────────

def test_format_alert_message_contains_key_fields():
    """Сообщение содержит severity, домен, тип события и URL."""
    event = _make_event()
    msg = _format_alert_message(event)
    assert "HIGH" in msg
    assert "example.com" in msg
    assert "vulnerability" in msg
    assert "SQL Injection" in msg
    assert "https://example.com/api/users" in msg
    assert "sqli" in msg


def test_format_alert_message_critical_emoji():
    """Critical событие начинается с 🚨."""
    event = _make_event(severity="critical")
    msg = _format_alert_message(event)
    assert msg.startswith("🚨")


def test_format_alert_message_no_url_in_payload():
    """Сообщение корректно формируется без URL в payload."""
    event = _make_event(payload={"title": "Secret Exposed"})
    msg = _format_alert_message(event)
    assert "Secret Exposed" in msg
    assert "URL:" not in msg


# ──────────────────────────────────────────────────────────────────
# Тест 4: send_telegram_alert — успешная отправка
# ──────────────────────────────────────────────────────────────────

def test_send_telegram_alert_success():
    """Успешный ответ Telegram API возвращает True."""
    with patch("httpx.post", return_value=_ok_telegram_response()) as mock_post:
        result = send_telegram_alert(
            chat_id="-1001234567890",
            event=_make_event(),
            bot_token="test-token",
        )
    assert result is True
    mock_post.assert_called_once()
    # Проверяем что запрос пошёл на правильный URL
    call_args = mock_post.call_args
    assert "sendMessage" in call_args[0][0]
    # Проверяем chat_id в теле запроса
    assert call_args[1]["json"]["chat_id"] == "-1001234567890"


# ──────────────────────────────────────────────────────────────────
# Тест 5: send_telegram_alert — Telegram вернул ok=False
# ──────────────────────────────────────────────────────────────────

def test_send_telegram_alert_telegram_error():
    """Ответ с ok=False возвращает False."""
    with patch("httpx.post", return_value=_fail_telegram_response("chat not found")):
        result = send_telegram_alert(
            chat_id="invalid-chat",
            event=_make_event(),
            bot_token="test-token",
        )
    assert result is False


# ──────────────────────────────────────────────────────────────────
# Тест 6: send_telegram_alert — пустой токен
# ──────────────────────────────────────────────────────────────────

def test_send_telegram_alert_empty_token():
    """Пустой bot_token возвращает False без HTTP-запроса."""
    with patch("httpx.post") as mock_post:
        result = send_telegram_alert(
            chat_id="-1001234567890",
            event=_make_event(),
            bot_token="",
        )
    assert result is False
    mock_post.assert_not_called()


# ──────────────────────────────────────────────────────────────────
# Тест 7: send_telegram_alert — таймаут
# ──────────────────────────────────────────────────────────────────

def test_send_telegram_alert_timeout():
    """Таймаут HTTP-запроса возвращает False."""
    with patch("httpx.post", side_effect=httpx.TimeoutException("timeout")):
        result = send_telegram_alert(
            chat_id="-1001234567890",
            event=_make_event(),
            bot_token="test-token",
        )
    assert result is False


# ──────────────────────────────────────────────────────────────────
# Тест 8: dispatch_alerts — рассылка по подходящим правилам
# ──────────────────────────────────────────────────────────────────

def test_dispatch_alerts_sends_to_matching_rules():
    """
    dispatch_alerts отправляет алерты только для подходящих правил.
    Правило 1: совпадает (домен + severity + тип).
    Правило 2: не совпадает (другой домен).
    """
    rules = [
        _make_rule(target_domain="example.com", telegram_chat_id="-111"),
        _make_rule(target_domain="other.com", telegram_chat_id="-222"),
    ]

    event = _make_event(target_domain="example.com", severity="high")

    with patch("httpx.get", return_value=_rules_response(rules)) as mock_get, \
         patch("httpx.post", return_value=_ok_telegram_response()) as mock_post:
        sent = dispatch_alerts(
            event=event,
            core_api_url="http://127.0.0.1:8000",
            internal_secret="test-secret",
            bot_token="test-token",
        )

    assert sent == 1  # Только первое правило совпало
    mock_get.assert_called_once()
    mock_post.assert_called_once()
    # Проверяем что отправили в правильный чат
    assert mock_post.call_args[1]["json"]["chat_id"] == "-111"


# ──────────────────────────────────────────────────────────────────
# Тест 9: dispatch_alerts — ошибка запроса правил
# ──────────────────────────────────────────────────────────────────

def test_dispatch_alerts_core_api_error():
    """При недоступности Core API dispatch возвращает 0."""
    with patch("httpx.get", side_effect=httpx.ConnectError("connection refused")):
        sent = dispatch_alerts(
            event=_make_event(),
            core_api_url="http://127.0.0.1:8000",
            internal_secret="test-secret",
            bot_token="test-token",
        )
    assert sent == 0


# ──────────────────────────────────────────────────────────────────
# Тест 10: dispatch_alerts — нет токена
# ──────────────────────────────────────────────────────────────────

def test_dispatch_alerts_no_token_returns_zero():
    """Без TELEGRAM_BOT_TOKEN dispatch_alerts возвращает 0 без HTTP-запросов."""
    with patch("httpx.get") as mock_get, patch("httpx.post") as mock_post, \
         patch.dict("os.environ", {}, clear=True):
        # Убеждаемся что TELEGRAM_BOT_TOKEN не в окружении
        import os
        os.environ.pop("TELEGRAM_BOT_TOKEN", None)
        sent = dispatch_alerts(
            event=_make_event(),
            core_api_url="http://127.0.0.1:8000",
            internal_secret="test-secret",
            bot_token="",   # Пустой токен
        )
    assert sent == 0
    mock_get.assert_not_called()
    mock_post.assert_not_called()


# ──────────────────────────────────────────────────────────────────
# Тест 11: dispatch_alerts — несколько правил совпадают
# ──────────────────────────────────────────────────────────────────

def test_dispatch_alerts_multiple_matching_rules():
    """
    Если несколько правил совпадают с событием — алерт отправляется в каждое.
    Например, одно правило общее (target_domain=None), второе конкретное.
    Используем severity=high чтобы попасть в immediate-путь (минуя батчинг).
    """
    rules = [
        _make_rule(target_domain=None, telegram_chat_id="-111", min_severity="info"),
        _make_rule(target_domain="example.com", telegram_chat_id="-222", min_severity="info"),
        _make_rule(target_domain="other.com", telegram_chat_id="-333", min_severity="info"),
    ]

    event = _make_event(target_domain="example.com", severity="high")

    with patch("httpx.get", return_value=_rules_response(rules)), \
         patch("httpx.post", return_value=_ok_telegram_response()) as mock_post:
        sent = dispatch_alerts(
            event=event,
            core_api_url="http://127.0.0.1:8000",
            internal_secret="test-secret",
            bot_token="test-token",
        )

    # Должно совпасть правило 1 (wildcard) и правило 2 (exact domain)
    assert sent == 2
    assert mock_post.call_count == 2


# ──────────────────────────────────────────────────────────────────
# Тест 12: dispatch_alerts — HTTP 403 от Core API
# ──────────────────────────────────────────────────────────────────

def test_dispatch_alerts_core_api_http_error():
    """HTTP 403 от Core API (неверный токен) возвращает 0."""
    error_resp = MagicMock(spec=httpx.Response)
    error_resp.status_code = 403
    error_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
        "403 Forbidden",
        request=MagicMock(),
        response=error_resp,
    )

    with patch("httpx.get", return_value=error_resp):
        sent = dispatch_alerts(
            event=_make_event(),
            core_api_url="http://127.0.0.1:8000",
            internal_secret="wrong-secret",
            bot_token="test-token",
        )
    assert sent == 0


# ──────────────────────────────────────────────────────────────────
# Тест 13: dispatch_alerts — неактивные правила пропускаются
# ──────────────────────────────────────────────────────────────────

def test_dispatch_alerts_skips_inactive_rules():
    """Неактивные правила (is_active=False) пропускаются даже если совпадают."""
    rules = [
        _make_rule(is_active=False, target_domain=None, telegram_chat_id="-111"),
        _make_rule(is_active=True, target_domain=None, telegram_chat_id="-222"),
    ]

    with patch("httpx.get", return_value=_rules_response(rules)), \
         patch("httpx.post", return_value=_ok_telegram_response()) as mock_post:
        sent = dispatch_alerts(
            event=_make_event(severity="critical"),
            core_api_url="http://127.0.0.1:8000",
            internal_secret="test-secret",
            bot_token="test-token",
        )

    assert sent == 1
    assert mock_post.call_count == 1
    assert mock_post.call_args[1]["json"]["chat_id"] == "-222"
