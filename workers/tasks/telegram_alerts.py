"""
Отправка Telegram-алертов по событиям безопасности.

Интеграция:
  - send_telegram_alert() — отправляет одно сообщение в чат
  - dispatch_alerts()     — получает правила из Core API и рассылает подходящие алерты
"""
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# Уровни серьёзности в порядке возрастания — используется для проверки min_severity
_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

# Emoji для каждого уровня серьёзности
_SEVERITY_EMOJI = {
    "info": "ℹ️",
    "low": "🔵",
    "medium": "🟡",
    "high": "🟠",
    "critical": "🚨",
}

# Максимальное время ожидания ответа от Telegram API
_TELEGRAM_TIMEOUT = 10.0

# Базовый URL Telegram Bot API
_TELEGRAM_API_BASE = "https://api.telegram.org"


# ──────────────────────────────────────────────────────────────────
# Форматирование сообщений
# ──────────────────────────────────────────────────────────────────

def _format_alert_message(event: dict[str, Any]) -> str:
    """
    Форматирует событие в читаемое Telegram-сообщение.

    Пример вывода:
        🚨 [CRITICAL] mycredit.ua
        Тип: vulnerability
        Находка: Prometheus Metrics Exposed
        URL: https://chatbot.mycredit.ua/metrics
        Теги: exposure, prometheus
    """
    severity = event.get("severity", "info").upper()
    domain = event.get("target_domain", "unknown")
    event_type = event.get("event_type", "unknown")
    payload = event.get("payload", {})

    emoji = _SEVERITY_EMOJI.get(event.get("severity", "info"), "⚠️")

    lines = [
        f"{emoji} [{severity}] {domain}",
        f"Тип: {event_type}",
    ]

    # Заголовок / название находки (разные воркеры используют разные ключи)
    title = (
        payload.get("title")
        or payload.get("template-id")
        or payload.get("finding")
        or payload.get("subdomain")
        or payload.get("secret_type")
        or ""
    )
    if title:
        lines.append(f"Находка: {title}")

    # URL если есть
    url = payload.get("url") or payload.get("matched-at") or ""
    if url:
        lines.append(f"URL: {url}")

    # Теги / CVE
    tags = payload.get("tags") or payload.get("cve") or []
    if isinstance(tags, list) and tags:
        lines.append(f"Теги: {', '.join(str(t) for t in tags)}")
    elif isinstance(tags, str) and tags:
        lines.append(f"Теги: {tags}")

    # Источник
    source = event.get("source_name", "")
    if source:
        lines.append(f"Источник: {source}")

    # Метка времени
    detected_at = event.get("detected_at", "")
    if detected_at:
        # Берём только дату и время без миллисекунд
        lines.append(f"Время: {str(detected_at)[:19]}")

    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────
# Отправка в Telegram
# ──────────────────────────────────────────────────────────────────

def send_telegram_alert(chat_id: str, event: dict[str, Any], bot_token: str) -> bool:
    """
    Отправляет одно форматированное сообщение в Telegram-чат.

    Аргументы:
        chat_id   — Telegram chat_id (числовой или @username)
        event     — словарь нормализованного события
        bot_token — токен Telegram Bot API

    Возвращает True при успехе, False при ошибке.
    """
    if not bot_token:
        logger.error("TELEGRAM_BOT_TOKEN не задан — отправка невозможна")
        return False

    if not chat_id:
        logger.error("chat_id пустой — отправка невозможна")
        return False

    text = _format_alert_message(event)
    url = f"{_TELEGRAM_API_BASE}/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",      # HTML безопаснее Markdown для произвольных строк
        "disable_web_page_preview": True,
    }

    try:
        resp = httpx.post(url, json=payload, timeout=_TELEGRAM_TIMEOUT)
        if resp.status_code == 200 and resp.json().get("ok"):
            logger.info("Алерт отправлен в Telegram chat=%s event_type=%s", chat_id, event.get("event_type"))
            return True
        else:
            # Telegram возвращает 200 с ok=False при ошибках (например неверный chat_id)
            error_desc = resp.json().get("description", "неизвестная ошибка")
            logger.warning(
                "Telegram отклонил сообщение: chat=%s code=%d desc=%s",
                chat_id, resp.status_code, error_desc,
            )
            return False
    except httpx.TimeoutException:
        logger.error("Timeout при отправке алерта в Telegram chat=%s", chat_id)
        return False
    except httpx.RequestError as exc:
        logger.error("Сетевая ошибка при отправке алерта: %s", exc)
        return False


# ──────────────────────────────────────────────────────────────────
# Проверка min_severity
# ──────────────────────────────────────────────────────────────────

def _severity_gte(event_severity: str, min_severity: str) -> bool:
    """Возвращает True если event_severity >= min_severity по порядку."""
    try:
        return _SEVERITY_ORDER.index(event_severity) >= _SEVERITY_ORDER.index(min_severity)
    except ValueError:
        return False


def _rule_matches(rule: dict[str, Any], event: dict[str, Any]) -> bool:
    """
    Проверяет, подходит ли событие под правило.
    Дублирует логику AlertRule.matches_event() для использования в воркере
    без импорта SQLAlchemy-модели.
    """
    # Фильтр по домену
    target_domain = rule.get("target_domain")
    if target_domain is not None:
        if event.get("target_domain") != target_domain:
            return False

    # Фильтр по типам событий
    event_types = rule.get("event_types")
    if event_types is not None:
        if event.get("event_type") not in event_types:
            return False

    # Фильтр по минимальной серьёзности
    min_severity = rule.get("min_severity", "medium")
    event_severity = event.get("severity", "info")
    if not _severity_gte(event_severity, min_severity):
        return False

    return True


# ──────────────────────────────────────────────────────────────────
# Диспетчер алертов
# ──────────────────────────────────────────────────────────────────

def dispatch_alerts(
    event: dict[str, Any],
    core_api_url: str,
    internal_secret: str,
    bot_token: str = "",
) -> int:
    """
    Рассылает Telegram-алерты для одного события по всем подходящим правилам.

    Алгоритм:
      1. GET /api/v1/internal/alert-rules — список активных правил из Core API
      2. Для каждого правила: проверяем _rule_matches()
      3. Если совпадение — send_telegram_alert()

    Аргументы:
        event           — нормализованное событие (словарь)
        core_api_url    — базовый URL Core API (например "http://127.0.0.1:8000")
        internal_secret — Bearer-токен для /internal/* эндпоинтов
        bot_token       — Telegram Bot API токен (если пустой — пробуем из env)

    Возвращает количество успешно отправленных алертов.
    """
    import os

    # Токен бота — приоритет: аргумент → переменная окружения
    resolved_token = bot_token or os.getenv("TELEGRAM_BOT_TOKEN", "")

    if not resolved_token:
        logger.warning("TELEGRAM_BOT_TOKEN не задан — dispatch_alerts пропущен")
        return 0

    rules_url = f"{core_api_url}/api/v1/internal/alert-rules"
    headers = {"Authorization": f"Bearer {internal_secret}"}

    try:
        resp = httpx.get(rules_url, headers=headers, timeout=_TELEGRAM_TIMEOUT)
        resp.raise_for_status()
        rules: list[dict[str, Any]] = resp.json()
    except httpx.HTTPStatusError as exc:
        logger.error("Ошибка получения правил алертов: HTTP %d %s", exc.response.status_code, exc)
        return 0
    except httpx.RequestError as exc:
        logger.error("Сетевая ошибка при запросе правил алертов: %s", exc)
        return 0

    sent = 0
    for rule in rules:
        # Дополнительная защита: пропускаем неактивные (Core должен уже фильтровать)
        if not rule.get("is_active", True):
            continue

        if not _rule_matches(rule, event):
            continue

        chat_id = rule.get("telegram_chat_id", "")
        if not chat_id:
            logger.warning("Правило %s не имеет telegram_chat_id — пропускаем", rule.get("id"))
            continue

        if send_telegram_alert(chat_id=chat_id, event=event, bot_token=resolved_token):
            sent += 1

    logger.info(
        "dispatch_alerts: event_type=%s severity=%s domain=%s → отправлено %d алертов",
        event.get("event_type"),
        event.get("severity"),
        event.get("target_domain"),
        sent,
    )
    return sent
