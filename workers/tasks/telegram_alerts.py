"""
Отправка Telegram-алертов по событиям безопасности.

Интеграция:
  - send_telegram_alert()  — отправляет одно сообщение в чат
  - dispatch_alerts()      — получает правила из Core API и рассылает подходящие алерты
  - flush_batches()        — отправляет накопленные батч-дайджесты (вызывать из Celery beat)
"""
import logging
import os
from collections import Counter
from typing import Any

import httpx

from app.services.alert_suppression import (
    BATCH_WINDOW_SEC,
    _IMMEDIATE_SEVERITIES,
    get_suppression_store,
)

logger = logging.getLogger(__name__)

# Уровни серьёзности в порядке возрастания — используется для проверки min_severity
_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

# Emoji для батч-дайджеста по уровням
_BATCH_EMOJI = {
    "info":     "ℹ️",
    "low":      "🔵",
    "medium":   "🟡",
    "high":     "🟠",
    "critical": "🚨",
}

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
# Форматирование и отправка батч-дайджеста
# ──────────────────────────────────────────────────────────────────

def _format_batch_digest(events: list[dict[str, Any]]) -> str:
    """
    Формирует компактный дайджест из нескольких событий.

    Пример вывода:
        🔔 Дайджест алертов за 5 мин (@domain.com)
        • 3 × medium | tech_profile
        • 2 × low | subdomain_found
    """
    # Определяем домен из первого события
    domain = events[0].get("target_domain", "unknown") if events else "unknown"
    minutes = BATCH_WINDOW_SEC // 60

    header = f"🔔 Дайджест алертов за {minutes} мин (@{domain})"

    # Считаем (severity, event_type) пары
    counter: Counter[tuple[str, str]] = Counter(
        (e.get("severity", "info"), e.get("event_type", "unknown"))
        for e in events
    )

    lines = [header]
    # Сортируем: сначала более критичные
    def _severity_rank(pair: tuple[tuple[str, str], int]) -> int:
        sev = pair[0][0]
        try:
            return -_SEVERITY_ORDER.index(sev)
        except ValueError:
            return 0

    for (severity, event_type), count in sorted(counter.items(), key=_severity_rank):
        emoji = _BATCH_EMOJI.get(severity, "⚠️")
        lines.append(f"  {emoji} {count} × {severity} | {event_type}")

    return "\n".join(lines)


def send_batch_digest(
    chat_id: str,
    events: list[dict[str, Any]],
    bot_token: str,
) -> bool:
    """
    Отправляет батч-дайджест нескольких событий одним сообщением.

    Возвращает True при успехе, False при ошибке.
    """
    if not bot_token or not chat_id or not events:
        return False

    text = _format_batch_digest(events)
    url = f"{_TELEGRAM_API_BASE}/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }

    try:
        resp = httpx.post(url, json=payload, timeout=_TELEGRAM_TIMEOUT)
        if resp.status_code == 200 and resp.json().get("ok"):
            logger.info(
                "Батч-дайджест отправлен: chat=%s events=%d",
                chat_id, len(events),
            )
            return True
        else:
            error_desc = resp.json().get("description", "неизвестная ошибка")
            logger.warning(
                "Telegram отклонил дайджест: chat=%s code=%d desc=%s",
                chat_id, resp.status_code, error_desc,
            )
            return False
    except httpx.TimeoutException:
        logger.error("Timeout при отправке дайджеста: chat=%s", chat_id)
        return False
    except httpx.RequestError as exc:
        logger.error("Сетевая ошибка при отправке дайджеста: %s", exc)
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
# Pipeline Latency: фиксация времени отправки алерта
# ──────────────────────────────────────────────────────────────────

def _mark_event_alerted(event_id: str, core_api_url: str, internal_secret: str) -> None:
    """
    Устанавливает alert_sent_at = now() для события через internal API.
    Используется для измерения pipeline latency (ingested_at → alert_sent_at).
    Вызывается один раз — при первом успешном алерте по событию.
    """
    if not event_id:
        return
    url = f"{core_api_url}/api/v1/internal/events/{event_id}/mark-alerted"
    headers = {"Authorization": f"Bearer {internal_secret}"}
    try:
        r = httpx.patch(url, headers=headers, timeout=5)
        if r.status_code not in (200, 204):
            logger.warning(
                "mark-alerted неожиданный статус: %d event_id=%s",
                r.status_code, event_id,
            )
    except httpx.RequestError as exc:
        logger.warning("Ошибка mark-alerted event_id=%s: %s", event_id, exc)


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
      3. Если severity >= high  → немедленная отправка (минуя подавление и батч)
      4. Если severity < high   → проверяем подавление, затем добавляем в батч;
                                   если батч-окно закрылось — отправляем дайджест

    Аргументы:
        event           — нормализованное событие (словарь)
        core_api_url    — базовый URL Core API (например "http://127.0.0.1:8000")
        internal_secret — Bearer-токен для /internal/* эндпоинтов
        bot_token       — Telegram Bot API токен (если пустой — пробуем из env)

    Возвращает количество успешно отправленных алертов/дайджестов.
    """
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

    store = get_suppression_store()
    severity = event.get("severity", "info")
    sent = 0
    # Pipeline Latency: фиксируем alert_sent_at только при первом успешном алерте
    event_id: str = event.get("event_id") or event.get("id") or ""
    _latency_marked = False

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

        rule_id: int = rule.get("id", 0)

        # ── Немедленная отправка для high / critical ──────────────
        if severity in _IMMEDIATE_SEVERITIES:
            if send_telegram_alert(chat_id=chat_id, event=event, bot_token=resolved_token):
                store.record_fired(rule_id)
                sent += 1
                # Pipeline Latency: первый успешный алерт — фиксируем время
                if not _latency_marked and event_id:
                    _mark_event_alerted(event_id, core_api_url, internal_secret)
                    _latency_marked = True
            continue

        # ── Подавление дублей для низких severity ─────────────────
        if store.should_suppress(rule_id, severity):
            logger.debug(
                "Алерт подавлен (suppression window): rule_id=%s severity=%s",
                rule_id, severity,
            )
            continue

        # ── Батчинг ───────────────────────────────────────────────
        ready_batch = store.add_to_batch(rule_id, event)
        if ready_batch is not None:
            # Батч-окно закрылось — отправляем дайджест
            if send_batch_digest(chat_id=chat_id, events=ready_batch, bot_token=resolved_token):
                sent += 1
                # Pipeline Latency: фиксируем при первом успешном батч-дайджесте
                if not _latency_marked and event_id:
                    _mark_event_alerted(event_id, core_api_url, internal_secret)
                    _latency_marked = True
        else:
            logger.debug(
                "Событие добавлено в батч: rule_id=%s severity=%s event_type=%s",
                rule_id, severity, event.get("event_type"),
            )

    logger.info(
        "dispatch_alerts: event_type=%s severity=%s domain=%s → отправлено %d",
        event.get("event_type"),
        event.get("severity"),
        event.get("target_domain"),
        sent,
    )
    return sent


def flush_batches(
    core_api_url: str,
    internal_secret: str,
    bot_token: str = "",
) -> int:
    """
    Принудительно отправляет все накопленные батч-дайджесты.
    Вызывать из Celery beat каждые BATCH_WINDOW_SEC секунд (5 мин).

    Алгоритм:
      1. Получить все непустые батчи из хранилища (flush_all_batches)
      2. Для каждого rule_id: получить chat_id из Core API и отправить дайджест

    Возвращает количество успешно отправленных дайджестов.
    """
    resolved_token = bot_token or os.getenv("TELEGRAM_BOT_TOKEN", "")
    if not resolved_token:
        logger.warning("TELEGRAM_BOT_TOKEN не задан — flush_batches пропущен")
        return 0

    store = get_suppression_store()
    batches = store.flush_all_batches()

    if not batches:
        return 0

    # Получаем актуальный список правил для маппинга rule_id → chat_id
    rules_url = f"{core_api_url}/api/v1/internal/alert-rules"
    headers = {"Authorization": f"Bearer {internal_secret}"}

    try:
        resp = httpx.get(rules_url, headers=headers, timeout=_TELEGRAM_TIMEOUT)
        resp.raise_for_status()
        rules: list[dict[str, Any]] = resp.json()
    except (httpx.HTTPStatusError, httpx.RequestError) as exc:
        logger.error("flush_batches: не удалось получить правила: %s", exc)
        return 0

    rule_map: dict[int, str] = {
        r.get("id", 0): r.get("telegram_chat_id", "")
        for r in rules
        if r.get("is_active", True)
    }

    sent = 0
    for rule_id, events in batches.items():
        chat_id = rule_map.get(rule_id, "")
        if not chat_id:
            logger.warning("flush_batches: rule_id=%s — chat_id не найден, батч потерян", rule_id)
            continue

        if send_batch_digest(chat_id=chat_id, events=events, bot_token=resolved_token):
            sent += 1

    logger.info("flush_batches: отправлено дайджестов %d из %d", sent, len(batches))
    return sent
