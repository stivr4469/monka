"""
Воркер мониторинга публичных paste-сервисов на упоминания домена.

Источники:
  1. Pastebin — API скрейпинга: https://scrape.pastebin.com/api_scraping.php
     (публичный эндпоинт, ключ не требуется)
  2. Pastee.org  — https://api.paste.ee/v1/pastes
     (публичный поиск, ключ не требуется)

Алгоритм:
  - Забираем список последних paste (до 100 штук)
  - Для каждого paste скачиваем текст
  - Ищем совпадения тремя regex-паттернами (в порядке специфичности):
      1. email  — user@domain (самый специфичный, матчим первым)
      2. url    — https://domain/...
      3. domain — прямое упоминание домена (самый широкий, последний)
  - При совпадении отправляем событие paste_leak в Core API

Rate limiting: 1 с между запросами к каждому источнику (Pastebin TOS).
Устойчивость: ошибка одного источника не прерывает работу остальных.
"""
import logging
import re
import time
from typing import Any, Iterator

import httpx

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# Константы
# ──────────────────────────────────────────────

# Pastebin публичный scraping API (не требует ключа)
PASTEBIN_LIST_URL = "https://scrape.pastebin.com/api_scraping.php"
PASTEBIN_ITEM_URL = "https://scrape.pastebin.com/api_scrape_item.php"
PASTEBIN_BASE_URL = "https://pastebin.com"

# Pastee.org публичный API
PASTEE_LIST_URL = "https://api.paste.ee/v1/pastes"

# Интервал между HTTP-запросами (соблюдаем Pastebin TOS — 1 req/s)
REQUEST_INTERVAL = 1.0

# Максимум paste за один обход источника
PASTEBIN_LIMIT = 100
PASTEE_LIMIT = 100

# Радиус контекста вокруг совпадения (символов с каждой стороны)
SNIPPET_RADIUS = 150

# Максимальная длина snippet в событии
SNIPPET_MAX_LEN = 300

# Таймаут HTTP-запросов
HTTP_TIMEOUT = 15.0

# Статусы Core API, которые считаются успешной доставкой
_INGEST_OK_STATUSES = frozenset({"accepted", "duplicate"})


# ──────────────────────────────────────────────
# Regex-паттерны
# ──────────────────────────────────────────────

def _build_patterns(domain: str) -> list[tuple[str, re.Pattern[str]]]:
    """
    Строит список (match_type, compiled_pattern) для заданного домена.

    Порядок важен — более специфичные паттерны идут первыми:
      email > url > domain (прямое упоминание)

    Используем re.escape чтобы точки и спец-символы в домене не ломали regex.
    """
    escaped = re.escape(domain)
    return [
        # Email: user@example.com или user.name+tag@sub.example.com
        ("email", re.compile(
            rf"[\w.+\-]+@(?:[\w\-]+\.)*{escaped}",
            re.IGNORECASE,
        )),
        # URL: http(s)://example.com или http(s)://sub.example.com/path
        ("url", re.compile(
            rf"https?://(?:[\w\-]+\.)*{escaped}(?:[/?#][^\s\"'<>]*)?",
            re.IGNORECASE,
        )),
        # Прямое упоминание домена (не часть email/URL — отрицательный lookbehind)
        ("domain", re.compile(
            rf"(?<![/@\w]){escaped}(?![\w])",
            re.IGNORECASE,
        )),
    ]


# ──────────────────────────────────────────────
# Утилиты
# ──────────────────────────────────────────────

def _extract_snippet(text: str, match: re.Match[str]) -> str:
    """
    Вырезает контекст вокруг совпадения.
    Результат не длиннее SNIPPET_MAX_LEN символов.
    """
    start = max(0, match.start() - SNIPPET_RADIUS)
    end = min(len(text), match.end() + SNIPPET_RADIUS)
    return text[start:end][:SNIPPET_MAX_LEN]


def _find_first_match(
    text: str,
    patterns: list[tuple[str, re.Pattern[str]]],
) -> tuple[str, str, str] | None:
    """
    Ищет первое совпадение по упорядоченному списку паттернов.
    Возвращает (match_type, matched_text, snippet) или None.
    """
    for match_type, pattern in patterns:
        m = pattern.search(text)
        if m:
            return match_type, m.group(0), _extract_snippet(text, m)
    return None


def _send_event(
    ingest_url: str,
    headers: dict[str, str],
    event: dict[str, Any],
) -> bool:
    """
    Отправляет событие в Core API через POST /internal/ingest.
    Возвращает True если доставка подтверждена (accepted или duplicate).
    """
    try:
        r = httpx.post(ingest_url, json=event, headers=headers, timeout=HTTP_TIMEOUT)
        status_val: str = r.json().get("status", "error")
        return status_val in _INGEST_OK_STATUSES
    except Exception as exc:
        logger.error("[paste] Ошибка отправки события в Core API: %s", exc)
        return False


# ──────────────────────────────────────────────
# Pastebin
# ──────────────────────────────────────────────

def _fetch_pastebin_list(limit: int = PASTEBIN_LIMIT) -> list[dict[str, Any]]:
    """
    Получает список последних публичных paste с pastebin.
    Возвращает список словарей {key, title, date, size, ...} или [] при ошибке.
    """
    try:
        r = httpx.get(
            PASTEBIN_LIST_URL,
            params={"limit": limit},
            timeout=HTTP_TIMEOUT,
        )
        if r.status_code != 200:
            logger.warning("[paste][pastebin] список paste вернул HTTP %d", r.status_code)
            return []
        data = r.json()
        # API возвращает список; защищаемся от неожиданных форматов
        return data if isinstance(data, list) else []
    except Exception as exc:
        logger.warning("[paste][pastebin] ошибка получения списка paste: %s", exc)
        return []


def _fetch_pastebin_item(key: str) -> str | None:
    """
    Скачивает raw-текст одного paste по ключу.
    Возвращает текст или None при любой ошибке (не прерывает обход).
    """
    try:
        r = httpx.get(
            PASTEBIN_ITEM_URL,
            params={"i": key},
            timeout=HTTP_TIMEOUT,
        )
        if r.status_code != 200:
            logger.debug("[paste][pastebin] item=%s вернул HTTP %d", key, r.status_code)
            return None
        return r.text
    except Exception as exc:
        logger.debug("[paste][pastebin] ошибка загрузки item=%s: %s", key, exc)
        return None


def scan_pastebin(
    domain: str,
    core_api_url: str,
    internal_secret: str,
) -> dict[str, int]:
    """
    Сканирует последние публичные paste на pastebin.com.

    Возвращает: {"checked": N, "matched": M, "sent": K}
    """
    ingest_url = f"{core_api_url}/api/v1/internal/ingest"
    ingest_headers: dict[str, str] = {"Authorization": f"Bearer {internal_secret}"}
    patterns = _build_patterns(domain)

    checked = matched = sent = 0

    pastes = _fetch_pastebin_list()
    if not pastes:
        logger.info("[paste][pastebin] список paste пуст или источник недоступен")
        return {"checked": 0, "matched": 0, "sent": 0}

    for item in pastes:
        key: str = item.get("key", "")
        if not key:
            continue

        # Rate limit — 1 запрос в секунду согласно Pastebin TOS
        text = _fetch_pastebin_item(key)
        time.sleep(REQUEST_INTERVAL)

        if text is None:
            continue

        checked += 1
        hit = _find_first_match(text, patterns)
        if hit is None:
            continue

        match_type, matched_text, snippet = hit
        matched += 1

        event: dict[str, Any] = {
            "event_type": "paste_leak",
            "severity": "high",
            "source_type": "paste_monitor",
            "source_name": "pastebin",
            "target_domain": domain,
            "payload": {
                "paste_url": f"{PASTEBIN_BASE_URL}/{key}",
                "paste_key": key,
                "snippet": snippet,
                "match_type": match_type,
                "matched_text": matched_text,
            },
        }

        if _send_event(ingest_url, ingest_headers, event):
            sent += 1

    logger.info(
        "[paste][pastebin] domain=%s checked=%d matched=%d sent=%d",
        domain, checked, matched, sent,
    )
    return {"checked": checked, "matched": matched, "sent": sent}


# ──────────────────────────────────────────────
# Pastee.org
# ──────────────────────────────────────────────

def _iter_pastee_items(limit: int = PASTEE_LIMIT) -> Iterator[dict[str, Any]]:
    """
    Постранично итерирует публичные paste на paste.ee.
    Yield-ит словари с полями id, link, description, sections, ...

    Пагинация: paste.ee возвращает next_page_url в теле ответа.
    Если next_page_url отсутствует — это последняя страница.
    """
    # paste.ee принимает не более 25 элементов на страницу
    per_page = min(limit, 25)
    next_url: str | None = PASTEE_LIST_URL
    params: dict[str, Any] = {"perpage": per_page}
    fetched = 0

    while next_url and fetched < limit:
        try:
            r = httpx.get(next_url, params=params, timeout=HTTP_TIMEOUT)
            if r.status_code != 200:
                logger.warning("[paste][pastee] список paste вернул HTTP %d", r.status_code)
                break
            data: dict[str, Any] = r.json()
        except Exception as exc:
            logger.warning("[paste][pastee] ошибка получения списка paste: %s", exc)
            break

        items: list[dict[str, Any]] = data.get("data", [])
        if not items:
            break

        for item in items:
            if fetched >= limit:
                return
            yield item
            fetched += 1

        # Следующая страница — paste.ee отдаёт полный URL или null
        next_url = data.get("next_page_url")  # None означает конец
        if next_url:
            # При пагинации params уже вшиты в next_url; сбрасываем, чтобы не дублировать
            params = {}
            time.sleep(REQUEST_INTERVAL)


def _extract_pastee_text(item: dict[str, Any]) -> tuple[str, str]:
    """
    Извлекает текст и публичный URL из записи paste.ee.
    Возвращает (url, text).

    paste.ee хранит тело в sections[0].contents.
    Если sections пусты — используем description как fallback.
    """
    url: str = item.get("link", "")
    sections: list[dict[str, Any]] = item.get("sections", [])
    if sections:
        text = sections[0].get("contents", "")
    else:
        text = item.get("description", "")
    return url, text


def scan_pastee(
    domain: str,
    core_api_url: str,
    internal_secret: str,
) -> dict[str, int]:
    """
    Сканирует публичные paste на paste.ee.

    Возвращает: {"checked": N, "matched": M, "sent": K}
    """
    ingest_url = f"{core_api_url}/api/v1/internal/ingest"
    ingest_headers: dict[str, str] = {"Authorization": f"Bearer {internal_secret}"}
    patterns = _build_patterns(domain)

    checked = matched = sent = 0

    for item in _iter_pastee_items():
        url, text = _extract_pastee_text(item)

        if not text:
            continue

        checked += 1
        hit = _find_first_match(text, patterns)
        if hit is None:
            continue

        match_type, matched_text, snippet = hit
        matched += 1

        paste_id = item.get("id", "")
        event: dict[str, Any] = {
            "event_type": "paste_leak",
            "severity": "high",
            "source_type": "paste_monitor",
            "source_name": "pastee",
            "target_domain": domain,
            "payload": {
                "paste_url": url,
                "paste_key": str(paste_id),
                "snippet": snippet,
                "match_type": match_type,
                "matched_text": matched_text,
            },
        }

        if _send_event(ingest_url, ingest_headers, event):
            sent += 1

    logger.info(
        "[paste][pastee] domain=%s checked=%d matched=%d sent=%d",
        domain, checked, matched, sent,
    )
    return {"checked": checked, "matched": matched, "sent": sent}


# ──────────────────────────────────────────────
# Агрегирующая функция
# ──────────────────────────────────────────────

def monitor_pastes(
    domain: str,
    core_api_url: str,
    internal_secret: str,
) -> dict[str, int]:
    """
    Запускает мониторинг всех paste-источников последовательно.

    Каждый источник изолирован try/except — сбой одного не мешает другим.

    Возвращает суммарный результат:
        {"checked": N, "matched": M, "sent": K}
    """
    domain = domain.strip().lower()
    logger.info("[paste] Начало мониторинга domain=%s", domain)

    totals: dict[str, int] = {"checked": 0, "matched": 0, "sent": 0}

    # Источник 1: Pastebin
    try:
        pb = scan_pastebin(domain, core_api_url, internal_secret)
        for k in totals:
            totals[k] += pb.get(k, 0)
    except Exception as exc:
        logger.error("[paste][pastebin] неожиданная ошибка: %s", exc)

    # Источник 2: Pastee.org
    try:
        pe = scan_pastee(domain, core_api_url, internal_secret)
        for k in totals:
            totals[k] += pe.get(k, 0)
    except Exception as exc:
        logger.error("[paste][pastee] неожиданная ошибка: %s", exc)

    logger.info(
        "[paste] Итого domain=%s checked=%d matched=%d sent=%d",
        domain, totals["checked"], totals["matched"], totals["sent"],
    )
    return totals
