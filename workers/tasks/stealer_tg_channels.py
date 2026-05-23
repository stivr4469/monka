"""
Мониторинг Telegram-каналов с дампами стилер-логов.

Скрейпит публичные каналы через t.me/s/{channel} (без API-ключа),
извлекает из текста постов строки в формате combo-list и url:login:pass,
фильтрует по целевому домену и ингестит совпадения в Core API.

Каналы добавляются в STEALER_TG_CHANNELS или через env STEALER_TG_EXTRA.
"""
import logging
import re
import time
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────
# Список публично известных каналов со стилер-логами
# ─────────────────────────────────────────────────────────

STEALER_TG_CHANNELS: list[str] = [
    # Крупные агрегаторы логов (публичные)
    "freelogs_shop",
    "stealerlogs",
    "freeclouds",
    "logs_mafia",
    "freecombolist",
    "combo_logs_free",
    "logs_free_club",
    "freeredlinelogs",
    "redline_logs_free",
    "raccoon_logs_free",
    "vidar_logs_channel",
    "logs_stealer",
    "dark_logs",
    "free_logs_combo",
    "leakbase_io",
    "leakednation",
    "databreach_logs",
    # Разбивка по стилерам
    "RedLineStealer",
    "RaccoonStealer",
    "LummaC2Logs",
    "MetaStealer_logs",
    "StealC_logs",
    # Англоязычные агрегаторы
    "leaksworldwide",
    "worldleaks",
    "cyberleaks_cc",
]

_CACHE: dict[str, tuple[float, list[dict]]] = {}
_CACHE_TTL = 1800  # 30 минут — каналы обновляются часто

_TIMEOUT = 15
_POSTS_LIMIT = 50  # последних постов

# ─────────────────────────────────────────────────────────
# Скрейпинг t.me/s/{channel}
# ─────────────────────────────────────────────────────────

def _fetch_channel_text(channel: str) -> list[str]:
    """
    Загружает HTML t.me/s/{channel} и вытаскивает текст всех постов.
    Возвращает список строк из тел постов.
    """
    try:
        r = httpx.get(
            f"https://t.me/s/{channel}",
            timeout=_TIMEOUT,
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; EASM-Monitor/1.0)",
                "Accept-Language": "en-US,en;q=0.9",
            },
            follow_redirects=True,
        )
        if r.status_code != 200:
            logger.debug("[tg-stealer] %s → HTTP %d", channel, r.status_code)
            return []

        # Извлекаем текст постов из div.tgme_widget_message_text
        raw_texts = re.findall(
            r'<div class="tgme_widget_message_text[^"]*"[^>]*>(.*?)</div>',
            r.text,
            re.DOTALL | re.IGNORECASE,
        )

        result = []
        for html_block in raw_texts:
            # Убираем HTML-теги
            text = re.sub(r"<[^>]+>", " ", html_block)
            # Декодируем HTML-entities
            text = (text
                    .replace("&amp;", "&")
                    .replace("&lt;", "<")
                    .replace("&gt;", ">")
                    .replace("&quot;", '"')
                    .replace("&#39;", "'")
                    .replace("&nbsp;", " "))
            text = text.strip()
            if text:
                result.append(text)

        return result

    except Exception as exc:
        logger.debug("[tg-stealer] %s: ошибка скрейпинга — %s", channel, exc)
        return []


# ─────────────────────────────────────────────────────────
# Парсеры форматов из текста постов
# ─────────────────────────────────────────────────────────

_URL_RE = re.compile(
    r'https?://[^\s:]+',
    re.IGNORECASE,
)

_COMBO_RE = re.compile(
    r'(?P<login>[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})'
    r':'
    r'(?P<password>\S{4,})',
)

_THREE_RE = re.compile(
    r'(?P<url>https?://[^\s:]+)'
    r'[:|]'
    r'(?P<login>[^\s:]+)'
    r':'
    r'(?P<password>\S{4,})',
)


def _parse_post_text(text: str) -> list[dict]:
    """
    Пытается извлечь учётные данные из текста поста.
    Поддерживает url:login:pass и combo (email:pass).
    """
    records = []

    # Трёхпольный формат
    for m in _THREE_RE.finditer(text):
        records.append({
            "url":      m.group("url"),
            "login":    m.group("login"),
            "password": m.group("password"),
        })

    # Combo email:pass (если трёхпольный ничего не дал или дополнительно)
    if not records:
        for m in _COMBO_RE.finditer(text):
            records.append({
                "url":      "",
                "login":    m.group("login"),
                "password": m.group("password"),
            })

    return records


# ─────────────────────────────────────────────────────────
# Сопоставление с доменом
# ─────────────────────────────────────────────────────────

def _domain_from_url(url: str) -> str:
    """Извлекает hostname без www."""
    try:
        host = urlparse(url).hostname or ""
        return host.removeprefix("www.")
    except Exception:
        return ""


def _domain_from_login(login: str) -> str:
    """Извлекает домен из email."""
    if "@" in login:
        return login.split("@", 1)[-1].lower()
    return ""


def _matches(rec: dict, target: str) -> bool:
    url_domain   = _domain_from_url(rec.get("url", ""))
    login_domain = _domain_from_login(rec.get("login", ""))
    for d in (url_domain, login_domain):
        if d and (d == target or d.endswith("." + target)):
            return True
    return False


# ─────────────────────────────────────────────────────────
# Отправка в Core API
# ─────────────────────────────────────────────────────────

def _ingest(
    records: list[dict],
    channel: str,
    domain: str,
    core_api_url: str,
    internal_secret: str,
) -> tuple[int, int]:
    url = f"{core_api_url}/api/v1/internal/ingest"
    headers = {"Authorization": f"Bearer {internal_secret}"}
    sent = errors = 0
    for rec in records:
        event = {
            "event_type": "stealer_log",
            "severity":   "critical",
            "source_type": "telegram_stealer",
            "source_name": f"tg:{channel}",
            "target_domain": domain,
            "payload": {
                "url":      rec.get("url", ""),
                "login":    rec.get("login", ""),
                "password": rec.get("password", ""),
                "channel":  channel,
            },
        }
        try:
            r = httpx.post(url, json=event, headers=headers, timeout=10)
            st = r.json().get("status", "error")
            if st in ("accepted", "duplicate"):
                sent += 1
            else:
                errors += 1
        except Exception as exc:
            logger.error("[tg-stealer] ingest error: %s", exc)
            errors += 1
    return sent, errors


# ─────────────────────────────────────────────────────────
# Оркестратор
# ─────────────────────────────────────────────────────────

def scan_tg_stealer_channels(
    domain: str,
    core_api_url: str,
    internal_secret: str,
    extra_channels: list[str] | None = None,
) -> dict:
    """
    Проверяет все каналы по домену. Возвращает сводку:
    {channel: {found, matched, sent, errors}, ...}
    """
    import os
    env_extra = [
        c.strip().lstrip("@")
        for c in os.getenv("STEALER_TG_EXTRA", "").split(",")
        if c.strip()
    ]
    channels = list(dict.fromkeys(
        STEALER_TG_CHANNELS + env_extra + (extra_channels or [])
    ))

    summary: dict[str, dict] = {}
    total_matched = total_sent = 0

    for channel in channels:
        cache_key = f"tg:{channel}"
        texts = _CACHE.get(cache_key)
        if texts and time.time() - texts[0] < _CACHE_TTL:
            post_texts = texts[1]
        else:
            post_texts = _fetch_channel_text(channel)
            _CACHE[cache_key] = (time.time(), post_texts)

        found = matched = sent = errors = 0

        for text in post_texts:
            recs = _parse_post_text(text)
            found += len(recs)
            hits = [r for r in recs if _matches(r, domain)]
            matched += len(hits)
            if hits:
                s, e = _ingest(hits, channel, domain, core_api_url, internal_secret)
                sent   += s
                errors += e

        if matched > 0 or found > 0:
            logger.info(
                "[tg-stealer] @%s: постов=%d записей=%d совпало=%d отправлено=%d",
                channel, len(post_texts), found, matched, sent,
            )

        summary[channel] = {
            "posts":   len(post_texts),
            "found":   found,
            "matched": matched,
            "sent":    sent,
            "errors":  errors,
        }
        total_matched += matched
        total_sent    += sent

    logger.info(
        "[tg-stealer] %s: каналов=%d совпало=%d отправлено=%d",
        domain, len(channels), total_matched, total_sent,
    )
    return summary
