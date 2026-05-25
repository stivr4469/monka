"""
Воркер мониторинга публичных Telegram-каналов на упоминания домена.

Подход: скрейпинг t.me/s/{channel} — публичный HTML-просмотр канала.
Работает без API ключей, без Telethon, без авторизации.

Алгоритм:
  1. GET https://t.me/s/{channel_username}
  2. Парсим HTML через regex: текст постов, дата, ссылка на пост
  3. Для каждого поста проверяем три паттерна совпадения (email > url > domain)
  4. При совпадении отправляем событие telegram_leak в Core API

Rate limiting: 2 секунды между каналами (уважаем Telegram).
Устойчивость: сбой одного канала не прерывает обход остальных.
"""

import html
import logging
import re
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# Константы
# ──────────────────────────────────────────────

# Базовый URL публичного просмотра канала
_TG_BASE_URL = "https://t.me/s"

# Таймаут HTTP-запросов
_HTTP_TIMEOUT = 15.0

# Максимум постов за один обход канала
_DEFAULT_POST_LIMIT = 50

# Пауза между запросами к разным каналам (rate limit)
_CHANNEL_INTERVAL = 2.0

# Максимальная длина snippet в событии
_SNIPPET_MAX = 400

# Статусы Core API, которые считаются успешной доставкой
_INGEST_OK_STATUSES = frozenset({"accepted", "duplicate"})

# User-Agent, имитирующий браузер
_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

# Список каналов для мониторинга по умолчанию
DEFAULT_LEAK_CHANNELS: list[str] = [
    # Базовые каналы — дампы и утечки БД
    "breachforums_com",   # дампы баз данных
    "leakbase_io",        # утечки
    "databreaches_cc",    # уведомления об утечках
    "darkwebinformer",    # новости даркнета
    "cybersecalerts",     # алерты безопасности
    "leakednation",       # утечки
    # Стилер-логи и утечки учётных данных
    "logsmafia",          # Logs Mafia — дистрибуция стилер-логов
    "lummac2logs",        # LummaC2 логи
    "stealerlogs",        # общие стилер-логи
    "combolists",         # combo-листы учётных данных
    "dumpz_to",           # дампы баз данных
    "dataleakage",        # утечки данных
    # Ransomware и APT
    "ransomwarenews",     # новости ransomware
    "soc_radar_news",     # SOCRadar новости угроз
    "breachdetector",     # детектор утечек
    # Threat Intelligence
    "threatintelctr",     # CTI фид
    "vxunderground",      # вредоносные образцы и анализ
    "malwaretech",        # анализ малвари
    "hackingnews_org",    # хакинг новости
    "cyberthreatintel",   # Cyber Threat Intel
    # Российский сегмент
    "black_market_rus",   # чёрный рынок RU
    "xakep_ru",           # Xakep.ru канал
    "ru_cybersecurity",   # ИБ на русском
    # Дополнительные источники
    "leakcheck_net",      # LeakCheck — агрегатор утечек
    "haveibeenpwned",     # HaveIBeenPwned новости
]

# ──────────────────────────────────────────────
# Regex-паттерны парсинга HTML
# ──────────────────────────────────────────────

# Блок текста поста в t.me/s/{channel}
# Telegram отображает текст поста в теге с классом tgme_widget_message_text
_RE_MSG_TEXT = re.compile(
    r'<div\s+class="tgme_widget_message_text[^"]*"[^>]*>(.*?)</div>',
    re.IGNORECASE | re.DOTALL,
)

# Дата поста: <time datetime="2024-01-15T12:00:00+00:00">
_RE_MSG_TIME = re.compile(
    r'<time\s+datetime="([^"]+)"',
    re.IGNORECASE,
)

# Ссылка на пост: <a href="https://t.me/{channel}/{id}"> — ищем в блоке сообщения
_RE_MSG_LINK = re.compile(
    r'<a\s+[^>]*href="(https://t\.me/[A-Za-z0-9_]+/\d+)"[^>]*>',
    re.IGNORECASE,
)

# Блок одного сообщения целиком — для парсинга по блокам
_RE_MSG_BLOCK = re.compile(
    r'<div\s+class="tgme_widget_message_wrap[^"]*"[^>]*>.*?</div>\s*</div>',
    re.IGNORECASE | re.DOTALL,
)

# Удаление HTML-тегов для получения чистого текста
_RE_STRIP_TAGS = re.compile(r"<[^>]+>")

# ──────────────────────────────────────────────
# Утилиты
# ──────────────────────────────────────────────

def _strip_html(raw: str) -> str:
    """Удаляет HTML-теги и декодирует HTML-сущности в текст."""
    no_tags = _RE_STRIP_TAGS.sub(" ", raw)
    return html.unescape(no_tags).strip()


def _build_domain_patterns(domain: str) -> list[tuple[str, re.Pattern[str]]]:
    """
    Строит список (match_type, compiled_pattern) для заданного домена.

    Порядок важен — более специфичные паттерны идут первыми:
      email > url > domain (прямое упоминание)
    """
    escaped = re.escape(domain)
    return [
        # Email: user@example.com
        ("email", re.compile(
            rf"[\w.+\-]+@(?:[\w\-]+\.)*{escaped}",
            re.IGNORECASE,
        )),
        # URL: http(s)://example.com или http(s)://sub.example.com/path
        ("url", re.compile(
            rf"https?://(?:[\w\-]+\.)*{escaped}(?:[/?#][^\s\"'<>]*)?",
            re.IGNORECASE,
        )),
        # Прямое упоминание домена
        ("domain", re.compile(
            rf"(?<![/@\w]){escaped}(?![\w])",
            re.IGNORECASE,
        )),
    ]


def _find_match_type(
    text: str,
    patterns: list[tuple[str, re.Pattern[str]]],
) -> str | None:
    """
    Возвращает тип первого совпадения ('email'|'url'|'domain') или None.
    """
    for match_type, pattern in patterns:
        if pattern.search(text):
            return match_type
    return None


def _send_ingest_event(
    ingest_url: str,
    headers: dict[str, str],
    event: dict[str, Any],
) -> bool:
    """
    Отправляет событие в Core API.
    Возвращает True если Core API подтвердил приём (accepted или duplicate).
    """
    try:
        r = httpx.post(ingest_url, json=event, headers=headers, timeout=_HTTP_TIMEOUT)
        status_val: str = r.json().get("status", "error")
        return status_val in _INGEST_OK_STATUSES
    except Exception as exc:
        logger.error("[tg] Ошибка отправки события в Core API: %s", exc)
        return False


# ──────────────────────────────────────────────
# Парсинг страницы t.me/s/{channel}
# ──────────────────────────────────────────────

def _parse_posts(html_body: str, channel_username: str) -> list[dict[str, str]]:
    """
    Парсит HTML-страницу t.me/s/{channel} и извлекает список постов.

    Стратегия:
      1. Найти все блоки tgme_widget_message_wrap через regex
      2. В каждом блоке искать текст, время и ссылку
      3. Если блоки не нашлись — попытка flat-парсинга (fallback)

    Возвращает list[{"text": str, "date": str, "url": str, "channel": str}]
    """
    posts: list[dict[str, str]] = []

    # Пытаемся разбить страницу на блоки сообщений
    blocks = _RE_MSG_BLOCK.findall(html_body)

    if blocks:
        # Парсинг по блокам — предпочтительный вариант
        for block in blocks:
            text_raw = _RE_MSG_TEXT.search(block)
            time_raw = _RE_MSG_TIME.search(block)
            link_raw = _RE_MSG_LINK.search(block)

            text = _strip_html(text_raw.group(1)) if text_raw else ""
            date = time_raw.group(1) if time_raw else ""
            url = link_raw.group(1) if link_raw else ""

            # Пропускаем пустые посты
            if not text and not url:
                continue

            posts.append({
                "text": text,
                "date": date,
                "url": url,
                "channel": channel_username,
            })

    # Fallback: если блоки не дали ни одного поста с текстом — плоский парсинг.
    # Это покрывает случаи когда regex блока не захватил весь блок корректно.
    if not posts:
        texts = [_strip_html(m.group(1)) for m in _RE_MSG_TEXT.finditer(html_body)]
        times = [m.group(1) for m in _RE_MSG_TIME.finditer(html_body)]
        links = [m.group(1) for m in _RE_MSG_LINK.finditer(html_body)]

        for i, text in enumerate(texts):
            if not text:
                continue
            posts.append({
                "text": text,
                "date": times[i] if i < len(times) else "",
                "url": links[i] if i < len(links) else "",
                "channel": channel_username,
            })

    return posts


# ──────────────────────────────────────────────
# Публичные функции
# ──────────────────────────────────────────────

def fetch_channel_posts(
    channel_username: str,
    limit: int = _DEFAULT_POST_LIMIT,
) -> list[dict[str, str]]:
    """
    Скачивает и парсит публичные посты Telegram-канала через t.me/s/{channel}.

    Аргументы:
        channel_username: имя канала без @ (например 'darkwebinformer')
        limit: максимальное количество постов для возврата

    Возвращает:
        list[{"text": str, "date": str, "url": str, "channel": str}]
        При любой ошибке — пустой список (не поднимает исключений).
    """
    url = f"{_TG_BASE_URL}/{channel_username}"
    try:
        r = httpx.get(
            url,
            headers={"User-Agent": _USER_AGENT},
            timeout=_HTTP_TIMEOUT,
            follow_redirects=True,
        )
        if r.status_code != 200:
            logger.warning(
                "[tg] Канал %s вернул HTTP %d",
                channel_username,
                r.status_code,
            )
            return []

        posts = _parse_posts(r.text, channel_username)
        return posts[:limit]

    except httpx.TimeoutException:
        logger.warning("[tg] Таймаут при загрузке канала %s", channel_username)
        return []
    except Exception as exc:
        logger.warning("[tg] Ошибка загрузки канала %s: %s", channel_username, exc)
        return []


def scan_channel(
    channel_username: str,
    domain: str,
    core_api_url: str,
    internal_secret: str,
) -> dict[str, Any]:
    """
    Сканирует один Telegram-канал на упоминания домена.

    Три типа совпадения (в порядке специфичности):
      - "email"  — user@domain в тексте
      - "url"    — https://domain/... в тексте
      - "domain" — прямое упоминание домена

    Возвращает:
        {"channel": str, "posts_checked": int, "matched": int, "sent": int}
    """
    ingest_url = f"{core_api_url}/api/v1/internal/ingest"
    ingest_headers: dict[str, str] = {"Authorization": f"Bearer {internal_secret}"}
    patterns = _build_domain_patterns(domain)

    posts_checked = matched = sent = 0

    posts = fetch_channel_posts(channel_username)

    for post in posts:
        posts_checked += 1
        text = post.get("text", "")
        post_url = post.get("url", "")
        date_str = post.get("date", "")

        # Проверяем совпадение в тексте поста
        match_type = _find_match_type(text, patterns)

        # Если в тексте не нашли — проверяем URL поста (маловероятно, но возможно)
        if match_type is None and post_url:
            match_type = _find_match_type(post_url, patterns)

        if match_type is None:
            continue

        matched += 1

        event: dict[str, Any] = {
            "event_type": "telegram_leak",
            "severity": "high",
            "source_type": "telegram_monitor",
            "source_name": channel_username,
            "target_domain": domain,
            "payload": {
                "channel": f"@{channel_username}",
                "post_url": post_url,
                "snippet": text[:_SNIPPET_MAX],
                "match_type": match_type,
                "post_date": date_str,
            },
        }

        if _send_ingest_event(ingest_url, ingest_headers, event):
            sent += 1

    logger.info(
        "[tg] channel=@%s domain=%s posts_checked=%d matched=%d sent=%d",
        channel_username,
        domain,
        posts_checked,
        matched,
        sent,
    )
    return {
        "channel": channel_username,
        "posts_checked": posts_checked,
        "matched": matched,
        "sent": sent,
    }


def monitor_telegram_channels(
    domain: str,
    core_api_url: str,
    internal_secret: str,
    extra_channels: list[str] | None = None,
) -> dict[str, Any]:
    """
    Обходит все Telegram-каналы для мониторинга утечек домена.

    Список каналов = DEFAULT_LEAK_CHANNELS + extra_channels (с дедупликацией).
    Пауза 2 секунды между каналами для соблюдения rate limit.
    Сбой одного канала не прерывает обход остальных.

    Возвращает:
        {
            "channels_checked": int,
            "total_posts": int,
            "matched": int,
            "sent": int,
            "errors": int,
        }
    """
    domain = domain.strip().lower()
    logger.info("[tg] Начало мониторинга domain=%s", domain)

    # Дедупликация: сохраняем порядок (DEFAULT сначала, extra добавляются в конец)
    seen: set[str] = set()
    channels: list[str] = []
    for ch in (DEFAULT_LEAK_CHANNELS + (extra_channels or [])):
        # Нормализуем: убираем @, пробелы
        normalized = ch.strip().lstrip("@")
        if normalized and normalized not in seen:
            seen.add(normalized)
            channels.append(normalized)

    totals: dict[str, int] = {
        "channels_checked": 0,
        "total_posts": 0,
        "matched": 0,
        "sent": 0,
        "errors": 0,
    }

    for idx, channel in enumerate(channels):
        # Пауза между каналами начиная со второго
        if idx > 0:
            time.sleep(_CHANNEL_INTERVAL)

        try:
            result = scan_channel(channel, domain, core_api_url, internal_secret)
            totals["channels_checked"] += 1
            totals["total_posts"] += result.get("posts_checked", 0)
            totals["matched"] += result.get("matched", 0)
            totals["sent"] += result.get("sent", 0)
        except Exception as exc:
            logger.error("[tg] Неожиданная ошибка при обработке @%s: %s", channel, exc)
            totals["errors"] += 1

    logger.info(
        "[tg] Итого domain=%s channels=%d posts=%d matched=%d sent=%d errors=%d",
        domain,
        totals["channels_checked"],
        totals["total_posts"],
        totals["matched"],
        totals["sent"],
        totals["errors"],
    )
    return totals


# ── Celery-обёртка ────────────────────────────────────────────────────────────

try:
    from workers.celery_app import app as _celery_app
    from workers.config import settings as _settings

    @_celery_app.task(
        bind=True,
        max_retries=2,
        default_retry_delay=300,
        name="workers.tasks.telegram_monitor.monitor_telegram_task",
    )
    def monitor_telegram_task(
        self,
        domain: str,
        extra_channels: list[str] | None = None,
    ) -> dict[str, Any]:
        """Celery-задача: мониторинг Telegram-каналов на утечки домена."""
        try:
            return monitor_telegram_channels(
                domain=domain,
                core_api_url=_settings.CORE_API_URL,
                internal_secret=_settings.INTERNAL_API_SECRET,
                extra_channels=extra_channels,
            )
        except Exception as exc:
            raise self.retry(exc=exc)

except ImportError:
    # Celery не установлен — модуль используется без воркера (тесты, отдельный запуск)
    pass


def run_telegram_monitor_all_assets() -> None:
    """
    10.H: Celery Beat задача — мониторинг Telegram для всех активных активов.

    Запрашивает список активов через Core API и запускает мониторинг Telegram-каналов
    на упоминание каждого домена.
    Запускается каждые 15 минут через Beat расписание.
    """
    import os

    import httpx

    core_url = os.environ.get("CORE_API_URL", "http://core:8000")
    internal_secret = os.environ.get("INTERNAL_API_SECRET", "")

    try:
        resp = httpx.get(
            f"{core_url}/api/v1/assets/",
            headers={"Authorization": f"Bearer {internal_secret}"},
            timeout=10,
        )
        assets = resp.json() if resp.is_success else []
        logger.info("[beat] telegram-monitor-all: запускаем для %d активов", len(assets))
        for asset in assets:
            domain = asset.get("domain") if isinstance(asset, dict) else None
            if domain:
                try:
                    monitor_telegram_channels(
                        domain=domain,
                        core_api_url=core_url,
                        internal_secret=internal_secret,
                    )
                except Exception as exc:
                    logger.warning("[beat] telegram-monitor-all: ошибка для %s: %s", domain, exc)
    except Exception as exc:
        logger.warning("[beat] telegram-monitor-all: ошибка получения активов: %s", exc)


# ──────────────────────────────────────────────
# Phase 12.E — Мониторинг бренда в Telegram-каналах
# ──────────────────────────────────────────────

# Максимальная длина snippet для brand-упоминаний
_BRAND_SNIPPET_MAX = 200


def monitor_brand_telegram(
    domain: str,
    brand_keywords: list[str],
    core_api_url: str,
    internal_secret: str,
) -> dict[str, Any]:
    """
    Ищет brand_keywords в тех же каналах что monitor_telegram,
    но severity="low" (brand mentions — не credentials).

    Аргументы:
        domain: домен актива (например "example.com")
        brand_keywords: список ключевых слов для поиска ["CompanyName", "product"]
        core_api_url: базовый URL Core API
        internal_secret: внутренний секрет для ingest

    Возвращает:
        {"channels_checked": int, "total_posts": int, "matched": int, "sent": int}
    """
    domain = domain.strip().lower()
    logger.info(
        "[tg/brand] Начало мониторинга бренда domain=%s keywords=%s",
        domain,
        brand_keywords,
    )

    ingest_url = f"{core_api_url}/api/v1/internal/ingest"
    ingest_headers: dict[str, str] = {"Authorization": f"Bearer {internal_secret}"}

    # Нормализуем ключевые слова для поиска
    keywords_lower = [kw.lower() for kw in brand_keywords if kw.strip()]
    if not keywords_lower:
        logger.warning(
            "[tg/brand] Пустой список brand_keywords для домена %s — пропускаем",
            domain,
        )
        return {"channels_checked": 0, "total_posts": 0, "matched": 0, "sent": 0}

    totals: dict[str, int] = {
        "channels_checked": 0,
        "total_posts": 0,
        "matched": 0,
        "sent": 0,
    }

    for idx, channel in enumerate(DEFAULT_LEAK_CHANNELS):
        # Пауза между каналами (rate limit)
        if idx > 0:
            time.sleep(_CHANNEL_INTERVAL)

        try:
            posts = fetch_channel_posts(channel)
            totals["channels_checked"] += 1
            totals["total_posts"] += len(posts)

            for post in posts:
                text_lower = post.get("text", "").lower()
                post_url = post.get("url", "")
                date_str = post.get("date", "")

                # Проверяем наличие любого бренд-ключевого слова в тексте поста
                matched_keyword: str | None = None
                for kw in keywords_lower:
                    if kw in text_lower:
                        matched_keyword = kw
                        break

                if matched_keyword is None:
                    continue

                totals["matched"] += 1

                # Формируем snippet: первые 200 символов текста поста
                snippet = post.get("text", "")[:_BRAND_SNIPPET_MAX]

                event: dict[str, Any] = {
                    "event_type": "telegram_leak",
                    "severity": "low",
                    "source_type": "telegram_monitor",
                    "source_name": "telegram_brand_monitor",
                    "target_domain": domain,
                    "payload": {
                        "keyword": matched_keyword,
                        "channel": f"@{channel}",
                        "snippet": snippet,
                        "post_url": post_url,
                        "post_date": date_str,
                    },
                }

                if _send_ingest_event(ingest_url, ingest_headers, event):
                    totals["sent"] += 1

        except Exception as exc:
            logger.error(
                "[tg/brand] Неожиданная ошибка при обработке @%s: %s",
                channel,
                exc,
            )

    logger.info(
        "[tg/brand] Итого domain=%s channels=%d posts=%d matched=%d sent=%d",
        domain,
        totals["channels_checked"],
        totals["total_posts"],
        totals["matched"],
        totals["sent"],
    )
    return totals
