"""
Воркер мониторинга упоминаний бренда в публичных форумах.

Источники:
  1. Reddit — публичный JSON API (без OAuth)
  2. Hacker News — через Algolia Search API

Алгоритм:
  1. Для каждого бренд-ключевого слова ищем посты за последнюю неделю
  2. Проверяем заголовок + тело на наличие негативных ключевых слов
  3. При совпадении отправляем событие forum_mention в Core API
  4. Дедупликация: сохраняем уже обработанные URL в /tmp/brand_seen_{safe_domain}.json

Rate limiting: 1 секунда между запросами к одному источнику.
"""

import json
import logging
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# Константы
# ──────────────────────────────────────────────

# Таймаут HTTP-запросов (секунды)
_HTTP_TIMEOUT = 15.0

# User-Agent для Reddit (требуют идентификации)
_REDDIT_USER_AGENT = "EASM-Brand-Monitor/1.0"

# Статусы Core API, которые считаются успешной доставкой
_INGEST_OK_STATUSES = frozenset({"accepted", "duplicate"})

# Максимальная длина сниппета в событии
_SNIPPET_MAX = 400

# Пауза между запросами к одному источнику (rate limit)
_SOURCE_INTERVAL = 1.0

# Негативные ключевые слова для фильтрации упоминаний
NEGATIVE_KEYWORDS: list[str] = [
    "hack",
    "hacked",
    "breach",
    "breached",
    "leak",
    "leaked",
    "phish",
    "phishing",
    "scam",
    "fake",
    "fraud",
    "malware",
    "ransomware",
    "exposed",
    "stolen",
    "compromise",
    "vulnerability",
    "attack",
    "exploit",
    "unauthorized",
    "data loss",
]

# ──────────────────────────────────────────────
# Дедупликация
# ──────────────────────────────────────────────

def _get_seen_cache_path(domain: str) -> Path:
    """Возвращает путь к файлу дедупликации для домена."""
    # Безопасное имя файла: убираем спецсимволы, точки → подчёркивания
    safe = re.sub(r"[^\w]", "_", domain.lower())
    return Path(f"/tmp/brand_seen_{safe}.json")


def _load_seen_urls(domain: str) -> set[str]:
    """Загружает множество уже обработанных URL из кэша."""
    cache_path = _get_seen_cache_path(domain)
    try:
        if cache_path.exists():
            data = json.loads(cache_path.read_text(encoding="utf-8"))
            return set(data) if isinstance(data, list) else set()
    except Exception as exc:
        logger.warning("[brand] Ошибка чтения кэша %s: %s", cache_path, exc)
    return set()


def _save_seen_urls(domain: str, seen: set[str]) -> None:
    """Сохраняет множество обработанных URL в кэш."""
    cache_path = _get_seen_cache_path(domain)
    try:
        cache_path.write_text(
            json.dumps(sorted(seen), ensure_ascii=False),
            encoding="utf-8",
        )
    except Exception as exc:
        logger.warning("[brand] Ошибка записи кэша %s: %s", cache_path, exc)


# ──────────────────────────────────────────────
# Определение негативных упоминаний
# ──────────────────────────────────────────────

def is_negative_mention(text: str) -> tuple[bool, str]:
    """
    Проверяет текст на наличие негативных ключевых слов.

    Аргументы:
        text: заголовок + тело поста (объединённые)

    Возвращает:
        (True, "leaked") если найдено негативное слово
        (False, "") если текст нейтральный
    """
    # Нормализуем регистр для поиска
    lower_text = text.lower()
    for keyword in NEGATIVE_KEYWORDS:
        # Ищем как подстроку (data loss содержит пробел — обычный in достаточен)
        if keyword in lower_text:
            return True, keyword
    return False, ""


# ──────────────────────────────────────────────
# Reddit API
# ──────────────────────────────────────────────

def search_reddit(brand: str, limit: int = 25) -> list[dict[str, Any]]:
    """
    Ищет упоминания бренда в Reddit через публичный JSON API (без OAuth).

    URL: https://www.reddit.com/search.json?q={brand}&sort=new&limit=25&t=week

    Аргументы:
        brand: ключевое слово для поиска (например "CompanyName")
        limit: максимум результатов

    Возвращает:
        list[{"title": str, "text": str, "url": str, "subreddit": str, "created_at": str}]
        При любой ошибке — пустой список.
    """
    url = "https://www.reddit.com/search.json"
    params = {
        "q": brand,
        "sort": "new",
        "limit": limit,
        "t": "week",
    }
    headers = {"User-Agent": _REDDIT_USER_AGENT}

    try:
        response = httpx.get(
            url,
            params=params,
            headers=headers,
            timeout=_HTTP_TIMEOUT,
            follow_redirects=True,
        )
        if response.status_code != 200:
            logger.warning(
                "[brand/reddit] HTTP %d при поиске '%s'",
                response.status_code,
                brand,
            )
            return []

        data = response.json()
        children = data.get("data", {}).get("children", [])
        posts: list[dict[str, Any]] = []

        for child in children:
            post_data = child.get("data", {})

            # Формируем полный URL поста Reddit
            permalink = post_data.get("permalink", "")
            post_url = f"https://www.reddit.com{permalink}" if permalink else ""

            # Дата в ISO формате из unix timestamp
            created_utc = post_data.get("created_utc", 0)
            try:
                created_at = datetime.fromtimestamp(
                    float(created_utc), tz=timezone.utc
                ).isoformat()
            except (ValueError, OSError):
                created_at = ""

            posts.append({
                "title": post_data.get("title", ""),
                "text": post_data.get("selftext", ""),
                "url": post_url,
                "subreddit": post_data.get("subreddit", ""),
                "created_at": created_at,
            })

        logger.debug(
            "[brand/reddit] Найдено %d постов для '%s'",
            len(posts),
            brand,
        )
        return posts

    except httpx.TimeoutException:
        logger.warning("[brand/reddit] Таймаут при поиске '%s'", brand)
        return []
    except Exception as exc:
        logger.warning("[brand/reddit] Ошибка при поиске '%s': %s", brand, exc)
        return []


# ──────────────────────────────────────────────
# Hacker News API (через Algolia)
# ──────────────────────────────────────────────

def search_hackernews(brand: str) -> list[dict[str, Any]]:
    """
    Ищет упоминания бренда в Hacker News через Algolia Search API.

    URL: https://hn.algolia.com/api/v1/search?query={brand}&tags=story,comment
         &hitsPerPage=20&numericFilters=created_at_i>{last_week_unix}

    Аргументы:
        brand: ключевое слово для поиска

    Возвращает:
        list[{"title": str, "url": str, "hn_id": str, "created_at": str, "points": int}]
        При любой ошибке — пустой список.
    """
    # Вычисляем unix timestamp неделю назад
    one_week_ago = int(time.time()) - 7 * 24 * 3600

    url = "https://hn.algolia.com/api/v1/search"
    params = {
        "query": brand,
        "tags": "story,comment",
        "hitsPerPage": 20,
        "numericFilters": f"created_at_i>{one_week_ago}",
    }

    try:
        response = httpx.get(
            url,
            params=params,
            timeout=_HTTP_TIMEOUT,
            follow_redirects=True,
        )
        if response.status_code != 200:
            logger.warning(
                "[brand/hn] HTTP %d при поиске '%s'",
                response.status_code,
                brand,
            )
            return []

        data = response.json()
        hits = data.get("hits", [])

        if not hits:
            return []

        posts: list[dict[str, Any]] = []
        for hit in hits:
            object_id = hit.get("objectID", "")
            # Формируем прямую ссылку на HN пост
            hn_url = hit.get("url") or f"https://news.ycombinator.com/item?id={object_id}"

            # Дата из unix timestamp
            created_ts = hit.get("created_at_i", 0)
            try:
                created_at = datetime.fromtimestamp(
                    int(created_ts), tz=timezone.utc
                ).isoformat()
            except (ValueError, OSError):
                created_at = ""

            posts.append({
                "title": hit.get("title") or hit.get("comment_text", "")[:200],
                "url": hn_url,
                "hn_id": object_id,
                "created_at": created_at,
                "points": int(hit.get("points") or 0),
            })

        logger.debug(
            "[brand/hn] Найдено %d результатов для '%s'",
            len(posts),
            brand,
        )
        return posts

    except httpx.TimeoutException:
        logger.warning("[brand/hn] Таймаут при поиске '%s'", brand)
        return []
    except Exception as exc:
        logger.warning("[brand/hn] Ошибка при поиске '%s': %s", brand, exc)
        return []


# ──────────────────────────────────────────────
# Отправка события в Core API
# ──────────────────────────────────────────────

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
        logger.error("[brand] Ошибка отправки события в Core API: %s", exc)
        return False


# ──────────────────────────────────────────────
# Основная функция мониторинга бренда
# ──────────────────────────────────────────────

def monitor_brand(
    domain: str,
    brand_keywords: list[str],
    core_api_url: str,
    internal_secret: str,
) -> dict[str, int]:
    """
    Мониторинг упоминаний бренда в Reddit и Hacker News.

    Аргументы:
        domain: домен актива (например "example.com")
        brand_keywords: список ключевых слов ["CompanyName", "product-name"].
                        Если пустой — используется домен без TLD.
        core_api_url: базовый URL Core API
        internal_secret: внутренний секрет для ingest

    Возвращает:
        {"reddit": N, "hn": N, "negative": N, "sent": N}
    """
    domain = domain.strip().lower()

    # Если список ключевых слов пустой — берём домен без TLD
    if not brand_keywords:
        # Убираем TLD: "example.com" → "example", "my.company.io" → "my.company"
        parts = domain.split(".")
        brand_name = ".".join(parts[:-1]) if len(parts) > 1 else domain
        keywords = [brand_name]
        logger.info(
            "[brand] brand_keywords пустой, используем '%s' для домена '%s'",
            brand_name,
            domain,
        )
    else:
        keywords = list(brand_keywords)

    ingest_url = f"{core_api_url}/api/v1/internal/ingest"
    ingest_headers: dict[str, str] = {"Authorization": f"Bearer {internal_secret}"}

    # Загружаем кэш уже обработанных URL
    seen_urls = _load_seen_urls(domain)

    totals: dict[str, int] = {
        "reddit": 0,
        "hn": 0,
        "negative": 0,
        "sent": 0,
    }

    for keyword in keywords:
        logger.info(
            "[brand] Поиск по ключевому слову '%s' для домена '%s'",
            keyword,
            domain,
        )

        # ── Reddit ────────────────────────────────────────────────────────────
        reddit_posts = search_reddit(keyword)
        totals["reddit"] += len(reddit_posts)

        for post in reddit_posts:
            post_url = post.get("url", "")

            # Пропускаем уже обработанные URL
            if post_url and post_url in seen_urls:
                continue

            # Объединяем заголовок и тело для проверки
            full_text = f"{post.get('title', '')} {post.get('text', '')}"
            is_neg, matched_keyword = is_negative_mention(full_text)

            if not is_neg:
                if post_url:
                    seen_urls.add(post_url)
                continue

            totals["negative"] += 1

            event: dict[str, Any] = {
                "event_type": "forum_mention",
                "severity": "medium",
                "source_type": "osint",
                "source_name": "brand_monitor",
                "target_domain": domain,
                "payload": {
                    "platform": "reddit",
                    "title": post.get("title", "")[:_SNIPPET_MAX],
                    "url": post_url,
                    "matched_keyword": matched_keyword,
                    "sentiment": "negative",
                    "published_at": post.get("created_at", ""),
                },
            }

            if _send_ingest_event(ingest_url, ingest_headers, event):
                totals["sent"] += 1

            # Помечаем URL как обработанный независимо от успеха отправки
            if post_url:
                seen_urls.add(post_url)

        # Пауза между источниками
        time.sleep(_SOURCE_INTERVAL)

        # ── Hacker News ───────────────────────────────────────────────────────
        hn_posts = search_hackernews(keyword)
        totals["hn"] += len(hn_posts)

        for post in hn_posts:
            post_url = post.get("url", "")
            hn_id = post.get("hn_id", "")
            # Используем hn_id как уникальный ключ если URL нет
            cache_key = post_url or f"hn:{hn_id}"

            # Пропускаем уже обработанные
            if cache_key and cache_key in seen_urls:
                continue

            full_text = post.get("title", "")
            is_neg, matched_keyword = is_negative_mention(full_text)

            if not is_neg:
                if cache_key:
                    seen_urls.add(cache_key)
                continue

            totals["negative"] += 1

            event = {
                "event_type": "forum_mention",
                "severity": "medium",
                "source_type": "osint",
                "source_name": "brand_monitor",
                "target_domain": domain,
                "payload": {
                    "platform": "hackernews",
                    "title": post.get("title", "")[:_SNIPPET_MAX],
                    "url": post_url,
                    "matched_keyword": matched_keyword,
                    "sentiment": "negative",
                    "published_at": post.get("created_at", ""),
                },
            }

            if _send_ingest_event(ingest_url, ingest_headers, event):
                totals["sent"] += 1

            if cache_key:
                seen_urls.add(cache_key)

        # Пауза между итерациями keyword
        time.sleep(_SOURCE_INTERVAL)

    # Сохраняем обновлённый кэш
    _save_seen_urls(domain, seen_urls)

    logger.info(
        "[brand] Итого domain=%s reddit=%d hn=%d negative=%d sent=%d",
        domain,
        totals["reddit"],
        totals["hn"],
        totals["negative"],
        totals["sent"],
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
        name="workers.tasks.brand_monitor.monitor_brand_task",
    )
    def monitor_brand_task(
        self,
        domain: str,
        brand_keywords: list[str] | None = None,
    ) -> dict[str, int]:
        """Celery-задача: мониторинг упоминаний бренда в форумах."""
        try:
            return monitor_brand(
                domain=domain,
                brand_keywords=brand_keywords or [],
                core_api_url=_settings.CORE_API_URL,
                internal_secret=_settings.INTERNAL_API_SECRET,
            )
        except Exception as exc:
            raise self.retry(exc=exc)

except ImportError:
    # Celery не установлен — модуль используется без воркера (тесты, отдельный запуск)
    pass
