"""
Воркер мониторинга даркнета на упоминания домена.

Источники (clearweb-индексаторы, Tor не нужен):
  1. Ahmia.fi   — публичный поисковик по .onion (HTML-парсинг)
  2. DarkSearch — публичный JSON API (darksearch.io)
  3. RansomWatch — агрегатор постов всех известных ransomware-групп (JSON API)
     https://ransomwatch.telemetry.ltd/api/posts.json
     Это наиболее критичный источник: наличие домена здесь = активная атака

Источники (требуют Tor или внешний API):
  4. ransomware_sites — прямые .onion-сайты ransomware-группировок через Tor
     Парсит LockBit, ALPHV/BlackCat, Play, Clop, RansomHub, Akira и др.
     Если Tor недоступен — gracefully пропускается без ошибки
  5. IntelX.io — поисковик по даркнету, пастам и архивам утечек
     Публичный phonebook API (без ключа, лимит 5 результатов)

Принципы:
  - Каждый источник изолирован try/except: сбой одного не прерывает остальные
  - RansomWatch кэшируется 1 час — он возвращает весь архив разом (~мегабайты)
  - Snippet обрезается до 500 символов согласно спецификации
  - ransomwatch + ransomware_sites → severity "critical", остальные → "high"
  - Нормализация домена: strip + lower перед поиском
  - Tor-источники: graceful degradation при недоступности Tor
"""
import logging
import re
import time
from typing import Any

import httpx

from workers.tasks.bulk_ingest import bulk_ingest

# Новые источники мониторинга — импорт опциональный (graceful degradation)
try:
    from tasks.ransomware_sites import monitor_ransomware_sites as _monitor_ransomware_sites
    _RANSOMWARE_SITES_AVAILABLE = True
except ImportError:
    _RANSOMWARE_SITES_AVAILABLE = False

try:
    from tasks.intelx_api import search_intelx as _search_intelx
    _INTELX_AVAILABLE = True
except ImportError:
    _INTELX_AVAILABLE = False

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# Константы
# ──────────────────────────────────────────────

# Ahmia — публичный clearweb-прокси к .onion-поисковику
AHMIA_SEARCH_URL = "https://ahmia.fi/search/"

# DarkSearch — публичный JSON API, до 10 бесплатных запросов/мин
DARKSEARCH_SEARCH_URL = "https://darksearch.io/api/search"

# RansomWatch — агрегатор постов ransomware-групп, публичный JSON
RANSOMWATCH_POSTS_URL = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"

# TTL кэша RansomWatch в секундах (1 час)
_RANSOMWATCH_CACHE_TTL = 3600

# Максимальная длина snippet в payload (по спецификации — 500 символов)
SNIPPET_MAX_LEN = 500

# Таймаут HTTP-запросов
HTTP_TIMEOUT = 20.0

# User-Agent чтобы не блокировали как curl
_USER_AGENT = (
    "Mozilla/5.0 (compatible; EASM-DarknetMonitor/1.0; +https://github.com/easm)"
)

# Статусы Core API, которые считаются успешной доставкой
_INGEST_OK_STATUSES = frozenset({"accepted", "duplicate"})

# ──────────────────────────────────────────────
# Кэш RansomWatch (модульный синглтон)
# ──────────────────────────────────────────────

_RANSOMWATCH_CACHE: dict[str, Any] = {
    "data": None,       # list[dict] | None
    "fetched_at": 0.0,  # unix timestamp последней загрузки
}


# ──────────────────────────────────────────────
# Утилиты
# ──────────────────────────────────────────────

def _truncate_snippet(text: str) -> str:
    """Обрезает текст до SNIPPET_MAX_LEN символов."""
    return text[:SNIPPET_MAX_LEN]


def _make_headers() -> dict[str, str]:
    """Возвращает базовые HTTP-заголовки для исходящих запросов."""
    return {
        "User-Agent": _USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
    }


def _send_event(
    ingest_url: str,
    headers: dict[str, str],
    event: dict[str, Any],
) -> bool:
    """
    Отправляет событие в Core API через POST /internal/ingest.
    Возвращает True если доставка подтверждена (accepted или duplicate).
    Изолирована от исключений — не поднимает ошибки наружу.
    """
    try:
        r = httpx.post(ingest_url, json=event, headers=headers, timeout=HTTP_TIMEOUT)
        status_val: str = r.json().get("status", "error")
        return status_val in _INGEST_OK_STATUSES
    except Exception as exc:
        logger.error("[darknet] Ошибка отправки события в Core API: %s", exc)
        return False


# ──────────────────────────────────────────────
# Источник 1: Ahmia.fi
# ──────────────────────────────────────────────

# Паттерны для парсинга HTML-результатов Ahmia
_AHMIA_TITLE_RE = re.compile(r'<h4>\s*(.*?)\s*</h4>', re.IGNORECASE | re.DOTALL)
_AHMIA_LINK_RE = re.compile(r'href="(https?://ahmia\.fi/redirect/\?search_term=[^"]+)"', re.IGNORECASE)
_AHMIA_ONION_RE = re.compile(r'([a-z2-7]{56}\.onion[^\s"<]*)', re.IGNORECASE)
_AHMIA_SNIPPET_RE = re.compile(
    r'<p[^>]*class="[^"]*result-content[^"]*"[^>]*>(.*?)</p>',
    re.IGNORECASE | re.DOTALL,
)
_HTML_TAG_RE = re.compile(r'<[^>]+>')


def _strip_html(text: str) -> str:
    """Удаляет HTML-теги из текста."""
    return _HTML_TAG_RE.sub('', text).strip()


def search_ahmia(domain: str) -> list[dict[str, Any]]:
    """
    Ищет упоминания домена в индексе Ahmia.fi (clearweb-интерфейс к .onion).

    Парсит HTML-страницу результатов, так как Ahmia не предоставляет
    стабильного JSON API для публичного использования.

    Возвращает: [{"title": str, "url": str, "onion": str, "snippet": str}]
    При любой ошибке возвращает [] и логирует предупреждение.
    """
    results: list[dict[str, Any]] = []
    try:
        r = httpx.get(
            AHMIA_SEARCH_URL,
            params={"q": domain},
            headers=_make_headers(),
            timeout=HTTP_TIMEOUT,
            follow_redirects=True,
        )
        if r.status_code != 200:
            logger.warning("[darknet][ahmia] HTTP %d для домена %s", r.status_code, domain)
            return []

        html = r.text

        # Ищем блоки результатов — каждый содержит заголовок, ссылку и сниппет
        titles = _AHMIA_TITLE_RE.findall(html)
        links = _AHMIA_LINK_RE.findall(html)
        snippets = _AHMIA_SNIPPET_RE.findall(html)
        onion_urls = _AHMIA_ONION_RE.findall(html)

        # Объединяем по индексу — количество элементов может не совпадать,
        # берём максимум по заголовкам (самый надёжный индикатор результата)
        for i, title in enumerate(titles):
            clean_title = _strip_html(title)
            url = links[i] if i < len(links) else ""
            snippet = _truncate_snippet(_strip_html(snippets[i])) if i < len(snippets) else ""
            onion = onion_urls[i] if i < len(onion_urls) else ""

            # Фильтруем нерелевантные результаты — домен должен присутствовать
            # либо в URL/onion, либо в snippet/title
            combined_text = (clean_title + snippet + url + onion).lower()
            if domain.lower() not in combined_text:
                continue

            results.append({
                "title": clean_title,
                "url": url,
                "onion": onion,
                "snippet": snippet,
            })

    except Exception as exc:
        logger.warning("[darknet][ahmia] Ошибка запроса к ahmia.fi: %s", exc)

    logger.info("[darknet][ahmia] domain=%s found=%d", domain, len(results))
    return results


# ──────────────────────────────────────────────
# Источник 2: DarkSearch.io
# ──────────────────────────────────────────────

def search_darksearch(domain: str) -> list[dict[str, Any]]:
    """
    Ищет упоминания домена через публичный JSON API DarkSearch.io.

    API возвращает: {"data": [{"title": "", "description": "", "link": "", "onion": ""}]}
    Не требует API-ключа для базовых запросов (лимит ~10 req/мин).

    Возвращает: [{"title": str, "url": str, "onion": str, "snippet": str}]
    При любой ошибке возвращает [] и логирует предупреждение.
    """
    results: list[dict[str, Any]] = []
    try:
        r = httpx.get(
            DARKSEARCH_SEARCH_URL,
            params={"query": f'"{domain}"', "page": 1},
            headers=_make_headers(),
            timeout=HTTP_TIMEOUT,
        )
        if r.status_code != 200:
            logger.warning("[darknet][darksearch] HTTP %d для домена %s", r.status_code, domain)
            return []

        data = r.json()
        items: list[dict[str, Any]] = data.get("data", [])

        for item in items:
            description = item.get("description", "") or ""
            title = item.get("title", "") or ""
            link = item.get("link", "") or ""
            onion = item.get("onion", "") or link  # link часто и есть .onion URL

            results.append({
                "title": _strip_html(title),
                "url": link,
                "onion": onion,
                "snippet": _truncate_snippet(_strip_html(description)),
            })

    except Exception as exc:
        logger.warning("[darknet][darksearch] Ошибка запроса к darksearch.io: %s", exc)

    logger.info("[darknet][darksearch] domain=%s found=%d", domain, len(results))
    return results


# ──────────────────────────────────────────────
# Источник 3: RansomWatch (агрегатор ransomware-групп)
# ──────────────────────────────────────────────

def _fetch_ransomwatch_posts() -> list[dict[str, Any]]:
    """
    Загружает все посты RansomWatch с кэшированием на _RANSOMWATCH_CACHE_TTL секунд.

    RansomWatch возвращает весь архив за один запрос (~несколько MB JSON),
    поэтому кэш обязателен для предотвращения избыточных запросов.

    Возвращает список постов или [] при ошибке.
    Thread-safety: обновление кэша не атомарно, допустимо дублирование
    запросов при параллельных вызовах — это приемлемо для данного use-case.
    """
    now = time.time()
    age = now - _RANSOMWATCH_CACHE["fetched_at"]

    if _RANSOMWATCH_CACHE["data"] is not None and age < _RANSOMWATCH_CACHE_TTL:
        logger.debug("[darknet][ransomwatch] Кэш актуален (возраст %.0f с)", age)
        return _RANSOMWATCH_CACHE["data"]  # type: ignore[return-value]

    logger.info("[darknet][ransomwatch] Загружаем свежие данные из API")
    try:
        r = httpx.get(
            RANSOMWATCH_POSTS_URL,
            headers=_make_headers(),
            timeout=HTTP_TIMEOUT,
        )
        if r.status_code != 200:
            logger.warning("[darknet][ransomwatch] HTTP %d", r.status_code)
            return []

        posts: list[dict[str, Any]] = r.json()
        if not isinstance(posts, list):
            logger.warning("[darknet][ransomwatch] Неожиданный формат ответа: %s", type(posts))
            return []

        # Обновляем кэш
        _RANSOMWATCH_CACHE["data"] = posts
        _RANSOMWATCH_CACHE["fetched_at"] = now
        logger.info("[darknet][ransomwatch] Загружено %d постов, кэш обновлён", len(posts))
        return posts

    except Exception as exc:
        logger.warning("[darknet][ransomwatch] Ошибка загрузки: %s", exc)
        return []


def check_ransomwatch(domain: str) -> list[dict[str, Any]]:
    """
    Проверяет наличие домена в постах ransomware-группировок через RansomWatch.

    Поиск case-insensitive по полям: post_title + description.
    Матч = подтверждённая или готовящаяся публикация украденных данных.

    Поля поста RansomWatch: group_name, post_title, published, description
    (структура может незначительно меняться — используем .get() с fallback).

    Возвращает: [{"group": str, "title": str, "published": str, "snippet": str}]
    """
    posts = _fetch_ransomwatch_posts()
    if not posts:
        return []

    domain_lower = domain.lower()
    matches: list[dict[str, Any]] = []

    for post in posts:
        title = str(post.get("post_title", "") or post.get("title", "") or "")
        description = str(post.get("description", "") or "")
        group = str(post.get("group_name", "") or post.get("group", "") or "unknown")
        published = str(post.get("published", "") or post.get("added", "") or "")

        # Проверяем наличие домена в заголовке и описании (case-insensitive)
        combined = (title + " " + description).lower()
        if domain_lower not in combined:
            continue

        # Формируем snippet из описания с фокусом на контекст вокруг домена
        snippet_src = description if domain_lower in description.lower() else title
        idx = snippet_src.lower().find(domain_lower)
        if idx >= 0:
            start = max(0, idx - 100)
            end = min(len(snippet_src), idx + len(domain) + 400)
            raw_snippet = snippet_src[start:end]
        else:
            raw_snippet = snippet_src

        matches.append({
            "group": group,
            "title": title,
            "published": published,
            "snippet": _truncate_snippet(raw_snippet),
        })

    logger.info("[darknet][ransomwatch] domain=%s found=%d", domain, len(matches))
    return matches


# ──────────────────────────────────────────────
# Агрегирующая функция
# ──────────────────────────────────────────────

def monitor_darknet(
    domain: str,
    core_api_url: str,
    internal_secret: str,
) -> dict[str, int]:
    """
    Запускает все источники мониторинга даркнета последовательно.

    7.B.4: события накапливаются в батч и отправляются одним bulk POST
    вместо N×HTTP (по одному на событие).
    """
    domain = domain.strip().lower()
    logger.info("[darknet] Начало мониторинга domain=%s", domain)

    sources_checked = found = critical = 0
    tor_skipped = False
    events_batch: list[dict[str, Any]] = []

    # ── Источник 1: RansomWatch (критический) ─────────────────────────────────
    try:
        rw_results = check_ransomwatch(domain)
        sources_checked += 1
        found += len(rw_results)
        for hit in rw_results:
            events_batch.append({
                "event_type": "darknet_mention",
                "severity": "critical",
                "source_type": "darknet",
                "source_name": "ransomwatch",
                "target_domain": domain,
                "payload": {
                    "source": "ransomwatch",
                    "group": hit["group"],
                    "onion_url": "",
                    "title": hit["title"],
                    "snippet": hit["snippet"],
                    "published": hit["published"],
                },
            })
            critical += 1
    except Exception as exc:
        logger.error("[darknet][ransomwatch] Неожиданная ошибка: %s", exc)

    # ── Источник 2: Ahmia.fi ──────────────────────────────────────────────────
    try:
        ahmia_results = search_ahmia(domain)
        sources_checked += 1
        found += len(ahmia_results)
        for hit in ahmia_results:
            events_batch.append({
                "event_type": "darknet_mention",
                "severity": "high",
                "source_type": "darknet",
                "source_name": "ahmia",
                "target_domain": domain,
                "payload": {
                    "source": "ahmia",
                    "group": "",
                    "onion_url": hit["onion"],
                    "title": hit["title"],
                    "snippet": hit["snippet"],
                },
            })
    except Exception as exc:
        logger.error("[darknet][ahmia] Неожиданная ошибка: %s", exc)

    # ── Источник 3: DarkSearch ────────────────────────────────────────────────
    try:
        ds_results = search_darksearch(domain)
        sources_checked += 1
        found += len(ds_results)
        for hit in ds_results:
            events_batch.append({
                "event_type": "darknet_mention",
                "severity": "high",
                "source_type": "darknet",
                "source_name": "darksearch",
                "target_domain": domain,
                "payload": {
                    "source": "darksearch",
                    "group": "",
                    "onion_url": hit["onion"],
                    "title": hit["title"],
                    "snippet": hit["snippet"],
                },
            })
    except Exception as exc:
        logger.error("[darknet][darksearch] Неожиданная ошибка: %s", exc)

    # ── Источник 4: Ransomware Sites (через Tor, опциональный) ───────────────
    if _RANSOMWARE_SITES_AVAILABLE:
        try:
            rw_sites_result = _monitor_ransomware_sites(
                domain=domain,
                core_api_url=core_api_url,
                internal_secret=internal_secret,
            )
            sources_checked += 1
            if rw_sites_result.get("tor_required"):
                tor_skipped = True
                logger.info("[darknet][ransomware_sites] Tor недоступен, источник пропущен")
            else:
                # ransomware_sites сам отправляет через свой ingest — учитываем только счётчики
                group_found = rw_sites_result.get("found", 0)
                group_sent = rw_sites_result.get("sent", 0)
                found += group_found
                critical += group_sent
                logger.info(
                    "[darknet][ransomware_sites] domain=%s found=%d sent=%d",
                    domain, group_found, group_sent,
                )
        except Exception as exc:
            logger.error("[darknet][ransomware_sites] Неожиданная ошибка: %s", exc)
    else:
        logger.debug("[darknet][ransomware_sites] Модуль недоступен (ImportError)")

    # ── Источник 5: IntelX.io (clearnet, всегда доступен) ────────────────────
    if _INTELX_AVAILABLE:
        try:
            intelx_result = _search_intelx(
                domain=domain,
                core_api_url=core_api_url,
                internal_secret=internal_secret,
            )
            sources_checked += 1
            ix_found = intelx_result.get("found", 0)
            ix_sent = intelx_result.get("sent", 0)
            found += ix_found
            logger.info(
                "[darknet][intelx] domain=%s found=%d sent=%d mode=%s",
                domain, ix_found, ix_sent, intelx_result.get("mode", "?"),
            )
        except Exception as exc:
            logger.error("[darknet][intelx] Неожиданная ошибка: %s", exc)
    else:
        logger.debug("[darknet][intelx] Модуль недоступен (ImportError)")

    # 7.B.4: Отправляем весь батч одним запросом
    result = bulk_ingest(events_batch, core_api_url, internal_secret)
    sent = result["sent"]

    logger.info(
        "[darknet] Итого domain=%s sources=%d found=%d sent=%d critical=%d tor_skipped=%s",
        domain, sources_checked, found, sent, critical, tor_skipped,
    )
    return {
        "sources_checked": sources_checked,
        "found": found,
        "sent": sent,
        "critical": critical,
        "tor_skipped": tor_skipped,
    }


# ── Celery-обёртка ────────────────────────────────────────────────────────────

try:
    from workers.celery_app import app as _celery_app
    from workers.config import settings as _settings

    @_celery_app.task(
        bind=True,
        max_retries=2,
        default_retry_delay=600,
        name="workers.tasks.darknet_monitor.monitor_darknet_task",
    )
    def monitor_darknet_task(self, domain: str) -> dict:
        """
        Celery-задача: мониторинг даркнета на упоминания домена.
        Использует CORE_API_URL и INTERNAL_API_SECRET из конфигурации воркера.
        """
        try:
            return monitor_darknet(
                domain=domain,
                core_api_url=_settings.CORE_API_URL,
                internal_secret=_settings.INTERNAL_API_SECRET,
            )
        except Exception as exc:
            raise self.retry(exc=exc)

except ImportError:
    # Celery не установлен — модуль используется без воркера (тесты и т.д.)
    pass
