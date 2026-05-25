"""
Mobile App Monitoring — поиск приложений на App Store и Google Play.
Без официальных API — парсинг публичных поисковых endpoint'ов.

Алгоритм:
  1. Ищем приложения по brand_keywords на App Store (iTunes Search API)
  2. Ищем приложения на Google Play (graceful fallback при любой ошибке)
  3. Проверяем каждое приложение на подозрительность
  4. Отправляем события brand_abuse для подозрительных приложений
  5. Дедупликация по app_id: /tmp/mobile_seen_{safe_domain}.json
"""

import json
import logging
import re
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# Константы
# ──────────────────────────────────────────────

_TIMEOUT = httpx.Timeout(30.0)

# Директория для файлов дедупликации (monkeypatchable)
_BASELINE_DIR = Path("/tmp")

# Максимальная длина snippet в событии
_SNIPPET_MAX = 300

# Статусы Core API, которые считаются успешной доставкой
_INGEST_OK_STATUSES = frozenset({"accepted", "duplicate"})


# ──────────────────────────────────────────────
# Дедупликация
# ──────────────────────────────────────────────

def _get_seen_cache_path(domain: str) -> Path:
    """Возвращает путь к файлу дедупликации для домена."""
    safe = re.sub(r"[^\w]", "_", domain.lower())
    return _BASELINE_DIR / f"mobile_seen_{safe}.json"


def _load_seen_ids(domain: str) -> set[str]:
    """Загружает множество уже обработанных app_id из кэша."""
    cache_path = _get_seen_cache_path(domain)
    try:
        if cache_path.exists():
            data = json.loads(cache_path.read_text(encoding="utf-8"))
            return set(data) if isinstance(data, list) else set()
    except Exception as exc:
        logger.warning("[mobile] Ошибка чтения кэша %s: %s", cache_path, exc)
    return set()


_MAX_SEEN_IDS = 5000


def _save_seen_ids(domain: str, seen: set[str]) -> None:
    """Сохраняет множество обработанных app_id в кэш (не более _MAX_SEEN_IDS записей)."""
    cache_path = _get_seen_cache_path(domain)
    try:
        entries = sorted(seen)[-_MAX_SEEN_IDS:]
        cache_path.write_text(
            json.dumps(entries, ensure_ascii=False),
            encoding="utf-8",
        )
    except Exception as exc:
        logger.warning("[mobile] Ошибка записи кэша %s: %s", cache_path, exc)


# ──────────────────────────────────────────────
# App Store (iTunes Search API)
# ──────────────────────────────────────────────

def search_app_store(brand: str, limit: int = 10) -> list[dict[str, Any]]:
    """
    Поиск в App Store через iTunes Search API (публичный, без ключей).
    GET https://itunes.apple.com/search?term={brand}&entity=software&limit={limit}

    Возвращает список app с полями:
    - app_id, name, developer, bundle_id, url, rating, reviews, platform
    """
    url = "https://itunes.apple.com/search"
    params = {"term": brand, "entity": "software", "limit": limit, "country": "us"}
    try:
        resp = httpx.get(url, params=params, timeout=_TIMEOUT)
        resp.raise_for_status()
        results = resp.json().get("results", [])
        return [
            {
                "app_id": str(r.get("trackId", "")),
                "name": r.get("trackName", ""),
                "developer": r.get("artistName", ""),
                "bundle_id": r.get("bundleId", ""),
                "url": r.get("trackViewUrl", ""),
                "rating": r.get("averageUserRating", 0),
                "reviews": r.get("userRatingCount", 0),
                "platform": "app_store",
            }
            for r in results
        ]
    except Exception as e:
        logger.warning("[mobile] App Store search error: %s", e)
        return []


# ──────────────────────────────────────────────
# Google Play
# ──────────────────────────────────────────────

def search_google_play(brand: str) -> list[dict[str, Any]]:
    """
    Поиск в Google Play через публичный search endpoint.
    GET https://play.google.com/store/search?q={brand}&c=apps

    Парсим JSON-блок из HTML-ответа (паттерн google_play_scraper).
    Graceful fallback: возвращаем пустой список при любой ошибке.
    """
    url = "https://play.google.com/store/search"
    params = {"q": brand, "c": "apps", "hl": "en", "gl": "us"}
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
    }
    try:
        resp = httpx.get(url, params=params, headers=headers, timeout=_TIMEOUT)
        if resp.status_code != 200:
            logger.warning("[mobile] Google Play HTTP %d для '%s'", resp.status_code, brand)
            return []

        html = resp.text

        # Ищем JSON-блоки с данными приложений в структуре Google Play HTML
        # Паттерн: AF_initDataCallback({key: 'ds:3', ... data:[ ... ]})
        apps: list[dict[str, Any]] = []

        # Ищем package ids по известному паттерну URLs
        # /store/apps/details?id=com.example.app
        pkg_pattern = re.compile(r'/store/apps/details\?id=([\w.]+)')
        found_ids = pkg_pattern.findall(html)

        # Ищем названия рядом с pkg_id (упрощённый эвристический парсинг)
        name_pattern = re.compile(r'data-docid="([\w.]+)"[^>]*>.*?<span[^>]*>(.*?)</span>', re.DOTALL)

        # Если нашли хотя бы package ids — формируем базовые записи
        seen_pkg: set[str] = set()
        for pkg_id in found_ids[:10]:
            if pkg_id in seen_pkg:
                continue
            seen_pkg.add(pkg_id)
            apps.append({
                "app_id": pkg_id,
                "name": pkg_id,  # название без детального парсинга
                "developer": "",
                "bundle_id": pkg_id,
                "url": f"https://play.google.com/store/apps/details?id={pkg_id}",
                "rating": 0,
                "reviews": 0,
                "platform": "google_play",
            })

        logger.debug("[mobile] Google Play: найдено %d приложений для '%s'", len(apps), brand)
        return apps

    except Exception as e:
        logger.warning("[mobile] Google Play search error для '%s': %s", brand, e)
        return []


# ──────────────────────────────────────────────
# Детекция подозрительных приложений
# ──────────────────────────────────────────────

def is_suspicious_app(
    app: dict[str, Any],
    official_developer: str,
    brand: str,
) -> tuple[bool, str]:
    """
    Проверяет подозрительность приложения.

    Критерии:
    - Название содержит brand, но developer != official_developer → suspicious
    - bundle_id содержит brand (нижний регистр), но developer другой → suspicious
    - Рейтинг < 2.0 с упоминанием brand в названии → suspicious

    Аргументы:
        app: словарь с данными приложения (поля: name, developer, bundle_id, rating)
        official_developer: ожидаемое имя разработчика (если пустое — проверку пропускаем)
        brand: ключевое слово бренда

    Возвращает:
        (True, "reason") если подозрительно
        (False, "") если нормально
    """
    name = app.get("name", "")
    developer = app.get("developer", "")
    bundle_id = app.get("bundle_id", "")
    rating = float(app.get("rating") or 0)

    brand_lower = brand.lower()
    name_lower = name.lower()
    bundle_lower = bundle_id.lower()

    name_has_brand = brand_lower in name_lower
    bundle_has_brand = brand_lower in bundle_lower

    # Если official_developer задан — проверяем несоответствие
    if official_developer:
        dev_matches = developer.lower() == official_developer.lower()

        if name_has_brand and not dev_matches:
            return True, f"название содержит '{brand}', но разработчик '{developer}' != '{official_developer}'"

        if bundle_has_brand and not dev_matches:
            return True, f"bundle_id содержит '{brand}', но разработчик '{developer}' != '{official_developer}'"

    # Низкий рейтинг + упоминание бренда в названии
    if name_has_brand and 0 < rating < 2.0:
        return True, f"низкий рейтинг {rating:.1f} для приложения с '{brand}' в названии"

    return False, ""


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
    Возвращает True если Core API подтвердил приём.
    """
    try:
        r = httpx.post(ingest_url, json=event, headers=headers, timeout=_TIMEOUT)
        status_val: str = r.json().get("status", "error")
        return status_val in _INGEST_OK_STATUSES
    except Exception as exc:
        logger.error("[mobile] Ошибка отправки события в Core API: %s", exc)
        return False


# ──────────────────────────────────────────────
# Основная функция мониторинга
# ──────────────────────────────────────────────

def monitor_mobile_apps(
    domain: str,
    brand_keywords: list[str],
    official_developer: str | None,
    core_api_url: str,
    internal_secret: str,
) -> dict[str, Any]:
    """
    Основной мониторинг мобильных приложений.

    1. Ищет приложения на App Store и Google Play по brand_keywords
    2. Проверяет каждое приложение на suspicious
    3. Генерирует события для suspicious apps
    4. Дедупликация по app_id: /tmp/mobile_seen_{safe_domain}.json

    Аргументы:
        domain: домен актива (например "example.com")
        brand_keywords: список ключевых слов для поиска
        official_developer: имя официального разработчика (None — не проверяем)
        core_api_url: базовый URL Core API
        internal_secret: внутренний секрет для ingest

    Возвращает:
        {"app_store": N, "google_play": N, "suspicious": N, "sent": N}
    """
    domain = domain.strip().lower()
    dev = official_developer.strip() if official_developer else ""

    ingest_url = f"{core_api_url}/api/v1/internal/ingest"
    ingest_headers: dict[str, str] = {"Authorization": f"Bearer {internal_secret}"}

    # Загружаем кэш уже обработанных app_id
    seen_ids = _load_seen_ids(domain)

    totals: dict[str, Any] = {
        "app_store": 0,
        "google_play": 0,
        "suspicious": 0,
        "sent": 0,
    }

    # Если ключевых слов нет — берём домен без TLD
    if not brand_keywords:
        parts = domain.split(".")
        kw = ".".join(parts[:-1]) if len(parts) > 1 else domain
        keywords = [kw]
    else:
        keywords = list(brand_keywords)

    for keyword in keywords:
        logger.info("[mobile] Поиск по ключевому слову '%s' для домена '%s'", keyword, domain)

        # ── App Store ─────────────────────────────────────────────────────────
        as_apps = search_app_store(keyword)
        totals["app_store"] += len(as_apps)

        for app in as_apps:
            app_id = app.get("app_id", "")
            cache_key = f"as:{app_id}"

            if cache_key in seen_ids:
                continue

            suspicious, reason = is_suspicious_app(app, dev, keyword)

            if suspicious:
                totals["suspicious"] += 1
                event: dict[str, Any] = {
                    "event_type": "brand_abuse",
                    "severity": "high",
                    "source_type": "osint",
                    "source_name": "mobile_monitor",
                    "target_domain": domain,
                    "payload": {
                        "platform": "app_store",
                        "app_id": app_id,
                        "app_name": app.get("name", "")[:_SNIPPET_MAX],
                        "developer": app.get("developer", ""),
                        "url": app.get("url", ""),
                        "reason": reason,
                    },
                }
                if _send_ingest_event(ingest_url, ingest_headers, event):
                    totals["sent"] += 1

            seen_ids.add(cache_key)

        # ── Google Play ───────────────────────────────────────────────────────
        gp_apps = search_google_play(keyword)
        totals["google_play"] += len(gp_apps)

        for app in gp_apps:
            app_id = app.get("app_id", "")
            cache_key = f"gp:{app_id}"

            if cache_key in seen_ids:
                continue

            suspicious, reason = is_suspicious_app(app, dev, keyword)

            if suspicious:
                totals["suspicious"] += 1
                event = {
                    "event_type": "brand_abuse",
                    "severity": "high",
                    "source_type": "osint",
                    "source_name": "mobile_monitor",
                    "target_domain": domain,
                    "payload": {
                        "platform": "google_play",
                        "app_id": app_id,
                        "app_name": app.get("name", "")[:_SNIPPET_MAX],
                        "developer": app.get("developer", ""),
                        "url": app.get("url", ""),
                        "reason": reason,
                    },
                }
                if _send_ingest_event(ingest_url, ingest_headers, event):
                    totals["sent"] += 1

            seen_ids.add(cache_key)

    # Сохраняем обновлённый кэш
    _save_seen_ids(domain, seen_ids)

    logger.info(
        "[mobile] Итого domain=%s app_store=%d google_play=%d suspicious=%d sent=%d",
        domain,
        totals["app_store"],
        totals["google_play"],
        totals["suspicious"],
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
        name="workers.tasks.mobile_monitor.monitor_mobile_apps_task",
    )
    def monitor_mobile_apps_task(
        self,
        domain: str,
        brand_keywords: list[str] | None = None,
        official_developer: str | None = None,
    ) -> dict[str, Any]:
        """Celery-задача: мониторинг мобильных приложений."""
        try:
            return monitor_mobile_apps(
                domain=domain,
                brand_keywords=brand_keywords or [],
                official_developer=official_developer,
                core_api_url=_settings.CORE_API_URL,
                internal_secret=_settings.INTERNAL_API_SECRET,
            )
        except Exception as exc:
            raise self.retry(exc=exc)

except ImportError:
    # Celery не установлен — модуль используется без воркера (тесты, отдельный запуск)
    pass
