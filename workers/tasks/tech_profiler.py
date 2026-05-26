"""
Воркер: Technology Profiling — определение технологий и End-of-Life ПО (задача 10.A).

Анализирует HTTP-ответ домена: заголовки, куки, тело страницы.
Сравнивает с базой сигнатур (30+ технологий).
Извлекает версии и проверяет их по базе EOL (End-of-Life).
Результат отправляет в Core API через bulk_ingest.
"""
import logging
import re
from datetime import datetime, timezone
from typing import Any

import httpx

from workers.tasks.bulk_ingest import bulk_ingest

logger = logging.getLogger(__name__)

# Таймаут HTTP-запроса (секунды)
_HTTP_TIMEOUT = 10.0

# User-Agent как обычный браузер — снижает вероятность блокировки по WAF
_USER_AGENT = "Mozilla/5.0 (compatible; EASM-TechProfiler/1.0)"


# ──────────────────────────────────────────────────────────────────────────────
# База сигнатур технологий
# ──────────────────────────────────────────────────────────────────────────────
#
# Каждая запись — словарь с необязательными ключами:
#   "headers"  — dict {имя_заголовка: regex_паттерн}
#   "cookies"  — set  {имя_куки, ...} (присутствие куки — признак технологии)
#   "body"     — regex_паттерн для поиска в теле ответа
#
# Для извлечения версии в regex можно использовать группу захвата (\d+\.\d+).

_SIGNATURES: dict[str, dict[str, Any]] = {
    # ── CMS ──────────────────────────────────────────────────────────────────
    "WordPress": {
        "headers": {"X-Powered-By": r"PHP"},
        "cookies": {"wordpress_logged_in", "wp-settings-1"},
        "body": r"wp-content/|wordpress",
    },
    "Drupal": {
        "headers": {"X-Generator": r"Drupal"},
        "body": r"sites/default/files|Drupal\.settings",
    },
    "Joomla": {
        "body": r"/administrator/|Joomla!",
    },
    "Bitrix": {
        "cookies": {"BITRIX_SM_UIDH", "BX_USER_ID"},
        "body": r"bitrix/js|bitrix/components",
    },
    "Magento": {
        "cookies": {"frontend", "adminhtml"},
        "body": r"Mage\.Cookies|mage/cookies",
    },
    "Shopify": {
        "headers": {
            "X-ShopId": r".+",
            "X-StorefrontAccessToken": r".+",
        },
        "body": r"cdn\.shopify\.com|Shopify\.theme",
    },
    # ── Фреймворки серверного рендеринга ─────────────────────────────────────
    "Laravel": {
        "cookies": {"laravel_session"},
        "headers": {"X-Powered-By": r"PHP"},
        "body": r"laravel_token|laravel\.js",
    },
    "Django": {
        "cookies": {"csrftoken", "sessionid"},
        "headers": {"X-Frame-Options": r"SAMEORIGIN"},
    },
    "Rails": {
        "cookies": {"_rails_session"},
        "headers": {"X-Content-Type-Options": r"nosniff"},
    },
    "ASP.NET": {
        "headers": {
            "X-Powered-By": r"ASP\.NET",
            "X-AspNet-Version": r".+",
        },
        "cookies": {"ASP.NET_SessionId", "ASPXAUTH"},
    },
    "Spring Boot": {
        "body": r"Whitelabel Error Page|Spring Framework",
    },
    "Flask": {
        "cookies": {"session"},
        "headers": {"Server": r"Werkzeug"},
    },
    # ── Фронтенд-фреймворки ──────────────────────────────────────────────────
    "Next.js": {
        "headers": {"X-Powered-By": r"Next\.js"},
        "body": r"__NEXT_DATA__|_next/static",
    },
    "React": {
        "body": r"react(?:\.min)?\.js|__REACT_DEVTOOLS|react-dom",
    },
    "Vue.js": {
        "body": r"vue(?:\.min)?\.js|__vue__|Vue\.version",
    },
    "Angular": {
        "body": r"ng-version=|angular(?:\.min)?\.js|@angular/core",
    },
    "Svelte": {
        "body": r"__svelte|svelte/internal",
    },
    "Nuxt.js": {
        "body": r"__NUXT__|_nuxt/",
    },
    # ── Веб-серверы ──────────────────────────────────────────────────────────
    "Nginx": {
        "headers": {"Server": r"nginx(?:/(\d+\.\d+))?"},
    },
    "Apache": {
        "headers": {"Server": r"Apache(?:/(\d+\.\d+))?"},
    },
    "IIS": {
        "headers": {"Server": r"IIS/(\d+\.\d+)|Microsoft-IIS"},
    },
    "LiteSpeed": {
        "headers": {"Server": r"LiteSpeed"},
    },
    "Caddy": {
        "headers": {"Server": r"Caddy"},
    },
    # ── Языки / рантаймы ─────────────────────────────────────────────────────
    "PHP": {
        "headers": {"X-Powered-By": r"PHP/(\d+\.\d+)"},
    },
    "Express.js": {
        "headers": {"X-Powered-By": r"Express"},
    },
    # ── CDN / WAF / прокси ───────────────────────────────────────────────────
    "Cloudflare": {
        "headers": {
            "CF-RAY": r".+",
            "Server": r"cloudflare",
        },
    },
    "AWS CloudFront": {
        "headers": {
            "Via": r"cloudfront",
            "X-Amz-Cf-Id": r".+",
        },
    },
    "Varnish": {
        "headers": {
            "X-Varnish": r".+",
            "Via": r"varnish",
        },
    },
    "Fastly": {
        "headers": {
            "Fastly-Debug-Digest": r".+",
            "Via": r"1\.\d Varnish.*fastly",
        },
    },
    "Akamai": {
        "headers": {"X-Akamai-Transformed": r".+"},
    },
    # ── DevOps-инструменты / SaaS ─────────────────────────────────────────────
    "WordPress VIP": {
        "headers": {"X-Hacker": r".+VIP"},
    },
    "GitLab": {
        "headers": {"X-GitLab-Meta": r".+"},
        "body": r"gitlab-logo|GitLab",
    },
    "Jenkins": {
        "headers": {"X-Jenkins": r".+"},
        "body": r"Jenkins(?:\s+ver\.)?|hudson\.model",
    },
    "Confluence": {
        "headers": {"X-Confluence-Request-Time": r".+"},
        "body": r"Confluence",
    },
    "Jira": {
        "body": r'JIRA|<span id="logo-text"',
    },
    "Kibana": {
        "body": r"kbnVersion|kibana",
    },
    "Grafana": {
        "headers": {"X-Grafana-Theme": r".+"},
        "body": r"grafana(?:\.js)?",
    },
    "Kubernetes API": {
        "body": r'"apiVersion":',
        "headers": {"Content-Type": r"application/json"},
    },
}


# ──────────────────────────────────────────────────────────────────────────────
# База End-of-Life версий (упрощённая)
# ──────────────────────────────────────────────────────────────────────────────
#
# Ключ: технология. Значение: словарь {версия_префикс: дата_EOL_ISO или None}.
# None = технология ещё поддерживается.

_EOL_VERSIONS: dict[str, dict[str, str | None]] = {
    "PHP": {
        "5.6": "2018-12-31",
        "7.0": "2019-12-03",
        "7.1": "2019-12-01",
        "7.2": "2020-11-30",
        "7.3": "2021-12-06",
        "7.4": "2022-11-28",
        "8.0": "2023-11-26",
        "8.1": "2025-12-31",  # активная поддержка до 2025-12-31
        "8.2": None,
        "8.3": None,
    },
    "Nginx": {
        "1.14": "2019-04-23",
        "1.16": "2020-04-20",
        "1.18": "2022-06-13",
        "1.20": "2023-05-23",
        "1.22": None,
        "1.24": None,
        "1.26": None,
    },
    "Apache": {
        "2.2": "2017-07-11",
        "2.4": None,   # всё ещё поддерживается
    },
    "IIS": {
        "6.0": "2015-07-14",
        "7.0": "2015-01-13",
        "7.5": "2015-01-13",
        "8.0": "2016-01-12",
        "8.5": None,
        "10.0": None,
    },
}


# ──────────────────────────────────────────────────────────────────────────────
# Вспомогательные функции
# ──────────────────────────────────────────────────────────────────────────────

def _extract_version(header_value: str, pattern: str) -> str | None:
    """
    Пытается извлечь версию из значения заголовка по паттерну.

    Ищет группу захвата вида (digits+.digits+) в паттерне.
    Если группа не определена — возвращает None.
    """
    try:
        m = re.search(pattern, header_value, re.IGNORECASE)
        if m and m.lastindex:
            return m.group(1)
    except re.error:
        pass
    return None


def _check_eol(tech_name: str, version: str | None) -> tuple[bool, str | None]:
    """
    Проверяет, находится ли версия технологии на End-of-Life.

    Возвращает (is_eol, eol_date_str).
    is_eol = True, если дата EOL уже наступила (сравниваем с today).
    eol_date_str = дата EOL в ISO-формате или None.
    """
    if version is None or tech_name not in _EOL_VERSIONS:
        return False, None

    eol_map = _EOL_VERSIONS[tech_name]
    today = datetime.now(timezone.utc).date()

    # Ищем совпадение по префиксу версии (например "7.4" совпадёт с "7.4.33")
    for prefix, eol_date in eol_map.items():
        if version.startswith(prefix):
            if eol_date is None:
                # Версия всё ещё поддерживается
                return False, None
            # Сравниваем с today
            try:
                eol_dt = datetime.fromisoformat(eol_date).date()
                if today >= eol_dt:
                    return True, eol_date
                else:
                    # EOL наступит, но ещё не наступил — предупреждение
                    return False, eol_date
            except ValueError:
                return False, None

    return False, None


def _match_signature(
    sig: dict[str, Any],
    headers: dict[str, str],
    cookies: set[str],
    body: str,
) -> tuple[bool, str | None]:
    """
    Проверяет соответствие HTTP-ответа одной сигнатуре.

    Для совпадения достаточно ЛЮБОГО из условий (headers / cookies / body).
    При совпадении по заголовку пытается извлечь версию.

    Возвращает (matched, version_or_None).
    """
    extracted_version: str | None = None
    headers_lower = {k.lower(): v for k, v in headers.items()}

    # Проверка заголовков
    sig_headers: dict[str, str] = sig.get("headers", {})
    for header_name, pattern in sig_headers.items():
        h_val = headers_lower.get(header_name.lower())
        if h_val and re.search(pattern, h_val, re.IGNORECASE):
            ver = _extract_version(h_val, pattern)
            if ver:
                extracted_version = ver
            return True, extracted_version

    # Проверка кук
    sig_cookies: set[str] = sig.get("cookies", set())
    for cookie_name in sig_cookies:
        for actual_cookie in cookies:
            if re.search(cookie_name, actual_cookie, re.IGNORECASE):
                return True, extracted_version

    # Проверка тела страницы
    body_pattern: str | None = sig.get("body")
    if body_pattern and re.search(body_pattern, body, re.IGNORECASE):
        return True, extracted_version

    return False, None


# ──────────────────────────────────────────────────────────────────────────────
# HTTP-клиент: два попытки (HTTPS → HTTP fallback)
# ──────────────────────────────────────────────────────────────────────────────

def _fetch_domain(domain: str) -> tuple[dict[str, str], set[str], str]:
    """
    Выполняет HTTP GET для домена.

    Сначала HTTPS, при ошибке — fallback на HTTP.
    Возвращает (headers_dict, cookies_set, body_text).
    Raises httpx.RequestError если оба протокола недостижимы.
    """
    client_kwargs = {
        "follow_redirects": True,
        "max_redirects": 3,
        "timeout": _HTTP_TIMEOUT,
        "verify": False,  # самоподписанные сертификаты на корпоративных сканируемых доменах
        "headers": {"User-Agent": _USER_AGENT},
    }

    last_exc: Exception | None = None

    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            with httpx.Client(**client_kwargs) as client:
                response = client.get(url)
                headers = dict(response.headers)
                # Имена кук из Set-Cookie заголовков
                cookies: set[str] = {c for c in response.cookies}
                # Декодируем тело — limit 512KB, нам хватит для детектирования
                body = response.text[:524288]
                logger.debug(
                    "[tech_profiler] %s → %d, %d байт",
                    url, response.status_code, len(body),
                )
                return headers, cookies, body
        except Exception as exc:
            last_exc = exc
            logger.debug("[tech_profiler] %s недостижим: %s", url, exc)

    raise last_exc or RuntimeError(f"Не удалось подключиться к {domain}")


# ──────────────────────────────────────────────────────────────────────────────
# Основная функция воркера
# ──────────────────────────────────────────────────────────────────────────────

def run_tech_profiler(
    domain: str,
    core_api_url: str,
    internal_secret: str,
) -> dict[str, Any]:
    """
    Запускает Technology Profiling для домена.

    Шаги:
    1. HTTP GET домена (HTTPS → HTTP fallback).
    2. Сравнение заголовков / кук / тела с базой сигнатур.
    3. Извлечение версий из заголовков (Server, X-Powered-By).
    4. Проверка версий на End-of-Life.
    5. Формирование и отправка события через bulk_ingest.

    Возвращает dict с найденными технологиями и EOL-результатами.
    При недостижимости домена — возвращает {"domain": domain, "error": "..."}.
    """
    logger.info("[tech_profiler] Запуск для домена: %s", domain)

    # ── Шаг 1: HTTP-запрос ───────────────────────────────────────────────────
    try:
        headers, cookies, body = _fetch_domain(domain)
    except Exception as exc:
        logger.warning("[tech_profiler] %s недостижим: %s", domain, exc)
        return {"domain": domain, "error": str(exc)}

    # ── Шаг 2 + 3: детектирование технологий и версий ────────────────────────
    technologies: list[dict[str, Any]] = []

    for tech_name, sig in _SIGNATURES.items():
        matched, version = _match_signature(sig, headers, cookies, body)
        if matched:
            logger.debug("[tech_profiler] %s обнаружен: %s (версия: %s)", domain, tech_name, version)
            technologies.append({
                "name": tech_name,
                "version": version,
            })

    # ── Шаг 4: проверка EOL ──────────────────────────────────────────────────
    eol_detected: list[dict[str, Any]] = []

    for tech in technologies:
        name = tech["name"]
        version = tech["version"]
        is_eol, eol_date = _check_eol(name, version)
        if is_eol and eol_date:
            eol_detected.append({
                "tech": name,
                "version": version,
                "eol_date": eol_date,
            })
            logger.warning(
                "[tech_profiler] %s: EOL! %s версия %s (EOL: %s)",
                domain, name, version, eol_date,
            )

    # ── Шаг 5: формируем и отправляем событие ───────────────────────────────
    severity = "medium" if eol_detected else "info"
    now_iso = datetime.now(timezone.utc).isoformat()

    event: dict[str, Any] = {
        "event_type": "tech_profile",
        "severity": severity,
        "source_type": "scanner",
        "source_name": "tech_profiler",
        "target_domain": domain,
        "payload": {
            "technologies": technologies,
            "technologies_count": len(technologies),
            "eol_detected": eol_detected,
            "eol_count": len(eol_detected),
            "server_header": headers.get("server", headers.get("Server")),
            "powered_by": headers.get("x-powered-by", headers.get("X-Powered-By")),
        },
        "detected_at": now_iso,
    }

    ingest_result = bulk_ingest(
        events=[event],
        core_api_url=core_api_url,
        internal_secret=internal_secret,
    )
    logger.info(
        "[tech_profiler] %s: отправлено (sent=%d errors=%d), "
        "технологий=%d, EOL=%d",
        domain,
        ingest_result.get("sent", 0),
        ingest_result.get("errors", 0),
        len(technologies),
        len(eol_detected),
    )

    return {
        "domain": domain,
        "technologies": technologies,
        "eol_detected": eol_detected,
        "severity": severity,
    }


def run_tech_profiler_all_assets() -> None:
    """
    10.H: Celery Beat задача — профилирование технологий всех активных активов.

    Запрашивает список активов через Core API и запускает tech profiling каждого.
    Запускается ежедневно в 05:00 UTC через Beat расписание.
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
        logger.info("[beat] tech-profile-all: запускаем для %d активов", len(assets))
        for asset in assets:
            domain = asset.get("domain") if isinstance(asset, dict) else None
            if domain:
                try:
                    run_tech_profiler(
                        domain=domain,
                        core_api_url=core_url,
                        internal_secret=internal_secret,
                    )
                except Exception as exc:
                    logger.warning("[beat] tech-profile-all: ошибка для %s: %s", domain, exc)
    except Exception as exc:
        logger.warning("[beat] tech-profile-all: ошибка получения активов: %s", exc)
