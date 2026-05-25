"""
Воркер поиска упоминаний домена в публичных GitHub репозиториях.

Поисковые запросы:
  1. "domain.com" password
  2. "domain.com" secret
  3. "domain.com" api_key
  4. "domain.com" token
  5. "domain.com" email
  6. "domain.com" extension:env OR extension:cfg OR extension:ini

Фильтрация false positive:
  - Списки доменов / domain-ranking файлы
  - WHOIS-дампы и TLD-списки
  - Исследовательские датасеты (Tranco, crawl-результаты)
  - Файлы с явно нерелевантными расширениями (.csv, .html в rankingpath)

Severity:
  critical — конфигурационные файлы (.env/.cfg/.ini/.config)
  high     — код с паролями/api_key/secret (py/js/rb/php/go/yaml)
  medium   — код с token
  low      — упоминание email в коде
  skip     — явный false positive
"""
import logging
import re
import time
from pathlib import PurePosixPath

import httpx

logger = logging.getLogger(__name__)

GITHUB_SEARCH_URL = "https://api.github.com/search/code"
# GitHub rate limit: 10 req/min для аутентифицированных
REQUEST_INTERVAL = 7.0

SEARCH_QUERIES = [
    '"{domain}" password',
    '"{domain}" secret',
    '"{domain}" api_key',
    '"{domain}" token',
    '"{domain}" email',
    '"{domain}" extension:env OR extension:cfg OR extension:ini',
]

# Расширения конфиг-файлов → critical
_CONFIG_EXTENSIONS = {".env", ".cfg", ".ini", ".config", ".conf", ".properties"}

# Расширения кода → контекст определяет severity
_CODE_EXTENSIONS = {
    ".py", ".js", ".ts", ".rb", ".php", ".go", ".java", ".cs",
    ".yaml", ".yml", ".json", ".sh", ".bash", ".zsh",
}

# Паттерны путей — явные false positive
_FP_PATH_PATTERNS = re.compile(
    r"(?i)"
    r"data/rank/"
    r"|tld_lists/"
    r"|Analysis_Tranco"
    r"|RESULTS_EC2/"
    r"|/headless_timing"
    r"|/invalid_html"
    r"|domains2scan/"
    r"|web\d+_\d+\."
    r"|/shards/"
    r"|whois/tld"
    r"|chunk_\d+"
    r"|top[\-_]?\d+k?"     # top1m, top-10k и т.п.
    r"|tranco"
    r"|alexa"
    r"|majestic"
    r"|umbrella"
    r"|quantcast"
    r"|domainlist"
    r"|domain.?list"
    r"|rank.?list"
)

# Паттерны имён репозиториев — явные false positive
_FP_REPO_PATTERNS = re.compile(
    r"(?i)"
    r"tranco"
    r"|domain.?list"
    r"|rank.?list"
    r"|tld.?list"
    r"|whois.?data"
    r"|crawl.?data"
    r"|pii.?xel"
    r"|piidb"
    r"|privadb"
    r"|randomwebsite"
    r"|web.?crawl"
    r"|site.?mirror"
    r"|domain.?scan"
    r"|nextlist"
    r"|reviewnav.?handler"
    r"|alexa.?top"
    r"|majestic.?million"
)

# Ключевые слова в имени файла, указывающие на списки/дампы
_FP_FILENAME_PATTERNS = re.compile(
    r"(?i)"
    r"(top|rank|list|dump|crawl|index|domain|tld|whois|mirror)\d*\."
    r"|^\d+\.txt$"          # просто число.txt — обычно список
    r"|_timings?\."
    r"|_response\."
    r"|_list\."
)


def _is_false_positive(repo_name: str, file_path: str) -> bool:
    """Возвращает True если результат — явный false positive."""
    if _FP_REPO_PATTERNS.search(repo_name):
        return True
    if _FP_PATH_PATTERNS.search(file_path):
        return True
    filename = PurePosixPath(file_path).name
    if _FP_FILENAME_PATTERNS.search(filename):
        return True
    return False


def _classify_severity(query: str, file_path: str) -> str:
    """
    Определяет severity по расширению файла и типу запроса.

    critical — конфиг-файл (.env/.cfg/.ini/.config)
    high     — код + password/api_key/secret
    medium   — код + token/secret
    low      — код + email / нераспознанный файл
    """
    ext = PurePosixPath(file_path).suffix.lower()
    q = query.lower()

    if ext in _CONFIG_EXTENSIONS:
        return "critical"

    is_code = ext in _CODE_EXTENSIONS

    if is_code:
        if any(kw in q for kw in ("password", "api_key")):
            return "high"
        if any(kw in q for kw in ("secret",)):
            return "high"
        if "token" in q:
            return "medium"
        if "email" in q:
            return "low"

    # Неизвестное расширение, но запрос на credentials
    if any(kw in q for kw in ("password", "api_key", "secret")):
        return "medium"

    return "low"


def _build_headers(github_token: str) -> dict:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"
    return headers


def _search_once(query: str, headers: dict, timeout: float = 15.0) -> list[dict]:
    """Выполняет один поисковый запрос, возвращает список items."""
    params = {"q": query, "per_page": 30, "sort": "indexed", "order": "desc"}
    try:
        r = httpx.get(GITHUB_SEARCH_URL, headers=headers, params=params, timeout=timeout)
    except Exception as exc:
        logger.warning("GitHub search request failed: %s", exc)
        return []

    if r.status_code == 403:
        logger.warning("GitHub rate limit exceeded, sleeping 60s")
        time.sleep(60)
        try:
            r = httpx.get(GITHUB_SEARCH_URL, headers=headers, params=params, timeout=timeout)
        except Exception as exc:
            logger.warning("GitHub search retry failed: %s", exc)
            return []

    if r.status_code != 200:
        logger.warning("GitHub search returned %d for query: %s", r.status_code, query)
        return []

    return r.json().get("items", [])


def search_github(
    domain: str,
    github_token: str,
    core_api_url: str,
    internal_secret: str,
) -> dict:
    """
    Ищет упоминания домена в публичных GitHub репозиториях.
    Найденные совпадения (после фильтрации FP) отправляет в Core API
    как события типа github_leak.

    Возвращает: {"queries": N, "found": M, "filtered": F, "sent": K, "errors": E}
    """
    ingest_url = f"{core_api_url}/api/v1/internal/ingest"
    headers_ingest = {"Authorization": f"Bearer {internal_secret}"}
    headers_gh = _build_headers(github_token)

    total_found = filtered = sent = errors = 0

    for query_tpl in SEARCH_QUERIES:
        query = query_tpl.format(domain=domain)
        logger.info("[github] query: %s", query)

        items = _search_once(query, headers_gh)
        total_found += len(items)

        for item in items:
            repo_name = item.get("repository", {}).get("full_name", "")
            file_path = item.get("path", "")
            file_url  = item.get("html_url", "")
            repo_url  = item.get("repository", {}).get("html_url", "")

            if _is_false_positive(repo_name, file_path):
                filtered += 1
                logger.debug("[github] FP отфильтрован: %s / %s", repo_name, file_path)
                continue

            severity = _classify_severity(query, file_path)

            event = {
                "event_type": "github_leak",
                "severity": severity,
                "source_type": "github_search",
                "source_name": "github-search-worker",
                "target_domain": domain,
                "payload": {
                    "query":     query,
                    "repo":      repo_name,
                    "file_path": file_path,
                    "file_url":  file_url,
                    "repo_url":  repo_url,
                    "severity_reason": _severity_reason(severity, query, file_path),
                },
            }

            try:
                r = httpx.post(ingest_url, json=event, headers=headers_ingest, timeout=10)
                status = r.json().get("status", "error")
                if status in ("accepted", "duplicate"):
                    sent += 1
                else:
                    errors += 1
            except Exception as exc:
                logger.error("ingest error: %s", exc)
                errors += 1

        time.sleep(REQUEST_INTERVAL)

    logger.info(
        "[github] domain=%s queries=%d found=%d filtered=%d sent=%d errors=%d",
        domain, len(SEARCH_QUERIES), total_found, filtered, sent, errors,
    )
    return {
        "queries": len(SEARCH_QUERIES),
        "found": total_found,
        "filtered": filtered,
        "sent": sent,
        "errors": errors,
    }


def _severity_reason(severity: str, query: str, file_path: str) -> str:
    """Краткое объяснение почему выбран данный severity."""
    ext = PurePosixPath(file_path).suffix.lower()
    if severity == "critical":
        return f"Конфигурационный файл ({ext})"
    if severity == "high":
        return f"Код ({ext}) + ключевое слово из запроса: {query.split()[-1]}"
    if severity == "medium":
        return f"Код ({ext}) + token"
    return f"Упоминание домена в {ext or 'файле'}"


# ── Celery-обёртка ────────────────────────────────────────────────────────────

try:
    from workers.celery_app import app as _celery_app
    from workers.config import settings as _settings

    @_celery_app.task(
        bind=True,
        max_retries=2,
        default_retry_delay=300,
        name="workers.tasks.github_search.search_github_task",
    )
    def search_github_task(self, domain: str) -> dict:
        """Celery-задача: поиск упоминаний домена в GitHub."""
        try:
            return search_github(
                domain=domain,
                github_token=_settings.GITHUB_TOKEN,
                core_api_url=_settings.CORE_API_URL,
                internal_secret=_settings.INTERNAL_API_SECRET,
            )
        except Exception as exc:
            raise self.retry(exc=exc)

except ImportError:
    pass
