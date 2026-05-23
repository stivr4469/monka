"""
Воркер поиска упоминаний домена в публичных GitHub репозиториях.

Поисковые запросы:
  1. "domain.com" password
  2. "domain.com" secret
  3. "domain.com" api_key
  4. "domain.com" token
  5. "domain.com" email
  6. "domain.com" extension:env OR extension:cfg OR extension:ini
"""
import logging
import time
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

GITHUB_SEARCH_URL = "https://api.github.com/search/code"
# Интервал между запросами — GitHub rate limit: 10 req/min для аутентифицированных
REQUEST_INTERVAL = 7.0

SEARCH_QUERIES = [
    '"{domain}" password',
    '"{domain}" secret',
    '"{domain}" api_key',
    '"{domain}" token',
    '"{domain}" email',
    '"{domain}" extension:env OR extension:cfg OR extension:ini',
]


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
        # Повторная попытка
        try:
            r = httpx.get(GITHUB_SEARCH_URL, headers=headers, params=params, timeout=timeout)
        except Exception as exc:
            logger.warning("GitHub search retry failed: %s", exc)
            return []

    if r.status_code != 200:
        logger.warning("GitHub search returned %d for query: %s", r.status_code, query)
        return []

    data = r.json()
    return data.get("items", [])


def search_github(
    domain: str,
    github_token: str,
    core_api_url: str,
    internal_secret: str,
) -> dict:
    """
    Ищет упоминания домена в публичных GitHub репозиториях.
    Найденные совпадения отправляет в Core API как события типа github_leak.

    Возвращает: {"queries": N, "found": M, "sent": K, "errors": E}
    """
    ingest_url = f"{core_api_url}/api/v1/internal/ingest"
    headers_ingest = {"Authorization": f"Bearer {internal_secret}"}
    headers_gh = _build_headers(github_token)

    total_found = sent = errors = 0

    for query_tpl in SEARCH_QUERIES:
        query = query_tpl.format(domain=domain)
        logger.info("[github] query: %s", query)

        items = _search_once(query, headers_gh)
        total_found += len(items)

        for item in items:
            repo_name = item.get("repository", {}).get("full_name", "")
            file_path = item.get("path", "")
            file_url = item.get("html_url", "")
            repo_url = item.get("repository", {}).get("html_url", "")

            event = {
                "event_type": "github_leak",
                "severity": "high",
                "source_type": "github_search",
                "source_name": "github-search-worker",
                "target_domain": domain,
                "payload": {
                    "query": query,
                    "repo": repo_name,
                    "file_path": file_path,
                    "file_url": file_url,
                    "repo_url": repo_url,
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

        # Пауза между запросами чтобы не попасть в rate limit
        time.sleep(REQUEST_INTERVAL)

    logger.info(
        "[github] domain=%s queries=%d found=%d sent=%d errors=%d",
        domain,
        len(SEARCH_QUERIES),
        total_found,
        sent,
        errors,
    )
    return {
        "queries": len(SEARCH_QUERIES),
        "found": total_found,
        "sent": sent,
        "errors": errors,
    }
