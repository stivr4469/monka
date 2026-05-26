"""
Katana Crawler — краулер следующего поколения от ProjectDiscovery.

Находит скрытые API-эндпоинты, параметры запросов и формы ввода в JS-файлах.
Запускает katana до nuclei для увеличения покрытия сканирования.

Установка бинаря:
    go install github.com/projectdiscovery/katana/cmd/katana@latest
    # или скачать с https://github.com/projectdiscovery/katana/releases

Pipeline: target URL → katana (crawl) → список URL/params → nuclei (scan)
"""
from __future__ import annotations

import json
import logging
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from workers.celery_app import app
from workers.config import settings
from workers.tasks.base import IngestClient, run_tool

logger = logging.getLogger(__name__)

_KATANA_TIMEOUT   = 180     # секунды
_KATANA_DEPTH     = 3       # глубина обхода
_KATANA_CONCURR   = 10      # параллельных запросов
_KATANA_BINARY    = "katana"
_MAX_URLS         = 500     # максимум URL для передачи в nuclei


def _find_katana() -> str | None:
    binary = shutil.which(_KATANA_BINARY)
    if binary:
        return binary
    home_go = Path.home() / "go" / "bin" / _KATANA_BINARY
    if home_go.exists():
        return str(home_go)
    return None


def _is_interesting_url(url: str) -> bool:
    """Фильтр: только URL с параметрами или API-паттернами."""
    parsed = urlparse(url)
    if parsed.query:
        return True
    path = parsed.path.lower()
    api_patterns = ["/api/", "/v1/", "/v2/", "/graphql", "/admin", "/login",
                    "/auth", "/oauth", "/token", "/upload", "/download"]
    return any(p in path for p in api_patterns)


def _endpoint_event(
    url: str,
    target_domain: str,
    has_params: bool,
    is_api: bool,
) -> dict[str, Any]:
    severity = "medium" if (has_params or is_api) else "info"
    return {
        "event_type":   "hidden_endpoint_discovered",
        "severity":     severity,
        "source_type":  "scanner",
        "source_name":  "katana",
        "target_domain": target_domain,
        "payload": {
            "url":        url,
            "has_params": has_params,
            "is_api":     is_api,
            "discovered_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        },
    }


@app.task(bind=True, name="katana_crawler.crawl_target", max_retries=1)
def crawl_target(self, url: str, target_domain: str) -> dict[str, Any]:
    """
    Краулит целевой URL через katana, ищет скрытые API и параметры.

    Returns:
        {
            "status": "ok",
            "urls_discovered": N,
            "api_endpoints": M,
            "urls_for_nuclei": [...] — список URL для передачи в nuclei
        }
    """
    binary = _find_katana()
    if not binary:
        logger.warning(
            "[katana] Бинарь не найден — установи: go install github.com/projectdiscovery/katana/cmd/katana@latest"
        )
        return {"status": "skipped", "reason": "katana not installed", "urls_discovered": 0}

    logger.info("[katana] Краулинг %s (глубина %d)", url, _KATANA_DEPTH)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        output_file = f.name

    try:
        stdout, stderr = run_tool(
            [
                binary,
                "-u", url,
                "-d", str(_KATANA_DEPTH),
                "-c", str(_KATANA_CONCURR),
                "-o", output_file,
                "-silent",
                "-jc",           # обход JS-файлов
                "-fx",           # автоформа
                "-timeout", "10",
                "-rl", "50",     # rate limit запросов/секунду
            ],
            timeout=_KATANA_TIMEOUT,
        )
    except RuntimeError as exc:
        logger.error("[katana] Ошибка запуска: %s", exc)
        return {"status": "error", "error": str(exc), "urls_discovered": 0}
    finally:
        pass

    # Парсим вывод
    discovered_urls: list[str] = []
    try:
        output_path = Path(output_file)
        if output_path.exists():
            for line in output_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line.startswith("http"):
                    discovered_urls.append(line)
        else:
            # katana может писать в stdout
            for line in stdout.splitlines():
                line = line.strip()
                if line.startswith("http"):
                    discovered_urls.append(line)
    finally:
        Path(output_file).unlink(missing_ok=True)

    logger.info("[katana] Найдено %d URL для %s", len(discovered_urls), target_domain)

    # Фильтр интересных URL для nuclei
    interesting = [u for u in discovered_urls if _is_interesting_url(u)]
    api_endpoints = [
        u for u in interesting
        if any(p in urlparse(u).path.lower() for p in ["/api/", "/v1/", "/v2/", "/graphql"])
    ]

    # Отправляем события для API-эндпоинтов
    client = IngestClient(
        core_api_url=settings.core_api_url,
        internal_secret=settings.internal_api_secret,
    )
    sent = 0
    for found_url in interesting[:50]:   # лимит событий
        parsed = urlparse(found_url)
        ev = _endpoint_event(
            url=found_url,
            target_domain=target_domain,
            has_params=bool(parsed.query),
            is_api=any(p in parsed.path.lower() for p in ["/api/", "/v1/", "/graphql"]),
        )
        try:
            client.send(ev)
            sent += 1
        except Exception as exc:
            logger.warning("[katana] Ingest error: %s", exc)

    return {
        "status":          "ok",
        "urls_discovered": len(discovered_urls),
        "api_endpoints":   len(api_endpoints),
        "interesting_urls": len(interesting),
        "events_sent":     sent,
        # Топ-N URL для передачи в nuclei как следующий шаг pipeline
        "urls_for_nuclei": interesting[:_MAX_URLS],
    }


@app.task(bind=True, name="katana_crawler.crawl_and_scan", max_retries=1)
def crawl_and_scan(self, url: str, target_domain: str) -> dict[str, Any]:
    """
    Полный pipeline: katana → nuclei.
    Краулит цель, затем запускает nuclei по найденным URL.
    """
    from workers.tasks.nuclei import scan_target  # noqa: PLC0415

    crawl_result = crawl_target.run(url, target_domain)
    if crawl_result.get("status") != "ok":
        return crawl_result

    urls_for_nuclei = crawl_result.get("urls_for_nuclei", [])
    if not urls_for_nuclei:
        return {**crawl_result, "nuclei_status": "no_urls"}

    # Запускаем nuclei для каждого найденного URL (первые 20 для ограничения времени)
    nuclei_results: list[dict] = []
    for target_url in urls_for_nuclei[:20]:
        try:
            result = scan_target.run(target_url, target_domain)
            nuclei_results.append(result)
        except Exception as exc:
            logger.warning("[katana+nuclei] Ошибка для %s: %s", target_url, exc)

    total_vulns = sum(r.get("total_secrets", 0) + r.get("findings", 0) for r in nuclei_results)

    return {
        **crawl_result,
        "nuclei_targets_scanned": len(nuclei_results),
        "total_vulnerabilities":  total_vulns,
    }
