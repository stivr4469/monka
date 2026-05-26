"""
gowitness Scanner — высокопроизводительный скриншотер на Go (sensepost/gowitness).

Заменяет тяжёлый Playwright Python для visual phishing detection и Visual Drift.
Запускает gowitness через subprocess, сохраняет скриншоты в /tmp/screenshots/.

Установка бинаря:
    go install github.com/sensepost/gowitness@latest
    # или скачать с https://github.com/sensepost/gowitness/releases
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from workers.celery_app import app
from workers.config import settings
from workers.tasks.base import IngestClient, run_tool

logger = logging.getLogger(__name__)

_SCREENSHOTS_DIR = Path("/tmp/screenshots")
_GOWITNESS_TIMEOUT = 120    # секунды на один batch
_GOWITNESS_THREADS = 10     # параллельных запросов
_GOWITNESS_BINARY = "gowitness"


def _find_gowitness() -> str | None:
    """Ищет бинарь gowitness в PATH и ~/go/bin."""
    binary = shutil.which(_GOWITNESS_BINARY)
    if binary:
        return binary
    home_go = Path.home() / "go" / "bin" / _GOWITNESS_BINARY
    if home_go.exists():
        return str(home_go)
    return None


def _screenshot_event(
    url: str,
    target_domain: str,
    screenshot_path: str,
    status_code: int | None = None,
    title: str | None = None,
) -> dict[str, Any]:
    return {
        "event_type":   "screenshot_captured",
        "severity":     "info",
        "source_type":  "scanner",
        "source_name":  "gowitness",
        "target_domain": target_domain,
        "payload": {
            "url":             url,
            "screenshot_path": screenshot_path,
            "status_code":     status_code,
            "title":           title,
            "captured_at":     datetime.now(timezone.utc).isoformat(timespec="seconds"),
        },
    }


@app.task(bind=True, name="gowitness_scanner.screenshot_domains", max_retries=1)
def screenshot_domains(self, urls: list[str], target_domain: str) -> dict[str, Any]:
    """
    Снимает скриншоты списка URL через gowitness.

    Args:
        urls:          Список URL (e.g. ["https://sub.company.com", ...])
        target_domain: Корневой домен клиента для группировки событий.

    Returns:
        {"status": "ok", "screenshots_taken": N, "failed": M}
    """
    binary = _find_gowitness()
    if not binary:
        logger.warning("[gowitness] Бинарь не найден — установи: go install github.com/sensepost/gowitness@latest")
        return {"status": "skipped", "reason": "gowitness not installed", "screenshots_taken": 0}

    if not urls:
        return {"status": "ok", "screenshots_taken": 0, "failed": 0}

    _SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)

    # Записываем URLs в временный файл
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(urls))
        url_file = f.name

    out_dir = _SCREENSHOTS_DIR / target_domain.replace(".", "_")
    out_dir.mkdir(parents=True, exist_ok=True)

    db_file = str(out_dir / "gowitness.sqlite3")

    try:
        stdout, stderr = run_tool(
            [
                binary,
                "scan", "file",
                "--file", url_file,
                "--screenshot-path", str(out_dir),
                "--db-path", db_file,
                "--threads", str(_GOWITNESS_THREADS),
                "--timeout", "15",
                "--disable-logging",
            ],
            timeout=_GOWITNESS_TIMEOUT,
        )
    except RuntimeError as exc:
        logger.error("[gowitness] Ошибка запуска: %s", exc)
        return {"status": "error", "error": str(exc), "screenshots_taken": 0, "failed": len(urls)}
    finally:
        Path(url_file).unlink(missing_ok=True)

    # Считаем созданные скриншоты
    screenshots = list(out_dir.glob("*.png"))
    taken = len(screenshots)
    failed = max(0, len(urls) - taken)

    logger.info("[gowitness] %s: %d скриншотов снято, %d не удалось", target_domain, taken, failed)

    # Отправляем события в ingest
    client = IngestClient(
        core_api_url=settings.core_api_url,
        internal_secret=settings.internal_api_secret,
    )
    sent = 0
    for url, png in zip(urls, screenshots):
        ev = _screenshot_event(url=url, target_domain=target_domain, screenshot_path=str(png))
        try:
            client.send(ev)
            sent += 1
        except Exception as exc:
            logger.warning("[gowitness] Ошибка ingest: %s", exc)

    return {
        "status":            "ok",
        "screenshots_taken": taken,
        "failed":            failed,
        "output_dir":        str(out_dir),
    }


@app.task(bind=True, name="gowitness_scanner.screenshot_single", max_retries=1)
def screenshot_single(self, url: str, target_domain: str) -> dict[str, Any]:
    """Скриншот одного URL — для быстрых spot-checks."""
    return screenshot_domains.run([url], target_domain)
