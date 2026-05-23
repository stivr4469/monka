"""
Модуль сканирования — запускает внешние инструменты и отправляет результаты в /ingest.
В dev-режиме работает как BackgroundTask внутри FastAPI-процесса.
В production заменяется на Celery-воркеры без изменения логики.
"""
import json
import logging
import os
import shutil
import subprocess

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

DEFAULT_PORT = int(os.getenv("APP_PORT", "8000"))
INGEST_URL = f"http://127.0.0.1:{DEFAULT_PORT}/api/v1/internal/ingest"
INGEST_HEADERS = {"Authorization": f"Bearer {settings.INTERNAL_API_SECRET}"}


def _ingest(event: dict) -> str:
    """Отправляет одно событие в Core API. Возвращает статус."""
    try:
        r = httpx.post(INGEST_URL, json=event, headers=INGEST_HEADERS, timeout=10)
        return r.json().get("status", "error")
    except Exception as exc:
        logger.error("ingest failed: %s", exc)
        return "error"


def _run(cmd: list[str], timeout: int = 120) -> str:
    """Запускает CLI-инструмент. Возвращает stdout или пустую строку при ошибке."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, shell=False
        )
        return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        logger.warning("tool %s failed: %s", cmd[0], exc)
        return ""


def run_subfinder(domain: str, port: int = 8000) -> None:
    """
    Фоновая задача: ищет поддомены через subfinder.
    После каждой находки сразу отправляет событие в /ingest.
    По завершении ставит в очередь nuclei-сканирование каждого поддомена.
    """
    global INGEST_URL
    INGEST_URL = f"http://127.0.0.1:{port}/api/v1/internal/ingest"

    subfinder_bin = shutil.which("subfinder") or "/tmp/subfinder"
    logger.info("[subfinder] Старт сканирования домена: %s", domain)

    stdout = _run([subfinder_bin, "-d", domain, "-silent", "-json", "-timeout", "30"])

    subdomains = []
    accepted = 0

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue

        host = rec.get("host", "")
        source = rec.get("source", "dns")
        if not host:
            continue

        subdomains.append(host)
        event = {
            "event_type": "subdomain",
            "severity": "info",
            "source_type": "subfinder",
            "source_name": "subfinder",
            "target_domain": domain,
            "payload": {"subdomain": host, "source": source},
        }
        status = _ingest(event)
        if status == "accepted":
            accepted += 1
            logger.info("[subfinder] ✓ %s [%s]", host, source)

    logger.info("[subfinder] Завершено: %d новых поддоменов для %s", accepted, domain)

    # Запускаем nuclei по каждому найденному поддомену
    for host in subdomains:
        run_nuclei(target=host, root_domain=domain, port=port)


def run_nuclei(target: str, root_domain: str, port: int = 8000) -> None:
    """
    Фоновая задача: сканирует один хост через nuclei на уязвимости.
    """
    global INGEST_URL
    INGEST_URL = f"http://127.0.0.1:{port}/api/v1/internal/ingest"

    nuclei_bin = shutil.which("nuclei") or "/tmp/nuclei"
    if not shutil.which("nuclei") and not __import__("os").path.exists("/tmp/nuclei"):
        logger.warning("[nuclei] бинарник не найден, пропускаю %s", target)
        return

    logger.info("[nuclei] Сканирование: %s", target)

    SEVERITY_MAP = {"info": "info", "low": "low", "medium": "medium",
                    "high": "high", "critical": "critical"}

    stdout = _run(
        [nuclei_bin, "-u", target, "-jsonl", "-silent",
         "-severity", "info,low,medium,high,critical"],
        timeout=180,
    )

    sent = 0
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue

        severity_raw = rec.get("info", {}).get("severity", "info").lower()
        event = {
            "event_type": "vulnerability",
            "severity": SEVERITY_MAP.get(severity_raw, "info"),
            "source_type": "nuclei",
            "source_name": rec.get("template-id", "nuclei"),
            "target_domain": root_domain,
            "payload": {
                "template_id": rec.get("template-id", ""),
                "name": rec.get("info", {}).get("name", ""),
                "matched_url": rec.get("matched-at", target),
                "host": target,
                "tags": rec.get("info", {}).get("tags", []),
            },
        }
        status = _ingest(event)
        if status == "accepted":
            sent += 1

    logger.info("[nuclei] %d находок для %s", sent, target)
