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
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx

from app.core.config import get_settings

logger = logging.getLogger(__name__)

# Количество параллельных потоков для nuclei-сканирования
_NUCLEI_WORKERS = 5


def _make_ingest_url(port: int) -> str:
    """Вычисляет URL эндпоинта ingest без глобального состояния."""
    return f"http://127.0.0.1:{port}/api/v1/internal/ingest"


def _make_ingest_headers() -> dict[str, str]:
    """Возвращает заголовки авторизации для internal API."""
    # Читаем через get_settings() — безопасно для многопоточности, lru_cache
    return {"Authorization": f"Bearer {get_settings().INTERNAL_API_SECRET}"}


def _ingest(event: dict, port: int) -> str:
    """
    Отправляет одно событие в Core API.
    Возвращает статус из JSON-ответа или "error".

    Аргументы передаются явно — никаких глобальных переменных.
    """
    url = _make_ingest_url(port)
    headers = _make_ingest_headers()
    try:
        r = httpx.post(url, json=event, headers=headers, timeout=10)
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


def run_nuclei(target: str, root_domain: str, port: int = 8000) -> None:
    """
    Сканирует один хост через nuclei на уязвимости.
    Не использует глобальных переменных — port передаётся явно.
    """
    nuclei_bin = shutil.which("nuclei") or "/tmp/nuclei"
    if not shutil.which("nuclei") and not os.path.exists("/tmp/nuclei"):
        logger.warning("[nuclei] бинарник не найден, пропускаю %s", target)
        return

    logger.info("[nuclei] Сканирование: %s", target)

    SEVERITY_MAP = {
        "info": "info",
        "low": "low",
        "medium": "medium",
        "high": "high",
        "critical": "critical",
    }

    stdout = _run(
        [
            nuclei_bin, "-u", target, "-jsonl", "-silent",
            "-severity", "low,medium,high,critical",
            "-rate-limit", "50",
            "-timeout", "5",
            "-retries", "1",
            "-bulk-size", "10",
            "-concurrency", "10",
        ],
        timeout=300,
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
        status = _ingest(event, port)
        if status == "accepted":
            sent += 1

    logger.info("[nuclei] %d находок для %s", sent, target)


def run_subfinder(domain: str, port: int = 8000) -> None:
    """
    Фоновая задача: ищет поддомены через subfinder.
    После каждой находки сразу отправляет событие в /ingest.
    По завершении запускает nuclei на всех найденных поддоменах параллельно
    (ThreadPoolExecutor с max_workers=5) вместо последовательного запуска.
    """
    subfinder_bin = shutil.which("subfinder") or "/tmp/subfinder"
    logger.info("[subfinder] Старт сканирования домена: %s", domain)

    stdout = _run([subfinder_bin, "-d", domain, "-silent", "-json", "-timeout", "30"])

    subdomains: list[str] = []
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
        status = _ingest(event, port)
        if status == "accepted":
            accepted += 1
            logger.info("[subfinder] subdomain принят: %s [%s]", host, source)

    logger.info("[subfinder] Завершено: %d новых поддоменов для %s", accepted, domain)

    if not subdomains:
        return

    # Параллельный запуск nuclei — вместо последовательного перебора
    # max_workers=5 чтобы не перегружать сеть и не исчерпать файловые дескрипторы
    logger.info(
        "[subfinder] Запуск nuclei на %d поддоменах (parallel=%d)",
        len(subdomains),
        _NUCLEI_WORKERS,
    )
    with ThreadPoolExecutor(max_workers=_NUCLEI_WORKERS) as executor:
        futures = {
            executor.submit(run_nuclei, host, domain, port): host
            for host in subdomains
        }
        for future in as_completed(futures):
            host = futures[future]
            try:
                future.result()
            except Exception as exc:
                logger.error("[nuclei] Ошибка для %s: %s", host, exc)
