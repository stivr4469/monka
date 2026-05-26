"""
CertStream Monitor — реалтайм Certificate Transparency вместо медленного crt.sh.

Два режима работы:
  1. Celery-задача scan_ct_live() — слушает WebSocket окно N секунд, собирает
     новые поддомены и отправляет в ingest pipeline.
  2. Daemon-режим run_daemon() — бесконечный listener для запуска как отдельный процесс
     (supervisord / systemd).

Зависимость: pip install certstream
Fallback: если пакет не установлен, задача завершается с предупреждением.
"""
from __future__ import annotations

import logging
import shutil
import threading
import time
from datetime import datetime, timezone
from typing import Any

from workers.celery_app import app
from workers.config import settings
from workers.tasks.base import IngestClient

logger = logging.getLogger(__name__)

_LISTEN_WINDOW_SEC = 60       # сколько секунд слушаем в Celery-задаче
_INGEST_BATCH_SIZE = 50       # отправляем событиями батчами


def _check_certstream() -> bool:
    """Проверяет доступность пакета certstream."""
    try:
        import certstream  # noqa: F401
        return True
    except ImportError:
        logger.warning("[certstream] Пакет не установлен: pip install certstream")
        return False


def _make_subdomain_event(subdomain: str, target_domain: str) -> dict[str, Any]:
    return {
        "event_type":   "subdomain_discovered",
        "severity":     "info",
        "source_type":  "scanner",
        "source_name":  "certstream_live",
        "target_domain": target_domain,
        "payload": {
            "subdomain": subdomain,
            "source":    "certificate_transparency",
            "detected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        },
    }


def _listen_window(
    monitored_domains: list[str],
    window_sec: int,
) -> list[dict[str, Any]]:
    """
    Подключается к CertStream WebSocket и собирает события в течение window_sec секунд.
    Возвращает список ingest-событий для найденных поддоменов.
    """
    import certstream  # noqa: PLC0415 (импорт внутри функции — certstream необязателен)

    collected: list[dict[str, Any]] = []
    stop_event = threading.Event()

    def callback(message: dict, context: Any) -> None:
        if stop_event.is_set():
            return
        if message.get("message_type") != "certificate_update":
            return
        leaf = message.get("data", {}).get("leaf_cert", {})
        all_domains: list[str] = leaf.get("all_domains", [])
        for cert_domain in all_domains:
            cert_domain = cert_domain.lstrip("*.").lower()
            for target in monitored_domains:
                if cert_domain.endswith(f".{target}") or cert_domain == target:
                    logger.debug("[certstream] Новый субдомен: %s → %s", cert_domain, target)
                    collected.append(_make_subdomain_event(cert_domain, target))

    # Запускаем listener в отдельном потоке
    listener_thread = threading.Thread(
        target=certstream.listen_for_events,
        args=(callback,),
        kwargs={"url": "wss://certstream.calidog.io"},
        daemon=True,
    )
    listener_thread.start()

    time.sleep(window_sec)
    stop_event.set()

    logger.info("[certstream] Окно %ds: собрано %d событий", window_sec, len(collected))
    return collected


@app.task(bind=True, name="certstream_monitor.scan_ct_live", max_retries=1)
def scan_ct_live(self, domain: str) -> dict[str, Any]:
    """
    Celery-задача: слушает CertStream window_sec секунд и отправляет
    обнаруженные поддомены в ingest API.
    """
    if not _check_certstream():
        return {"status": "skipped", "reason": "certstream not installed", "new_subdomains": 0}

    logger.info("[certstream] Старт для домена %s, окно %ds", domain, _LISTEN_WINDOW_SEC)
    monitored = [domain]

    try:
        events = _listen_window(monitored, _LISTEN_WINDOW_SEC)
    except Exception as exc:
        logger.error("[certstream] Ошибка WebSocket: %s", exc)
        return {"status": "error", "error": str(exc), "new_subdomains": 0}

    if not events:
        return {"status": "ok", "new_subdomains": 0}

    # Дедупликация по субдомену
    seen: set[str] = set()
    unique_events: list[dict] = []
    for ev in events:
        sub = ev["payload"]["subdomain"]
        if sub not in seen:
            seen.add(sub)
            unique_events.append(ev)

    # Отправка в ingest батчами
    client = IngestClient(
        core_api_url=settings.core_api_url,
        internal_secret=settings.internal_api_secret,
    )
    sent = 0
    for ev in unique_events:
        try:
            client.send(ev)
            sent += 1
        except Exception as exc:
            logger.warning("[certstream] Ошибка отправки события: %s", exc)

    logger.info("[certstream] %s: %d новых поддоменов отправлено", domain, sent)
    return {"status": "ok", "new_subdomains": sent}


# ─── Daemon-режим (не Celery) ─────────────────────────────────────────────────

def run_daemon(monitored_domains: list[str]) -> None:
    """
    Бесконечный listener для запуска как отдельный процесс.

    Использование:
        python -c "from workers.tasks.certstream_monitor import run_daemon; run_daemon(['company.com'])"
    """
    if not _check_certstream():
        raise RuntimeError("Пакет certstream не установлен: pip install certstream")

    import certstream  # noqa: PLC0415

    client = IngestClient(
        core_api_url=settings.core_api_url,
        internal_secret=settings.internal_api_secret,
    )

    def callback(message: dict, context: Any) -> None:
        if message.get("message_type") != "certificate_update":
            return
        leaf = message.get("data", {}).get("leaf_cert", {})
        for cert_domain in leaf.get("all_domains", []):
            cert_domain = cert_domain.lstrip("*.").lower()
            for target in monitored_domains:
                if cert_domain.endswith(f".{target}") or cert_domain == target:
                    logger.info("[certstream:daemon] Новый субдомен: %s", cert_domain)
                    try:
                        client.send(_make_subdomain_event(cert_domain, target))
                    except Exception as exc:
                        logger.warning("[certstream:daemon] Ingest error: %s", exc)

    logger.info("[certstream:daemon] Старт listener для %d доменов", len(monitored_domains))
    certstream.listen_for_events(callback, url="wss://certstream.calidog.io")
