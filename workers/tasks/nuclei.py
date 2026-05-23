"""Воркер: сканирование уязвимостей через nuclei."""
import json
import logging
from datetime import datetime, timezone

from workers.celery_app import app
from workers.config import settings
from workers.tasks.base import run_tool, send_event

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "info": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
    "unknown": "info",
}


@app.task(bind=True, max_retries=2, default_retry_delay=120, name="workers.tasks.nuclei.scan_target")
def scan_target(self, target: str, root_domain: str) -> dict:
    """
    Запускает nuclei против конкретного хоста.
    Каждое срабатывание шаблона — отдельное событие типа vulnerability.
    """
    logger.info("Запуск nuclei для таргета: %s", target)

    try:
        stdout, _ = run_tool(
            [
                settings.NUCLEI_BIN,
                "-u", target,
                "-jsonl",
                "-silent",
                "-severity", "info,low,medium,high,critical",
            ],
            timeout=300,
        )
    except RuntimeError as exc:
        logger.error("nuclei завершился с ошибкой: %s", exc)
        raise self.retry(exc=exc)

    sent = 0
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue

        severity_raw = record.get("info", {}).get("severity", "info").lower()
        severity = SEVERITY_MAP.get(severity_raw, "info")

        event = {
            "event_type": "vulnerability",
            "severity": severity,
            "source_type": "nuclei",
            "source_name": record.get("template-id", "nuclei"),
            "target_domain": root_domain,
            "payload": {
                "template_id": record.get("template-id", ""),
                "name": record.get("info", {}).get("name", ""),
                "matched_url": record.get("matched-at", target),
                "host": target,
                "tags": record.get("info", {}).get("tags", []),
            },
            "detected_at": datetime.now(timezone.utc).isoformat(),
        }
        try:
            send_event(event)
            sent += 1
        except Exception as exc:
            logger.warning("Не удалось отправить событие nuclei: %s", exc)

    logger.info("nuclei: %d находок для %s", sent, target)
    return {"target": target, "findings_sent": sent}
