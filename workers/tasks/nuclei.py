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


@app.task(
    bind=True,
    max_retries=2,
    default_retry_delay=120,
    name="workers.tasks.nuclei.scan_target",
)
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


@app.task(
    bind=True,
    name="workers.tasks.nuclei.scan_all_active_targets",
    ignore_result=True,
)
def scan_all_active_targets(self) -> None:
    """
    Периодическая задача (запускается Celery Beat раз в сутки).
    Опрашивает Core API за списком активных активов и ставит в очередь
    scan_target для каждого домена.
    """
    import httpx

    logger.info("Плановое nuclei-сканирование всех активных доменов")
    url = f"{settings.CORE_API_URL}/api/v1/assets/"
    headers = {"Authorization": f"Bearer {settings.INTERNAL_API_SECRET}"}

    try:
        response = httpx.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        assets = response.json()
    except Exception as exc:
        logger.error("Не удалось получить список активов для nuclei: %s", exc)
        return

    queued = 0
    for asset in assets:
        if asset.get("is_active"):
            domain = asset["domain"]
            # Сканируем сам домен как таргет
            scan_target.apply_async(args=[domain, domain], queue="scanning")
            queued += 1

    logger.info("Плановое nuclei-сканирование: поставлено %d задач", queued)
