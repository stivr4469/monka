"""Воркер: инвентаризация поддоменов через subfinder."""
import logging
from datetime import datetime, timezone

from workers.celery_app import app
from workers.config import settings
from workers.tasks.base import run_tool, send_event

logger = logging.getLogger(__name__)


@app.task(bind=True, max_retries=3, default_retry_delay=60, name="workers.tasks.subfinder.scan_domain")
def scan_domain(self, domain: str) -> dict:
    """
    Запускает subfinder для обнаружения поддоменов.
    Каждый найденный поддомен отправляется как отдельное NormalizedEvent.
    """
    logger.info("Запуск subfinder для домена: %s", domain)

    try:
        stdout, stderr = run_tool(
            [settings.SUBFINDER_BIN, "-d", domain, "-silent", "-json"],
            timeout=120,
        )
    except RuntimeError as exc:
        logger.error("subfinder завершился с ошибкой: %s", exc)
        raise self.retry(exc=exc)

    sent = 0
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        import json
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            # subfinder иногда выдаёт просто hostname без JSON
            record = {"host": line}

        subdomain = record.get("host", "")
        if not subdomain:
            continue

        event = {
            "event_type": "subdomain",
            "severity": "info",
            "source_type": "subfinder",
            "source_name": "subfinder",
            "target_domain": domain,
            "payload": {
                "subdomain": subdomain,
                "ip": record.get("ip", ""),
                "source": record.get("source", ""),
            },
            "detected_at": datetime.now(timezone.utc).isoformat(),
        }
        try:
            send_event(event)
            sent += 1
        except Exception as exc:
            logger.warning("Не удалось отправить событие для %s: %s", subdomain, exc)

    logger.info("subfinder: обнаружено %d поддоменов для %s", sent, domain)
    return {"domain": domain, "subdomains_sent": sent}
