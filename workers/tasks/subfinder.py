"""Воркер: инвентаризация поддоменов через subfinder."""
import json
import logging
from datetime import datetime, timezone

from workers.celery_app import app
from workers.config import settings
from workers.tasks.base import run_tool, send_event

logger = logging.getLogger(__name__)


@app.task(
    bind=True,
    max_retries=3,
    default_retry_delay=60,
    name="workers.tasks.subfinder.scan_domain",
)
def scan_domain(self, domain: str) -> dict:
    """
    Запускает subfinder для обнаружения поддоменов.
    Каждый найденный поддомен отправляется как отдельное NormalizedEvent.
    После завершения ставит в очередь nuclei-сканирование каждого поддомена.
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
    subdomains: list[str] = []

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            # subfinder иногда выдаёт просто hostname без JSON
            record = {"host": line}

        subdomain = record.get("host", "")
        if not subdomain:
            continue

        subdomains.append(subdomain)

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

    # Ставим задачи nuclei в очередь для каждого поддомена
    # Импортируем здесь чтобы избежать циклического импорта
    from workers.tasks.nuclei import scan_target
    for subdomain in subdomains:
        scan_target.apply_async(
            args=[subdomain, domain],
            queue="scanning",
        )
    logger.info("subfinder: поставлено %d nuclei-задач для %s", len(subdomains), domain)

    return {"domain": domain, "subdomains_sent": sent, "nuclei_queued": len(subdomains)}


@app.task(
    bind=True,
    name="workers.tasks.subfinder.scan_domain_all_active",
    ignore_result=True,
)
def scan_domain_all_active(self) -> None:
    """
    Периодическая задача (запускается Celery Beat раз в сутки).
    Опрашивает Core API за списком активных активов и ставит в очередь
    scan_domain для каждого.
    """
    import httpx

    logger.info("Запуск плановой переинвентаризации всех активных доменов")
    url = f"{settings.CORE_API_URL}/api/v1/assets/"
    headers = {"Authorization": f"Bearer {settings.INTERNAL_API_SECRET}"}

    try:
        response = httpx.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        assets = response.json()
    except Exception as exc:
        logger.error("Не удалось получить список активов: %s", exc)
        return

    queued = 0
    for asset in assets:
        if asset.get("is_active"):
            scan_domain.apply_async(args=[asset["domain"]], queue="discovery")
            queued += 1

    logger.info("Плановая переинвентаризация: поставлено %d доменов в очередь", queued)
