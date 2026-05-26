"""
holehe Scanner — где зарегистрирован корпоративный email (megadose/holehe).

Проверяет email сотрудника на 120+ популярных сайтах (Twitter, GitHub, Trello,
Discord, Notion и др.) через механизм восстановления пароля.

Ценность для клиента:
    «Ваш сотрудник использует корпоративную почту на 14 сторонних сервисах.
    В случае компрометации почты эти аккаунты немедленно под угрозой.»

Установка: pip install holehe
Запускается как sync-функция в asyncio.to_thread или напрямую как Celery task.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from workers.celery_app import app
from workers.config import settings
from workers.tasks.base import IngestClient

logger = logging.getLogger(__name__)

# Сервисы с высоким корпоративным риском — повышаем severity
_HIGH_RISK_SERVICES = {
    "github.com", "gitlab.com", "bitbucket.org",
    "trello.com", "notion.so", "atlassian.com", "jira.com", "confluence.com",
    "slack.com", "discord.com",
    "aws.amazon.com", "azure.microsoft.com", "cloud.google.com",
    "dropbox.com", "box.com", "drive.google.com",
}


def _check_holehe() -> bool:
    try:
        import holehe  # noqa: F401
        return True
    except ImportError:
        logger.warning("[holehe] Пакет не установлен: pip install holehe")
        return False


def _severity_for_service(service: str) -> str:
    """Высокий риск для облачных и dev-платформ."""
    return "high" if any(s in service for s in _HIGH_RISK_SERVICES) else "medium"


def _holehe_event(
    email: str,
    target_domain: str,
    service: str,
    service_domain: str,
) -> dict[str, Any]:
    sev = _severity_for_service(service_domain)
    return {
        "event_type":   "email_service_exposure",
        "severity":     sev,
        "source_type":  "scanner",
        "source_name":  "holehe",
        "target_domain": target_domain,
        "payload": {
            "email":          email,
            "service":        service,
            "service_domain": service_domain,
            "risk_level":     sev,
            "detected_at":    datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "description":    (
                f"Корпоративный email зарегистрирован на {service}. "
                "Компрометация почты = автоматический доступ к этому аккаунту."
            ),
        },
    }


async def _run_holehe_async(email: str) -> list[dict[str, Any]]:
    """
    Асинхронно запускает holehe для одного email.
    Возвращает список найденных сервисов.
    """
    try:
        from holehe.core import get_functions, Triple  # type: ignore[import]
    except ImportError:
        return []

    client_get = None
    try:
        import httpx
        # holehe использует httpx/aiohttp клиент
        async with httpx.AsyncClient() as client_get:
            modules = get_functions()
            results: list[dict] = []
            for module in modules:
                try:
                    out: list[Triple] = []
                    await module(email, client_get, out)
                    for triple in out:
                        if triple.exists:
                            results.append({
                                "service":        triple.module,
                                "service_domain": getattr(triple, "domain", triple.module),
                            })
                except Exception:
                    pass
            return results
    except Exception as exc:
        logger.warning("[holehe] Ошибка async run: %s", exc)
        return []


def _run_holehe_cli(email: str) -> list[dict[str, Any]]:
    """
    Fallback: запуск holehe через subprocess если async API недоступен.
    """
    import subprocess
    import shutil

    binary = shutil.which("holehe")
    if not binary:
        return []

    try:
        result = subprocess.run(
            [binary, email, "--only-used", "--no-color"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        found = []
        for line in result.stdout.splitlines():
            line = line.strip()
            # holehe выводит: "[+] service_name"
            if line.startswith("[+]"):
                service = line[3:].strip()
                found.append({"service": service, "service_domain": service})
        return found
    except Exception as exc:
        logger.warning("[holehe] CLI fallback ошибка: %s", exc)
        return []


@app.task(bind=True, name="holehe_scanner.check_email", max_retries=1)
def check_email(self, email: str, target_domain: str) -> dict[str, Any]:
    """
    Проверяет корпоративный email на регистрацию в 120+ сервисах.

    Args:
        email:         Почта сотрудника (например ceo@company.com).
        target_domain: Домен клиента для группировки событий.

    Returns:
        {"status": "ok", "services_found": N, "high_risk": M}
    """
    if not _check_holehe():
        return {"status": "skipped", "reason": "holehe not installed", "services_found": 0}

    logger.info("[holehe] Проверка %s для домена %s", email, target_domain)

    try:
        services = asyncio.run(_run_holehe_async(email))
    except Exception as exc:
        logger.warning("[holehe] Async API недоступен, пробую CLI: %s", exc)
        services = _run_holehe_cli(email)

    if not services:
        logger.info("[holehe] %s: сервисов не найдено", email)
        return {"status": "ok", "services_found": 0, "high_risk": 0}

    client = IngestClient(
        core_api_url=settings.core_api_url,
        internal_secret=settings.internal_api_secret,
    )

    high_risk = 0
    sent = 0
    for svc in services:
        ev = _holehe_event(
            email=email,
            target_domain=target_domain,
            service=svc["service"],
            service_domain=svc.get("service_domain", svc["service"]),
        )
        if ev["severity"] == "high":
            high_risk += 1
        try:
            client.send(ev)
            sent += 1
        except Exception as exc:
            logger.warning("[holehe] Ingest error: %s", exc)

    logger.info(
        "[holehe] %s: найдено %d сервисов (%d высокого риска)",
        email, len(services), high_risk,
    )
    return {
        "status":         "ok",
        "email":          email,
        "services_found": len(services),
        "high_risk":      high_risk,
        "sent":           sent,
    }


@app.task(bind=True, name="holehe_scanner.check_domain_emails", max_retries=1)
def check_domain_emails(self, emails: list[str], target_domain: str) -> dict[str, Any]:
    """Проверяет список корпоративных email (batch для full_scan)."""
    total_services = 0
    total_high_risk = 0
    for email in emails[:10]:   # лимит 10 email за один запуск (время ~120с)
        result = check_email.run(email, target_domain)
        total_services += result.get("services_found", 0)
        total_high_risk += result.get("high_risk", 0)

    return {
        "status":         "ok",
        "emails_checked": len(emails[:10]),
        "services_found": total_services,
        "high_risk":      total_high_risk,
    }
