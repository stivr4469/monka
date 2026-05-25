"""
Ticketing integration — создание тикетов в Jira и ServiceNow.
Без внешних SDK — только httpx + REST API.
"""
import logging
import os
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_TIMEOUT = httpx.Timeout(30.0)

# Jira
_JIRA_URL = os.environ.get("JIRA_URL", "")           # https://company.atlassian.net
_JIRA_USER = os.environ.get("JIRA_USER", "")          # user@company.com
_JIRA_TOKEN = os.environ.get("JIRA_API_TOKEN", "")    # API token
_JIRA_PROJECT = os.environ.get("JIRA_PROJECT_KEY", "SEC")  # проект

# ServiceNow
_SNOW_URL = os.environ.get("SERVICENOW_URL", "")      # https://company.service-now.com
_SNOW_USER = os.environ.get("SERVICENOW_USER", "")
_SNOW_PASS = os.environ.get("SERVICENOW_PASSWORD", "")

_JIRA_AVAILABLE = bool(_JIRA_URL and _JIRA_USER and _JIRA_TOKEN)
_SNOW_AVAILABLE = bool(_SNOW_URL and _SNOW_USER and _SNOW_PASS)


# ── Маппинг severity на приоритет ──────────────────────────────────────────

SEVERITY_TO_JIRA_PRIORITY = {
    "critical": "Highest",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}

SEVERITY_TO_SNOW_URGENCY = {
    "critical": "1",  # 1=High, 2=Medium, 3=Low
    "high": "1",
    "medium": "2",
    "low": "3",
}


def create_jira_ticket(
    event: dict[str, Any],
    hints: list[str],
) -> dict[str, Any] | None:
    """
    Создаёт тикет в Jira через REST API v3.
    POST https://{jira_url}/rest/api/3/issue

    Returns: {"ticket_id": "SEC-123", "url": "...", "platform": "jira"} или None при ошибке.
    """
    if not _JIRA_AVAILABLE:
        return None

    summary = f"[SURFACE] {event.get('event_type', '').upper()}: {event.get('target_domain', '')}"
    description = _build_description(event, hints)

    payload = {
        "fields": {
            "project": {"key": _JIRA_PROJECT},
            "summary": summary,
            "description": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [{"type": "text", "text": description}],
                    }
                ],
            },
            "issuetype": {"name": "Bug"},
            "priority": {
                "name": SEVERITY_TO_JIRA_PRIORITY.get(
                    event.get("severity", "low"), "Medium"
                )
            },
            "labels": [
                "security",
                "surface-platform",
                event.get("event_type", ""),
            ],
        }
    }

    try:
        resp = httpx.post(
            f"{_JIRA_URL}/rest/api/3/issue",
            json=payload,
            auth=(_JIRA_USER, _JIRA_TOKEN),
            timeout=_TIMEOUT,
        )
        if resp.status_code not in (200, 201):
            logger.error("Jira API error: %s %s", resp.status_code, resp.text[:500])
            return None

        data = resp.json()
        ticket_key = data.get("key", "")
        ticket_id = data.get("id", "")
        url = f"{_JIRA_URL}/browse/{ticket_key}"
        logger.info("Jira ticket created: %s", ticket_key)
        return {
            "ticket_id": ticket_key,
            "internal_id": ticket_id,
            "url": url,
            "platform": "jira",
        }
    except Exception as exc:
        logger.error("Jira ticket creation failed: %s", exc)
        return None


def create_snow_incident(
    event: dict[str, Any],
    hints: list[str],
) -> dict[str, Any] | None:
    """
    Создаёт инцидент в ServiceNow через REST API.
    POST https://{snow_url}/api/now/table/incident

    Returns: {"ticket_id": "INC0001234", "url": "...", "platform": "servicenow"} или None.
    """
    if not _SNOW_AVAILABLE:
        return None

    description = _build_description(event, hints)
    short_description = (
        f"[SURFACE] {event.get('event_type', '').upper()}: {event.get('target_domain', '')}"
    )

    payload = {
        "short_description": short_description,
        "description": description,
        "urgency": SEVERITY_TO_SNOW_URGENCY.get(event.get("severity", "low"), "3"),
        "impact": SEVERITY_TO_SNOW_URGENCY.get(event.get("severity", "low"), "3"),
        "category": "Security",
        "subcategory": "Vulnerability",
    }

    try:
        resp = httpx.post(
            f"{_SNOW_URL}/api/now/table/incident",
            json=payload,
            auth=(_SNOW_USER, _SNOW_PASS),
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            timeout=_TIMEOUT,
        )
        if resp.status_code not in (200, 201):
            logger.error("ServiceNow API error: %s %s", resp.status_code, resp.text[:500])
            return None

        data = resp.json().get("result", {})
        ticket_number = data.get("number", "")
        sys_id = data.get("sys_id", "")
        url = f"{_SNOW_URL}/nav_to.do?uri=incident.do?sys_id={sys_id}"
        logger.info("ServiceNow incident created: %s", ticket_number)
        return {
            "ticket_id": ticket_number,
            "sys_id": sys_id,
            "url": url,
            "platform": "servicenow",
        }
    except Exception as exc:
        logger.error("ServiceNow incident creation failed: %s", exc)
        return None


def _build_description(event: dict, hints: list[str]) -> str:
    """Формирует текст описания тикета."""
    lines = [
        "Security event detected by SURFACE Platform",
        "",
        f"Event Type: {event.get('event_type')}",
        f"Severity: {event.get('severity')}",
        f"Domain: {event.get('target_domain')}",
        f"Detected: {event.get('created_at', 'N/A')}",
        "",
        f"Details: {str(event.get('payload', {}))[:500]}",
        "",
        "Remediation Steps:",
    ]
    for i, hint in enumerate(hints, 1):
        lines.append(f"  {i}. {hint}")
    return "\n".join(lines)


def create_ticket_for_event(
    event: dict[str, Any],
) -> dict[str, Any]:
    """
    Основная функция — создаёт тикет в первом доступном провайдере.
    Приоритет: Jira > ServiceNow.

    Returns: {"created": bool, "platform": "jira"|"servicenow"|None, "ticket_id": str|None}
    """
    from tasks.remediation_hints import get_hints

    hints = get_hints(event.get("event_type", ""))

    # Пробуем Jira
    result = create_jira_ticket(event, hints)
    if result:
        return {"created": True, "platform": "jira", **result}

    # Fallback на ServiceNow
    result = create_snow_incident(event, hints)
    if result:
        return {"created": True, "platform": "servicenow", **result}

    return {"created": False, "platform": None, "ticket_id": None}
