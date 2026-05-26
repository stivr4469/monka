"""
Phase 13.H — Automated Remediation Playbooks: Jira / ServiceNow ticketing.

POST /api/v1/events/{event_id}/ticket  — создаёт тикет для события
GET  /api/v1/events/{event_id}/ticket  — возвращает статус тикета
"""
import sys
from pathlib import Path

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select

from app.api.deps import CurrentUser, DBDep
from app.models.asset import Asset
from app.models.event import Event

# Подключаем workers/ к sys.path для импорта ticketing
_workers_path = str(Path(__file__).parents[5] / "workers")
if _workers_path not in sys.path:
    sys.path.insert(0, _workers_path)

try:
    from workers.tasks.ticketing import (  # type: ignore[import]
        _JIRA_AVAILABLE,
        _SNOW_AVAILABLE,
        create_ticket_for_event,
    )

    _TICKETING_AVAILABLE = True
except ImportError:
    _TICKETING_AVAILABLE = False
    _JIRA_AVAILABLE = False
    _SNOW_AVAILABLE = False

    def create_ticket_for_event(event: dict) -> dict:  # type: ignore[misc]
        return {"created": False, "platform": None, "ticket_id": None}


router = APIRouter(tags=["tickets"])


class TicketResponse(BaseModel):
    """Ответ создания / статуса тикета."""

    created: bool
    platform: str | None = None
    ticket_id: str | None = None
    url: str | None = None
    ticket_ref: str | None = None


def _check_ticketing_available() -> None:
    """Выбрасывает 503 если ни Jira ни ServiceNow не настроены."""
    if not _JIRA_AVAILABLE and not _SNOW_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Ticketing не настроен. Установите переменные окружения: "
                "JIRA_URL/JIRA_USER/JIRA_API_TOKEN или "
                "SERVICENOW_URL/SERVICENOW_USER/SERVICENOW_PASSWORD"
            ),
        )


async def _get_event_for_org(event_id: str, organization_id: str, db) -> Event:
    """Возвращает событие с проверкой принадлежности к организации."""
    q = (
        select(Event)
        .join(Asset, Event.asset_id == Asset.id)
        .where(
            Event.id == event_id,
            Asset.organization_id == organization_id,
        )
    )
    result = await db.execute(q)
    event = result.scalar_one_or_none()
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Событие не найдено",
        )
    return event


@router.post("/{event_id}/ticket", response_model=TicketResponse)
async def create_ticket(
    event_id: str,
    db: DBDep,
    current_user: CurrentUser,
) -> TicketResponse:
    """
    13.H: Создаёт тикет в Jira или ServiceNow для события безопасности.

    Приоритет провайдеров: Jira > ServiceNow.
    Сохраняет ticket_ref в событии в формате "jira:SEC-123" или "servicenow:INC0001234".
    Возвращает 503 если ни один провайдер не настроен.
    """
    _check_ticketing_available()

    if current_user.organization_id is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Нет организации")

    event = await _get_event_for_org(event_id, current_user.organization_id, db)

    # Формируем dict-представление события для ticketing
    event_dict = {
        "id": event.id,
        "event_type": event.event_type,
        "severity": event.severity,
        "target_domain": event.target_domain,
        "payload": event.payload,
        "created_at": event.detected_at.isoformat() if event.detected_at else "N/A",
    }

    result = create_ticket_for_event(event_dict)

    # Сохраняем ссылку на тикет в БД
    if result.get("created") and result.get("ticket_id"):
        platform = result.get("platform", "")
        ticket_id = result.get("ticket_id", "")
        event.ticket_ref = f"{platform}:{ticket_id}"
        await db.commit()
        await db.refresh(event)

    return TicketResponse(
        created=result.get("created", False),
        platform=result.get("platform"),
        ticket_id=result.get("ticket_id"),
        url=result.get("url"),
        ticket_ref=event.ticket_ref,
    )


@router.get("/{event_id}/ticket", response_model=TicketResponse)
async def get_ticket_status(
    event_id: str,
    db: DBDep,
    current_user: CurrentUser,
) -> TicketResponse:
    """
    13.H: Возвращает статус тикета для события.

    Если тикет не создан — возвращает created=False.
    """
    if current_user.organization_id is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Нет организации")

    event = await _get_event_for_org(event_id, current_user.organization_id, db)

    if not event.ticket_ref:
        return TicketResponse(created=False, ticket_ref=None)

    # Разбираем ticket_ref формат "platform:ticket_id"
    parts = event.ticket_ref.split(":", 1)
    platform = parts[0] if len(parts) == 2 else None
    ticket_id = parts[1] if len(parts) == 2 else event.ticket_ref

    # Формируем URL для браузера
    url: str | None = None
    if platform == "jira":
        try:
            from workers.tasks.ticketing import _JIRA_URL  # type: ignore[import]

            url = f"{_JIRA_URL}/browse/{ticket_id}"
        except ImportError:
            pass
    elif platform == "servicenow":
        try:
            from workers.tasks.ticketing import _SNOW_URL  # type: ignore[import]

            url = f"{_SNOW_URL}/nav_to.do?uri=incident.do?number={ticket_id}"
        except ImportError:
            pass

    return TicketResponse(
        created=True,
        platform=platform,
        ticket_id=ticket_id,
        url=url,
        ticket_ref=event.ticket_ref,
    )
