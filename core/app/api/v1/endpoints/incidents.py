"""
Эндпоинты Correlation Engine — инциденты.

Инцидент — группа связанных событий одного актива одного семейства
в пределах временного окна WINDOW_HOURS.

ВАЖНО: фильтрация по organization_id пользователя гарантирует
изоляцию тенантов (через JOIN Event → Asset → Organization).
"""
from datetime import datetime

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from app.api.deps import CurrentUser, DBDep
from app.services.correlation import get_incident_events, get_open_incidents

router = APIRouter(prefix="/incidents", tags=["incidents"])


# ---------------------------------------------------------------------------
# Схемы ответов
# ---------------------------------------------------------------------------

class IncidentSummary(BaseModel):
    """Краткая сводка по инциденту."""
    incident_id: str
    event_count: int
    max_severity: str
    first_seen: datetime
    last_seen: datetime
    asset_id: str | None
    family: str

    model_config = {"from_attributes": True}


class IncidentEventRead(BaseModel):
    """Событие инцидента (упрощённая проекция)."""
    id: str
    event_type: str
    severity: str
    source_type: str
    source_name: str
    target_domain: str
    payload: dict
    detected_at: datetime
    resolved: bool
    incident_id: str | None

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Эндпоинты
# ---------------------------------------------------------------------------

@router.get("", response_model=list[IncidentSummary])
async def list_incidents(
    current_user: CurrentUser,
    db: DBDep,
) -> list[dict]:
    """
    Список активных инцидентов организации.

    Возвращает инциденты отсортированные по severity DESC, затем last_seen DESC.
    """
    incidents = await get_open_incidents(current_user.organization_id, db)
    return incidents


@router.get("/{incident_id}/events", response_model=list[IncidentEventRead])
async def get_events_by_incident(
    incident_id: str,
    current_user: CurrentUser,
    db: DBDep,
) -> list:
    """
    События инцидента.

    Проверяет что хотя бы одно событие принадлежит организации пользователя
    (через asset_id → assets.organization_id), иначе 404.
    """
    from sqlalchemy import select
    from app.models.asset import Asset
    from app.models.event import Event

    # Загружаем события инцидента
    events = await get_incident_events(incident_id, db)

    if not events:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Инцидент {incident_id!r} не найден",
        )

    # Проверка принадлежности к организации: хотя бы одно событие
    # должно иметь asset в org пользователя
    asset_ids = {ev.asset_id for ev in events if ev.asset_id}
    if not asset_ids:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Инцидент {incident_id!r} не найден",
        )

    from sqlalchemy import select as _select
    result = await db.execute(
        _select(Asset.id).where(
            Asset.id.in_(asset_ids),
            Asset.organization_id == current_user.organization_id,
        ).limit(1)
    )
    if result.scalar_one_or_none() is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Инцидент {incident_id!r} не найден",
        )

    return events
