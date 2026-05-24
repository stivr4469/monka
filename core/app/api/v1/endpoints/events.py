from datetime import datetime
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select, func

from app.api.deps import CurrentUser, DBDep
from app.core.config import settings
from app.core.crypto import decrypt_password
from app.models.event import Event

router = APIRouter(prefix="/events", tags=["events"])


class EventRead(BaseModel):
    id: str
    event_type: str
    severity: str
    source_type: str
    source_name: str
    target_domain: str
    payload: dict
    detected_at: datetime

    model_config = {"from_attributes": True}


class EventStats(BaseModel):
    total: int
    by_severity: dict[str, int]
    by_type: dict[str, int]


@router.get("/", response_model=list[EventRead])
async def list_events(
    db: DBDep,
    current_user: CurrentUser,
    domain: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    event_type: str | None = Query(default=None),
    limit: int = Query(default=50, le=500),
) -> list[Event]:
    q = select(Event).order_by(Event.detected_at.desc()).limit(limit)
    if domain:
        q = q.where(Event.target_domain == domain)
    if severity:
        q = q.where(Event.severity == severity)
    if event_type:
        q = q.where(Event.event_type == event_type)
    result = await db.execute(q)
    return list(result.scalars().all())


@router.get("/stats", response_model=EventStats)
async def event_stats(
    db: DBDep,
    current_user: CurrentUser,
    domain: str | None = Query(default=None),
) -> EventStats:
    """Сводная статистика по событиям."""
    base_q = select(Event)
    if domain:
        base_q = base_q.where(Event.target_domain == domain)

    # Всего
    total_r = await db.execute(select(func.count()).select_from(base_q.subquery()))
    total = total_r.scalar_one()

    # По severity
    sev_q = select(Event.severity, func.count()).group_by(Event.severity)
    if domain:
        sev_q = sev_q.where(Event.target_domain == domain)
    sev_r = await db.execute(sev_q)
    by_severity = dict(sev_r.all())

    # По типу
    type_q = select(Event.event_type, func.count()).group_by(Event.event_type)
    if domain:
        type_q = type_q.where(Event.target_domain == domain)
    type_r = await db.execute(type_q)
    by_type = dict(type_r.all())

    return EventStats(total=total, by_severity=by_severity, by_type=by_type)


@router.post("/{event_id}/reveal", summary="Расшифровать пароль из стилер-лога")
async def reveal_password(
    event_id: str,
    db: DBDep,
    current_user: CurrentUser,
) -> dict:
    """
    Возвращает расшифрованный пароль для события stealer_log.
    Требует JWT-авторизацию. Каждый запрос логируется.
    """
    result = await db.execute(select(Event).where(Event.id == event_id))
    event = result.scalar_one_or_none()

    if not event:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Событие не найдено")

    if event.event_type != "stealer_log":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Расшифровка доступна только для событий stealer_log",
        )

    enc = event.payload.get("password_enc", "")
    if not enc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Зашифрованный пароль не найден в payload",
        )

    try:
        password = decrypt_password(enc, settings.INTERNAL_API_SECRET)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))

    return {
        "event_id": event_id,
        "login": event.payload.get("login", ""),
        "password": password,
        "url": event.payload.get("url", ""),
    }
