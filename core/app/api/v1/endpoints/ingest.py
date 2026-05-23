import logging
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import DBDep, verify_internal_secret
from app.models.asset import Asset
from app.models.event import Event
from app.schemas.normalized_event import NormalizedEvent

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/internal",
    tags=["internal"],
    dependencies=[Depends(verify_internal_secret)],
)


@router.post("/ingest", status_code=status.HTTP_202_ACCEPTED)
async def ingest_event(event: NormalizedEvent, db: DBDep) -> dict:
    """
    Принимает нормализованные события от Celery-воркеров.
    Дедуплицирует по dedup_hash — повторное событие возвращает 202 без записи.
    """
    # Дедупликация
    if event.dedup_hash:
        existing = await db.execute(
            select(Event).where(Event.dedup_hash == event.dedup_hash)
        )
        if existing.scalar_one_or_none():
            logger.debug("Дубликат события пропущен: %s", event.dedup_hash)
            return {"status": "duplicate", "detail": "Событие уже существует"}

    # Привязываем к активу, если он зарегистрирован
    asset_result = await db.execute(
        select(Asset).where(Asset.domain == event.target_domain, Asset.is_active == True)  # noqa: E712
    )
    asset = asset_result.scalar_one_or_none()

    db_event = Event(
        event_type=event.event_type,
        severity=event.severity,
        source_type=event.source_type,
        source_name=event.source_name,
        target_domain=event.target_domain,
        payload=event.payload,
        detected_at=event.detected_at,
        dedup_hash=event.dedup_hash,
        asset_id=asset.id if asset else None,
    )
    db.add(db_event)

    try:
        await db.commit()
        await db.refresh(db_event)
    except Exception as exc:
        await db.rollback()
        logger.error("Ошибка сохранения события: %s", exc)
        raise HTTPException(status_code=500, detail="Ошибка сохранения события") from exc

    logger.info(
        "Событие принято: id=%s type=%s severity=%s domain=%s",
        db_event.id,
        db_event.event_type,
        db_event.severity,
        db_event.target_domain,
    )
    return {"status": "accepted", "event_id": db_event.id}
