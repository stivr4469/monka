import asyncio
import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select

from app.api.deps import DBDep, verify_internal_secret
from app.core.config import settings
from app.models.asset import Asset
from app.models.event import Event
from app.models.organization import Organization
from app.schemas.normalized_event import BulkIngestRequest, NormalizedEvent
from app.services.opensearch_client import index_event
from app.services.webhook import notify_critical_event
from app.workers_client import ensure_workers_path, get_executor

logger = logging.getLogger(__name__)

# Подключаем workers/ к sys.path через единый синглтон
ensure_workers_path()

try:
    from tasks.telegram_alerts import dispatch_alerts as _dispatch_alerts
    _ALERTS_AVAILABLE = True
except ImportError:
    _ALERTS_AVAILABLE = False

_SEVERITY_FOR_ALERTS = {"low", "medium", "high", "critical"}

_APP_PORT: int = settings.APP_PORT

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

    # Загружаем организацию для webhook (только если нужно — при critical)
    org: Organization | None = None
    if asset is not None and event.severity == "critical":
        org_result = await db.execute(
            select(Organization).where(Organization.id == asset.organization_id)
        )
        org = org_result.scalar_one_or_none()

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

    # Отправляем Telegram-алерт в фоне для non-info событий
    if _ALERTS_AVAILABLE and event.severity in _SEVERITY_FOR_ALERTS and settings.TELEGRAM_BOT_TOKEN:
        core_url = f"http://127.0.0.1:{_APP_PORT}"
        get_executor().submit(
            _dispatch_alerts,
            event.model_dump(),
            core_url,
            settings.INTERNAL_API_SECRET,
            settings.TELEGRAM_BOT_TOKEN,
        )

    # Отправляем webhook-уведомление для критических событий (если задан webhook_url)
    if event.severity == "critical" and org is not None and org.webhook_url:
        notify_critical_event(
            webhook_url=org.webhook_url,
            event_type=event.event_type,
            domain=event.target_domain,
            severity=event.severity,
            detected_at=db_event.detected_at,
            source_name=event.source_name,
        )

    # 7.C.1: Дублируем событие в OpenSearch асинхронно (не блокирует ответ)
    asyncio.ensure_future(
        index_event(db_event.id, {
            "event_type":    db_event.event_type,
            "severity":      db_event.severity,
            "source_type":   db_event.source_type,
            "source_name":   db_event.source_name,
            "target_domain": db_event.target_domain,
            "detected_at":   db_event.detected_at.isoformat() if db_event.detected_at else None,
            "dedup_hash":    db_event.dedup_hash,
            "payload":       db_event.payload or {},
        })
    )

    return {"status": "accepted", "event_id": db_event.id}


@router.post("/ingest/bulk", status_code=status.HTTP_202_ACCEPTED)
async def bulk_ingest_events(body: BulkIngestRequest, db: DBDep) -> dict:
    """
    7.B.2: Батчевый приём событий — один запрос вместо N×HTTP.
    Дедупликация: один SELECT IN (...) для всего батча.
    Вставка: db.add_all() за одну транзакцию.
    """
    if not body.events:
        return {"status": "accepted", "accepted": 0, "duplicates": 0, "errors": 0}

    # Собираем все dedup_hash батча
    hashes = [e.dedup_hash for e in body.events if e.dedup_hash]

    # Один запрос для проверки дублей
    existing_hashes: set[str] = set()
    if hashes:
        existing_result = await db.execute(
            select(Event.dedup_hash).where(Event.dedup_hash.in_(hashes))
        )
        existing_hashes = {row[0] for row in existing_result.all()}

    accepted = duplicates = errors = 0
    new_events: list[Event] = []

    for event in body.events:
        if event.dedup_hash and event.dedup_hash in existing_hashes:
            duplicates += 1
            continue

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
        new_events.append(db_event)

    if new_events:
        try:
            db.add_all(new_events)
            await db.commit()
            for ev in new_events:
                await db.refresh(ev)
            accepted = len(new_events)
        except Exception as exc:
            await db.rollback()
            logger.error("Ошибка bulk insert: %s", exc)
            errors = len(new_events)

    # 7.C.1: Асинхронная индексация в OpenSearch
    for ev in new_events:
        if ev.id:
            asyncio.ensure_future(
                index_event(ev.id, {
                    "event_type":    ev.event_type,
                    "severity":      ev.severity,
                    "source_type":   ev.source_type,
                    "source_name":   ev.source_name,
                    "target_domain": ev.target_domain,
                    "detected_at":   ev.detected_at.isoformat() if ev.detected_at else None,
                    "dedup_hash":    ev.dedup_hash,
                    "payload":       ev.payload or {},
                })
            )

    return {
        "status": "partial" if errors else "accepted",
        "accepted": accepted,
        "duplicates": duplicates,
        "errors": errors,
    }
