import asyncio
import uuid as _uuid
import logging
from datetime import datetime, timezone
from typing import Coroutine, Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select

from app.api.deps import DBDep, verify_internal_secret
from app.core.config import settings
from app.db import AsyncSessionLocal
from app.models.asset import Asset
from app.models.event import Event
from app.models.notification import Notification
from app.models.organization import Organization
from app.schemas.normalized_event import BulkIngestRequest, NormalizedEvent
from app.services.correlation import correlate_event
from app.services.graph_client import upsert_event_to_graph
from app.services.opensearch_client import index_event, index_leaked_credential
from app.services.webhook import notify_critical_event
from app.workers_client import ensure_workers_path, get_executor

logger = logging.getLogger(__name__)


def _create_bg_task(coro: Coroutine[Any, Any, Any]) -> asyncio.Task:
    """CRITICAL-5: create_task вместо ensure_future + логирование необработанных исключений."""
    task = asyncio.create_task(coro)
    task.add_done_callback(_log_task_exc)
    return task


def _log_task_exc(task: asyncio.Task) -> None:
    if not task.cancelled() and task.exception():
        logger.error("Фоновая задача завершилась с ошибкой: %s", task.exception(), exc_info=task.exception())


def _is_cred_event(source_type: str | None, event_type: str | None) -> bool:
    """DRY-хелпер: определяет является ли событие credential-leak (MEDIUM-8)."""
    return (
        source_type in ("stealer_log", "breach_checker")
        or event_type in ("credential_leak", "active_session_leak", "stealer_log")
    )


def _auto_condition(event_type: str, payload: dict) -> str | None:
    """
    9.H.3: Авто-генерация текстового условия для снятия штрафа Risk Score.

    Возвращает строку с рекомендацией по устранению угрозы или None
    если для данного типа события условие не определено.
    """
    # Открытый сетевой сервис — указываем конкретный порт и хост
    if event_type == "exposed_service":
        port = payload.get("port", "?")
        host = payload.get("host", "")
        return f"Закройте порт {port} на хосте {host}" if host else f"Закройте порт {port}"

    # Утечки учётных данных — смена пароля обязательна
    if event_type in ("credential_leak", "stealer_log"):
        return "Смените скомпрометированный пароль"

    # Активная сессия — принудительный logout
    if event_type == "active_session_leak":
        return "Завершите активную сессию — принудительный logout"

    # Фишинговый домен — блокировка через регистратора
    if event_type == "phishing_domain":
        return "Заблокируйте фишинговый домен через регистратора"

    # Захват поддомена — удалить или исправить CNAME
    if event_type == "subdomain_takeover":
        return "Удалите или обновите CNAME-запись поддомена"

    # Истекающий TLS-сертификат
    if event_type == "tls_expiry":
        return "Обновите TLS-сертификат до истечения срока"

    # Публичный S3-bucket
    if event_type == "open_s3_bucket":
        return "Закройте публичный доступ к S3-bucket"

    # Дрейф конфигурации инфраструктуры
    if event_type == "asset_drift":
        return "Проверьте изменения в конфигурации инфраструктуры"

    # Упоминание в даркнете — требует расследования
    if event_type == "darknet_mention":
        return "Проведите расследование упоминания в даркнете"

    # Утечка секретов/ключей в GitHub
    if event_type == "github_secret_leak":
        return "Немедленно ротируйте скомпрометированные ключи/секреты"

    # Для остальных типов событий условие не генерируется
    return None


# Подключаем workers/ к sys.path через единый синглтон
ensure_workers_path()

try:
    from workers.tasks.telegram_alerts import dispatch_alerts as _dispatch_alerts
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

    Data Lake: credential-события без привязанного актива пишутся только в
    OpenSearch (easm-leaked-credentials) — PostgreSQL не раздувается сырыми логами стилеров.
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

    # Data Lake: сырые credential-логи без клиентского актива → только OpenSearch
    if asset is None and _is_cred_event(event.source_type, event.event_type):
        _os_data = {
            "event_type":    event.event_type,
            "severity":      event.severity,
            "source_type":   event.source_type,
            "source_name":   event.source_name,
            "target_domain": event.target_domain,
            "detected_at":   event.detected_at.isoformat() if event.detected_at else None,
            "dedup_hash":    event.dedup_hash,
            "payload":       event.payload or {},
        }
        _create_bg_task(index_leaked_credential(str(_uuid.uuid4()), _os_data))
        logger.debug("Credential без актива → OpenSearch only: %s", event.target_domain)
        return {"status": "accepted_opensearch_only", "event_id": None}

    # Загружаем организацию для webhook (только если нужно — при critical)
    org: Organization | None = None
    if asset is not None and event.severity == "critical":
        org_result = await db.execute(
            select(Organization).where(Organization.id == asset.organization_id)
        )
        org = org_result.scalar_one_or_none()

    # 9.H.3: Авто-генерируем condition если явно не передан
    condition = event.condition or _auto_condition(event.event_type, event.payload)

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
        condition=condition,
        ingested_at=datetime.now(timezone.utc),
    )
    db.add(db_event)

    try:
        await db.commit()
        await db.refresh(db_event)
    except Exception as exc:
        await db.rollback()
        logger.error("Ошибка сохранения события: %s", exc)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Ошибка сохранения события") from exc

    logger.info(
        "Событие принято: id=%s type=%s severity=%s domain=%s",
        db_event.id,
        db_event.event_type,
        db_event.severity,
        db_event.target_domain,
    )

    # Correlation Engine: группируем событие в инцидент в фоне
    _create_bg_task(correlate_event(db_event.id, AsyncSessionLocal))

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

    # 10.I: Создаём уведомление в центре нотификаций для critical-событий
    if event.severity == "critical" and asset is not None:
        try:
            notif = Notification(
                org_id=asset.organization_id,
                event_id=db_event.id,
                message=f"\U0001f6a8 {event.event_type}: {event.target_domain}",
                severity="critical",
                is_read=False,
            )
            db.add(notif)
            await db.commit()
        except Exception as exc:
            logger.warning("[ingest] Ошибка создания уведомления: %s", exc, exc_info=True)
            await db.rollback()

    # 7.C.1 / 9.I: Дублируем событие в OpenSearch асинхронно (не блокирует ответ).
    # Credential-события (стилер / breach) идут в специализированный индекс
    # easm-leaked-credentials с оптимизированным маппингом и ILM-политикой.
    _os_event_data = {
        "event_type":    db_event.event_type,
        "severity":      db_event.severity,
        "source_type":   db_event.source_type,
        "source_name":   db_event.source_name,
        "target_domain": db_event.target_domain,
        "detected_at":   db_event.detected_at.isoformat() if db_event.detected_at else None,
        "dedup_hash":    db_event.dedup_hash,
        "payload":       db_event.payload or {},
    }
    _is_credential_event = _is_cred_event(event.source_type, event.event_type)
    if _is_credential_event:
        _create_bg_task(index_leaked_credential(str(db_event.id), _os_event_data))
    else:
        _create_bg_task(index_event(db_event.id, _os_event_data))

    # 9.E: Обновляем Neo4j-граф асинхронно (graceful: если Neo4j недоступен — игнорируем)
    _create_bg_task(upsert_event_to_graph(event.model_dump()))

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

    # CRITICAL-4: один запрос для всех доменов батча вместо N запросов в цикле
    domains_in_batch = {e.target_domain for e in body.events if e.target_domain}
    domain_to_asset: dict[str, Asset] = {}
    if domains_in_batch:
        assets_result = await db.execute(
            select(Asset).where(
                Asset.domain.in_(domains_in_batch),
                Asset.is_active.is_(True),
            )
        )
        domain_to_asset = {a.domain: a for a in assets_result.scalars()}

    accepted = duplicates = errors = 0
    new_events: list[Event] = []
    # Data Lake: credential-события без актива → только OpenSearch, не в PG
    opensearch_only: list[dict] = []

    for event in body.events:
        if event.dedup_hash and event.dedup_hash in existing_hashes:
            duplicates += 1
            continue

        asset = domain_to_asset.get(event.target_domain or "")

        # Data Lake: сырой credential-лог без клиентского актива → OpenSearch only
        if asset is None and _is_cred_event(event.source_type, event.event_type):
            opensearch_only.append({
                "event_type":    event.event_type,
                "severity":      event.severity,
                "source_type":   event.source_type,
                "source_name":   event.source_name,
                "target_domain": event.target_domain,
                "detected_at":   event.detected_at.isoformat() if event.detected_at else None,
                "dedup_hash":    event.dedup_hash,
                "payload":       event.payload or {},
            })
            duplicates += 1  # засчитываем как "не в PG" — не в accepted, не в errors
            continue

        # 9.H.3: Авто-генерируем condition если явно не передан
        condition = event.condition or _auto_condition(event.event_type, event.payload)
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
            condition=condition,
            ingested_at=datetime.now(timezone.utc),
        )
        new_events.append(db_event)

    # Отправляем сырые credential-логи в OpenSearch (без PostgreSQL)
    for _os_data in opensearch_only:
        _create_bg_task(index_leaked_credential(str(_uuid.uuid4()), _os_data))

    if new_events:
        try:
            db.add_all(new_events)
            await db.commit()
            for ev in new_events:
                await db.refresh(ev)
            accepted = sum(1 for ev in new_events if ev.id is not None)
        except Exception as exc:
            await db.rollback()
            logger.warning("Батч упал (%s), переходим на поштучную вставку через savepoint", exc)
            # Savepoint-фолбэк: спасаем валидные записи по одной
            for ev in new_events:
                try:
                    async with db.begin_nested():  # SAVEPOINT
                        db.add(ev)
                    await db.commit()
                    accepted += 1
                except Exception as single_exc:
                    logger.error(
                        "Битое событие пропущено: domain=%s type=%s err=%s",
                        ev.target_domain, ev.event_type, single_exc,
                    )
                    errors += 1

    # 7.C.1 / 9.I: Асинхронная индексация в OpenSearch.
    # Credential-события → easm-leaked-credentials, остальные → easm-events.
    for ev in new_events:
        if not ev.id:
            continue
        _ev_data = {
            "event_type":    ev.event_type,
            "severity":      ev.severity,
            "source_type":   ev.source_type,
            "source_name":   ev.source_name,
            "target_domain": ev.target_domain,
            "detected_at":   ev.detected_at.isoformat() if ev.detected_at else None,
            "dedup_hash":    ev.dedup_hash,
            "payload":       ev.payload or {},
        }
        if _is_cred_event(ev.source_type, ev.event_type):
            _create_bg_task(index_leaked_credential(str(ev.id), _ev_data))
        else:
            _create_bg_task(index_event(ev.id, _ev_data))
        # 9.E: Neo4j-граф для каждого события батча
        _create_bg_task(upsert_event_to_graph(_ev_data))

        # Telegram-алерт для critical/high событий (зеркалирует логику ingest_event)
        if _ALERTS_AVAILABLE and ev.severity in _SEVERITY_FOR_ALERTS and settings.TELEGRAM_BOT_TOKEN:
            core_url = f"http://127.0.0.1:{_APP_PORT}"
            get_executor().submit(
                _dispatch_alerts,
                _ev_data,
                core_url,
                settings.INTERNAL_API_SECRET,
                settings.TELEGRAM_BOT_TOKEN,
            )

    return {
        "status": "partial" if errors else "accepted",
        "accepted": accepted,
        "duplicates": duplicates,
        "errors": errors,
    }
