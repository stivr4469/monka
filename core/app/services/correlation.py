"""
Correlation Engine — группировка связанных событий в инциденты.

Логика корреляции:
- Два события коррелируют если:
    1. одинаковый asset_id (не None)
    2. разница по detected_at ≤ WINDOW_HOURS (default 24h)
    3. принадлежат одной family (сетевые, credential, recon, web, threat, code)
- Если в окне уже есть инцидент → присвоить его incident_id
- Если нет → создать новый UUID как incident_id
"""
import uuid
import logging
from collections.abc import AsyncGenerator, Callable
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.event import Event

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession as _AsyncSession

logger = logging.getLogger(__name__)

# Временное окно корреляции (часов)
WINDOW_HOURS: int = 24

# Семейства типов событий для корреляции
EVENT_FAMILIES: dict[str, frozenset[str]] = {
    "network": frozenset({
        "port_scan", "exposed_service", "masscan_result",
    }),
    "credential": frozenset({
        "stealer_log", "credential_leak", "email_breach", "active_session_leak",
    }),
    "recon": frozenset({
        "subdomain_found", "dns_record", "whois_change", "cert_transparency",
    }),
    "web": frozenset({
        "tech_profile", "tls_fingerprint", "http_header", "cookie_issue",
    }),
    "threat": frozenset({
        "ransomware_mention", "darknet_mention", "paste_mention", "brand_abuse",
    }),
    "code": frozenset({
        "github_secret_leak", "gitleaks_finding",
    }),
}

# Обратный индекс: event_type → family
_TYPE_TO_FAMILY: dict[str, str] = {
    event_type: family
    for family, event_types in EVENT_FAMILIES.items()
    for event_type in event_types
}


def _get_family(event_type: str) -> str | None:
    """Возвращает имя семейства для типа события или None если не определено."""
    return _TYPE_TO_FAMILY.get(event_type)


async def correlate_event(
    event_id: str,
    db_factory: Callable[[], "AsyncGenerator[AsyncSession, None]"],
) -> str | None:
    """
    Присваивает событию incident_id по правилам корреляции.

    Принимает фабрику сессий (AsyncSessionLocal), а не саму сессию —
    фоновая задача не должна использовать request-scoped сессию которая
    будет закрыта до завершения задачи.

    Возвращает incident_id (UUID str) или None если событие изолировано.
    """
    async with db_factory() as db:
        # Загружаем целевое событие
        result = await db.execute(select(Event).where(Event.id == event_id))
        event = result.scalar_one_or_none()

        if event is None:
            logger.warning("[correlation] Событие не найдено: id=%s", event_id)
            return None

        # Событие без привязанного актива коррелировать нельзя
        if event.asset_id is None:
            return None

        # Определяем семейство
        family = _get_family(event.event_type)
        if family is None:
            return None

        # Все типы событий одного семейства
        family_types = list(EVENT_FAMILIES[family])

        # Временное окно
        window_start = event.detected_at - timedelta(hours=WINDOW_HOURS)
        window_end = event.detected_at + timedelta(hours=WINDOW_HOURS)

        # Ищем существующий инцидент в окне: событие того же актива и семейства
        # с уже присвоенным incident_id
        stmt = (
            select(Event.incident_id)
            .where(
                Event.asset_id == event.asset_id,
                Event.event_type.in_(family_types),
                Event.incident_id.is_not(None),
                Event.detected_at >= window_start,
                Event.detected_at <= window_end,
                Event.id != event_id,
            )
            .order_by(Event.detected_at.asc())
            .limit(1)
        )
        existing = await db.execute(stmt)
        row = existing.scalar_one_or_none()

        incident_id: str = row if row else str(uuid.uuid4())

        # Сохраняем incident_id в событие
        event.incident_id = incident_id
        try:
            await db.commit()
            logger.info(
                "[correlation] event_id=%s → incident_id=%s (family=%s)",
                event_id, incident_id, family,
            )
        except Exception as exc:
            await db.rollback()
            logger.error("[correlation] Ошибка сохранения incident_id: %s", exc)
            return None

        return incident_id


async def get_incident_events(incident_id: str, db: AsyncSession) -> list[Event]:
    """Возвращает все события, принадлежащие инциденту."""
    result = await db.execute(
        select(Event)
        .where(Event.incident_id == incident_id)
        .order_by(Event.detected_at.asc())
    )
    return list(result.scalars().all())


async def get_open_incidents(org_id: str, db: AsyncSession) -> list[dict]:
    """
    Возвращает список активных инцидентов организации.

    Каждый инцидент содержит:
    - incident_id: str
    - event_count: int
    - max_severity: str (наихудший уровень)
    - first_seen: datetime
    - last_seen: datetime
    - asset_id: str | None
    - family: str (семейство событий)
    """
    from app.models.asset import Asset  # локальный импорт для избежания циклов

    # Severity-порядок для выбора наихудшей оценки
    severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    # Загружаем события организации с incident_id через JOIN с assets
    stmt = (
        select(Event)
        .join(Asset, Asset.id == Event.asset_id)
        .where(
            Asset.organization_id == org_id,
            Event.incident_id.is_not(None),
        )
        .order_by(Event.incident_id, Event.detected_at.asc())
    )
    result = await db.execute(stmt)
    events = list(result.scalars().all())

    # Группируем по incident_id
    incidents_map: dict[str, dict] = {}
    for ev in events:
        iid = ev.incident_id  # гарантированно не None по WHERE
        if iid is None:
            continue
        if iid not in incidents_map:
            incidents_map[iid] = {
                "incident_id": iid,
                "event_count": 0,
                "max_severity": "info",
                "first_seen": ev.detected_at,
                "last_seen": ev.detected_at,
                "asset_id": ev.asset_id,
                "family": _get_family(ev.event_type) or "unknown",
            }
        entry = incidents_map[iid]
        entry["event_count"] += 1
        if ev.detected_at < entry["first_seen"]:
            entry["first_seen"] = ev.detected_at
        if ev.detected_at > entry["last_seen"]:
            entry["last_seen"] = ev.detected_at
        # Обновляем наихудшую severity
        if severity_order.get(ev.severity, 0) > severity_order.get(entry["max_severity"], 0):
            entry["max_severity"] = ev.severity

    # Сортируем: сначала critical, потом по last_seen DESC
    def _sort_key(inc: dict) -> tuple:
        return (
            -severity_order.get(inc["max_severity"], 0),
            -(inc["last_seen"].timestamp() if inc["last_seen"] else 0),
        )

    return sorted(incidents_map.values(), key=_sort_key)
