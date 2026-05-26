"""
STIX 2.1 Export endpoint.

Экспорт событий безопасности в формате STIX 2.1 Bundle для подключения к SIEM.

Эндпоинты:
    GET /api/v1/export/stix           → Bundle JSON (inline)
    GET /api/v1/export/stix/bundle.json → Bundle JSON (attachment, для скачивания)

Требует авторизации (JWT или API-ключ).
Для MSSP: возвращаются только события организации текущего пользователя.
"""
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, Query, Response, status, HTTPException
from sqlalchemy import select

from app.api.deps import CurrentUser, DBDep
from app.models.asset import Asset
from app.models.event import Event

# Подключаем workers в sys.path для импорта stix_export
_workers_path = str(Path(__file__).parents[5] / "workers")
if _workers_path not in sys.path:
    sys.path.insert(0, _workers_path)

from workers.tasks.stix_export import events_to_stix_bundle, bundle_to_json  # noqa: E402

router = APIRouter(tags=["export"])

# Максимальное количество событий в одном Bundle
_MAX_EVENTS = 10_000


def _build_stix_response(bundle: dict, as_attachment: bool = False) -> Response:
    """Формирует HTTP Response с STIX Bundle JSON."""
    content = bundle_to_json(bundle).encode("utf-8")
    headers: dict[str, str] = {}
    if as_attachment:
        date_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        headers["Content-Disposition"] = f'attachment; filename="stix_bundle_{date_str}.json"'
    return Response(
        content=content,
        media_type="application/json",
        headers=headers,
    )


async def _fetch_events(
    db,
    organization_id: str,
    asset_id: str | None,
    days: int,
) -> list[dict]:
    """
    Запрашивает события из БД с фильтрацией по организации, активу и периоду.

    Изоляция тенантов гарантирована через JOIN к assets.organization_id.
    """
    since = datetime.now(timezone.utc) - timedelta(days=days)

    q = (
        select(Event)
        .join(Asset, Event.asset_id == Asset.id)
        .where(
            Asset.organization_id == organization_id,
            Event.detected_at >= since,
        )
        .order_by(Event.detected_at.desc())
        .limit(_MAX_EVENTS)
    )

    if asset_id:
        q = q.where(Event.asset_id == asset_id)

    result = await db.execute(q)
    events = result.scalars().all()

    # Конвертируем ORM-объекты в dict для stix_export
    return [
        {
            "event_type": e.event_type,
            "severity": e.severity,
            "target_domain": e.target_domain,
            "payload": e.payload or {},
            "detected_at": e.detected_at,
            "source_name": e.source_name,
        }
        for e in events
    ]


@router.get("/stix", summary="STIX 2.1 Bundle (inline JSON)")
async def export_stix(
    db: DBDep,
    current_user: CurrentUser,
    asset_id: str | None = Query(default=None, description="UUID актива для фильтрации"),
    days: int = Query(default=30, ge=1, le=365, description="Глубина выборки в днях"),
) -> Response:
    """
    Экспорт событий организации в формате STIX 2.1.

    Возвращает STIX Bundle JSON с:
    - Identity object (платформа/организация)
    - Indicator / ObservedData / Vulnerability / ThreatActor объектами

    Изоляция тенантов: только события СВОЕЙ организации.

    **Требует Authorization: Bearer <token или api_key>**
    """
    if current_user.organization_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Пользователь не привязан к организации",
        )

    events = await _fetch_events(db, current_user.organization_id, asset_id, days)

    # Имя организации: email домен как fallback
    org_name = current_user.email.split("@")[-1] if current_user.email else "SURFACE Platform"

    bundle = events_to_stix_bundle(events, org_name=org_name)
    return _build_stix_response(bundle, as_attachment=False)


@router.get("/stix/bundle.json", summary="STIX 2.1 Bundle (скачать файл)")
async def export_stix_download(
    db: DBDep,
    current_user: CurrentUser,
    asset_id: str | None = Query(default=None, description="UUID актива для фильтрации"),
    days: int = Query(default=30, ge=1, le=365, description="Глубина выборки в днях"),
) -> Response:
    """
    Скачать STIX 2.1 Bundle как файл.

    Аналогично GET /stix, но возвращает:
    - Content-Disposition: attachment; filename="stix_bundle_YYYYMMDD_HHmmSS.json"

    Удобно для ручного импорта в SIEM (Splunk, IBM QRadar, Elastic SIEM).
    """
    if current_user.organization_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Пользователь не привязан к организации",
        )

    events = await _fetch_events(db, current_user.organization_id, asset_id, days)

    org_name = current_user.email.split("@")[-1] if current_user.email else "SURFACE Platform"

    bundle = events_to_stix_bundle(events, org_name=org_name)
    return _build_stix_response(bundle, as_attachment=True)
