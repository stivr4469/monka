"""
Эндпоинты событий безопасности.

ВАЖНО: каждый запрос фильтруется по organization_id пользователя
через JOIN assets → organizations.
Прямая фильтрация по event.asset_id гарантирует изоляцию тенантов.
"""
import csv
import io
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query, Response, status
from pydantic import BaseModel
from sqlalchemy import select, func

from app.api.deps import CurrentUser, DBDep
from app.core.config import settings
from app.core.crypto import decrypt_password
from app.models.asset import Asset
from app.models.event import Event
from app.services.opensearch_client import search_events as os_search_events

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


class EventListResponse(BaseModel):
    """Ответ со списком событий и курсором для следующей страницы."""
    items: list[EventRead]
    next_before: str | None  # ISO-8601 timestamp для следующего запроса ?before=


def _org_event_query(organization_id: str):
    """
    Базовый запрос событий с фильтром по организации.

    Использует JOIN через asset_id чтобы гарантировать:
    - события только по активам СВОЕЙ организации
    - корректное поведение при asset_id IS NULL (события без привязки к активу
      не возвращаются — это намеренно; ingest всегда привязывает к активу)
    """
    return (
        select(Event)
        .join(Asset, Event.asset_id == Asset.id)
        .where(Asset.organization_id == organization_id)
    )


@router.get("/", response_model=EventListResponse)
async def list_events(
    db: DBDep,
    current_user: CurrentUser,
    domain: str | None = Query(default=None, description="Фильтр по домену"),
    severity: str | None = Query(default=None, description="Фильтр по severity"),
    event_type: str | None = Query(default=None, description="Фильтр по типу события"),
    limit: int = Query(default=50, ge=1, le=500, description="Размер страницы"),
    before: str | None = Query(
        default=None,
        description=(
            "Cursor для пагинации: ISO-8601 timestamp. "
            "Вернёт события СТРОГО до этого момента. "
            "Берётся из поля next_before предыдущего ответа."
        ),
    ),
) -> EventListResponse:
    """
    Список событий организации с cursor-based пагинацией.

    Изоляция тенантов: события фильтруются через JOIN к assets организации.
    Пагинация: передайте ?before=<next_before из предыдущего ответа>.
    """
    if current_user.organization_id is None:
        return EventListResponse(items=[], next_before=None)

    # Базовый запрос с фильтром по организации (изоляция тенантов)
    q = _org_event_query(current_user.organization_id)

    # Cursor-based пагинация по detected_at
    if before is not None:
        try:
            before_dt = datetime.fromisoformat(before)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Параметр before должен быть в формате ISO-8601, например 2024-01-15T10:30:00+00:00",
            )
        q = q.where(Event.detected_at < before_dt)

    # Дополнительные фильтры
    if domain:
        q = q.where(Event.target_domain == domain)
    if severity:
        q = q.where(Event.severity == severity)
    if event_type:
        q = q.where(Event.event_type == event_type)

    # Сортируем по убыванию времени, берём limit+1 для определения наличия следующей страницы
    q = q.order_by(Event.detected_at.desc()).limit(limit + 1)

    result = await db.execute(q)
    rows = list(result.scalars().all())

    # Если получили больше limit — есть следующая страница
    has_next = len(rows) > limit
    items = rows[:limit]

    # Курсор для следующей страницы — detected_at последнего элемента текущей страницы
    next_before: str | None = None
    if has_next and items:
        next_before = items[-1].detected_at.isoformat()

    return EventListResponse(
        items=[EventRead.model_validate(e) for e in items],
        next_before=next_before,
    )


@router.get("/stats", response_model=EventStats)
async def event_stats(
    db: DBDep,
    current_user: CurrentUser,
    domain: str | None = Query(default=None),
) -> EventStats:
    """Сводная статистика по событиям организации."""
    if current_user.organization_id is None:
        return EventStats(total=0, by_severity={}, by_type={})

    # Базовый запрос с фильтром по организации
    base_q = _org_event_query(current_user.organization_id)
    if domain:
        base_q = base_q.where(Event.target_domain == domain)

    # Всего событий
    total_r = await db.execute(select(func.count()).select_from(base_q.subquery()))
    total = total_r.scalar_one()

    # По severity — строим отдельный запрос с join
    sev_q = (
        select(Event.severity, func.count())
        .join(Asset, Event.asset_id == Asset.id)
        .where(Asset.organization_id == current_user.organization_id)
        .group_by(Event.severity)
    )
    if domain:
        sev_q = sev_q.where(Event.target_domain == domain)
    sev_r = await db.execute(sev_q)
    by_severity = dict(sev_r.all())

    # По типу события
    type_q = (
        select(Event.event_type, func.count())
        .join(Asset, Event.asset_id == Asset.id)
        .where(Asset.organization_id == current_user.organization_id)
        .group_by(Event.event_type)
    )
    if domain:
        type_q = type_q.where(Event.target_domain == domain)
    type_r = await db.execute(type_q)
    by_type = dict(type_r.all())

    return EventStats(total=total, by_severity=by_severity, by_type=by_type)


@router.get("/export")
async def export_events(
    db: DBDep,
    current_user: CurrentUser,
    format: str = Query(default="csv", description="Формат: csv или json"),
    domain: str | None = Query(default=None, description="Фильтр по домену"),
    severity: str | None = Query(default=None, description="Фильтр по severity"),
    event_type: str | None = Query(default=None, description="Фильтр по типу события"),
    limit: int = Query(default=1000, ge=1, le=10000, description="Максимум записей для экспорта"),
) -> Response:
    """
    Экспорт событий организации в CSV или JSON.

    Возвращает файл с заголовком Content-Disposition: attachment.
    Изоляция тенантов гарантирована через JOIN к assets организации.
    """
    if current_user.organization_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Пользователь не привязан к организации",
        )

    if format not in ("csv", "json"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Параметр format должен быть csv или json",
        )

    # Запрос с фильтром по организации
    q = _org_event_query(current_user.organization_id)
    if domain:
        q = q.where(Event.target_domain == domain)
    if severity:
        q = q.where(Event.severity == severity)
    if event_type:
        q = q.where(Event.event_type == event_type)

    q = q.order_by(Event.detected_at.desc()).limit(limit)
    result = await db.execute(q)
    events = list(result.scalars().all())

    # Формируем имя файла с доменом и датой
    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    domain_part = domain.replace(".", "_") if domain else "all"

    if format == "csv":
        # Формируем CSV в памяти
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["id", "event_type", "severity", "source_type", "source_name", "target_domain", "detected_at"])
        for e in events:
            writer.writerow([
                e.id,
                e.event_type,
                e.severity,
                e.source_type,
                e.source_name,
                e.target_domain,
                e.detected_at.isoformat(),
            ])
        content = output.getvalue().encode("utf-8")
        filename = f"events_{domain_part}_{date_str}.csv"
        media_type = "text/csv; charset=utf-8"

    else:
        # JSON: сериализуем через Pydantic чтобы не тащить payload в CSV
        import json
        data = [
            {
                "id": e.id,
                "event_type": e.event_type,
                "severity": e.severity,
                "source_type": e.source_type,
                "source_name": e.source_name,
                "target_domain": e.target_domain,
                "payload": e.payload,
                "detected_at": e.detected_at.isoformat(),
            }
            for e in events
        ]
        content = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
        filename = f"events_{domain_part}_{date_str}.json"
        media_type = "application/json; charset=utf-8"

    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/{event_id}/reveal", summary="Расшифровать пароль из стилер-лога")
async def reveal_password(
    event_id: str,
    db: DBDep,
    current_user: CurrentUser,
) -> dict:
    """
    Возвращает расшифрованный пароль для события stealer_log.
    Требует JWT-авторизацию. Каждый запрос логируется.
    Доступ ограничен событиями СВОЕЙ организации.
    """
    if current_user.organization_id is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Нет организации")

    # Получаем событие с проверкой принадлежности к организации через asset
    q = (
        select(Event)
        .join(Asset, Event.asset_id == Asset.id)
        .where(
            Event.id == event_id,
            Asset.organization_id == current_user.organization_id,
        )
    )
    result = await db.execute(q)
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


@router.get("/search", summary="Полнотекстовый поиск по событиям (OpenSearch + PostgreSQL fallback)")
async def search_events(
    current_user: CurrentUser,
    db: DBDep,
    q: str = Query(..., min_length=2, max_length=200, description="Поисковый запрос"),
    limit: int = Query(default=50, ge=1, le=200),
    domain: str | None = Query(default=None),
    severity: str | None = Query(default=None),
) -> dict:
    """
    7.C.4: Полнотекстовый поиск через OpenSearch.
    При недоступности OS — fallback на LIKE-поиск по PostgreSQL.
    Результаты фильтруются по organization_id пользователя.
    """
    # Получаем домены организации для изоляции тенантов
    asset_q = select(Asset.domain).where(
        Asset.organization_id == current_user.organization_id,
        Asset.is_active == True,  # noqa: E712
    )
    asset_result = await db.execute(asset_q)
    org_domains = {row[0] for row in asset_result.all()}

    # Попытка через OpenSearch
    os_results = await os_search_events(q, limit=limit, domain=domain, severity=severity)
    if os_results:
        filtered = [r for r in os_results if r.get("target_domain") in org_domains]
        return {"source": "opensearch", "total": len(filtered), "items": filtered[:limit]}

    # Fallback: PostgreSQL LIKE-поиск
    from sqlalchemy import or_, cast, String
    pg_q = (
        select(Event)
        .join(Asset, Asset.id == Event.asset_id, isouter=True)
        .where(
            or_(
                Asset.organization_id == current_user.organization_id,
                Event.target_domain.in_(org_domains),
            )
        )
    )
    if domain:
        pg_q = pg_q.where(Event.target_domain == domain)
    if severity:
        pg_q = pg_q.where(Event.severity == severity)
    pg_q = pg_q.order_by(Event.detected_at.desc()).limit(limit)

    result = await db.execute(pg_q)
    events = result.scalars().all()

    # Фильтруем по поисковому запросу в payload
    q_lower = q.lower()
    matched = [
        {
            "id": e.id,
            "event_type": e.event_type,
            "severity": e.severity,
            "source_name": e.source_name,
            "target_domain": e.target_domain,
            "detected_at": e.detected_at.isoformat() if e.detected_at else None,
            "payload": e.payload,
        }
        for e in events
        if q_lower in str(e.payload).lower()
        or q_lower in (e.target_domain or "").lower()
        or q_lower in (e.source_name or "").lower()
    ]

    return {"source": "postgresql", "total": len(matched), "items": matched[:limit]}
