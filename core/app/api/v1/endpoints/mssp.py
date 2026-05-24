"""MSSP Multi-Tenancy API (задача 9.F).

MSSP (Managed Security Service Provider) — компания-партнёр, управляющая безопасностью
множества клиентов через одну панель.

Бизнес-правила:
  - is_superuser → видит ВСЕ организации (для демо и отладки)
  - is_mssp_operator → видит только организации, где mssp_owner_id == user.id
  - Обычный пользователь → 403
  - Сортировка: сначала клиенты с наибольшим падением рейтинга (risk_delta_24h наименьшее)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import func, select

from app.api.deps import CurrentUser, DBDep
from app.models.asset import Asset
from app.models.event import Event
from app.models.organization import Organization
from app.models.user import User

router = APIRouter(prefix="/mssp", tags=["mssp"])

# ─── Веса severity для быстрого расчёта (без decay — для скорости при 100+ клиентах) ───
_SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 25,
    "high":     13,
    "medium":    8,
    "low":       3,
    "info":      0,
}


# ─── Схемы Pydantic ─────────────────────────────────────────────────────────────

class ClientRiskSummary(BaseModel):
    """Сводка безопасности клиента MSSP."""

    organization_id: str
    organization_name: str
    plan: str
    domain_count: int
    risk_score: int          # текущий Risk Score (0–100, snapshot за последние 24ч)
    risk_delta_24h: int      # изменение за 24ч: отрицательное = ухудшение
    critical_events: int     # кол-во critical событий за последние 24ч
    last_event_at: str | None


class AssignClientRequest(BaseModel):
    """Тело запроса для привязки организации к MSSP-оператору."""

    operator_id: str


# ─── Приватные утилиты ───────────────────────────────────────────────────────────

def _quick_risk_score(events: list[Any]) -> int:
    """
    Упрощённый Risk Score без временного затухания.

    Используем линейную формулу вместо экспоненциальной из assets.py —
    это позволяет обрабатывать сотни клиентов без значительной нагрузки на CPU.

    Формула: score = max(0, 100 - Σ weight(severity))
    """
    penalty = sum(_SEVERITY_WEIGHTS.get(str(ev.severity).lower(), 0) for ev in events)
    return max(0, 100 - penalty)


def _build_summary(
    org: Organization,
    domain_count: int,
    events_now: list[Any],
    events_prev: list[Any],
) -> ClientRiskSummary:
    """Собирает ClientRiskSummary из уже загруженных данных (без новых запросов к БД)."""
    score_now  = _quick_risk_score(events_now)
    score_prev = _quick_risk_score(events_prev)
    delta      = score_now - score_prev  # отрицательное = ухудшение

    critical_count = sum(
        1 for ev in events_now
        if str(ev.severity).lower() == "critical"
    )

    # Ищем самое свежее событие среди текущего окна
    last_event_at: str | None = None
    if events_now:
        latest = max(events_now, key=lambda ev: ev.detected_at)
        dt = latest.detected_at
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        last_event_at = dt.isoformat()

    return ClientRiskSummary(
        organization_id=org.id,
        organization_name=org.name,
        plan=org.plan,
        domain_count=domain_count,
        risk_score=score_now,
        risk_delta_24h=delta,
        critical_events=critical_count,
        last_event_at=last_event_at,
    )


def _require_mssp_access(user: User) -> None:
    """Проверяет право доступа к MSSP-панели. Бросает HTTPException 403 при отказе."""
    if not (getattr(user, "is_mssp_operator", False) or user.is_superuser):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Доступ только для MSSP-операторов",
        )


async def _get_accessible_org_ids(db: Any, user: User) -> list[str] | None:
    """
    Возвращает список id организаций, доступных текущему пользователю:
      - superuser → None (сигнал: доступ ко всем)
      - mssp_operator → список org_id где mssp_owner_id == user.id
    """
    if user.is_superuser:
        return None

    result = await db.execute(
        select(Organization.id).where(Organization.mssp_owner_id == user.id)
    )
    return list(result.scalars().all())


async def _build_org_summary(
    db: Any,
    org: Organization,
    now: datetime,
    window_24h: datetime,
    window_48h: datetime,
) -> ClientRiskSummary:
    """
    Загружает события для одной организации и строит сводку.

    Выполняем два запроса на организацию:
      1. COUNT доменов
      2. События за 0–24ч (текущий снимок)
      3. События за 24–48ч (предыдущий снимок для delta)

    Запросы легковесны: выбираем только поля severity + detected_at.
    """
    # Количество доменов
    count_res = await db.execute(
        select(func.count(Asset.id)).where(Asset.organization_id == org.id)
    )
    domain_count: int = count_res.scalar_one()

    # Домены организации нужны для JOIN с событиями через asset_id.
    # Используем subquery вместо python-цикла для одного round-trip.
    asset_subq = select(Asset.id).where(Asset.organization_id == org.id).scalar_subquery()

    # События за последние 24 часа
    events_now_res = await db.execute(
        select(Event.severity, Event.detected_at)
        .where(
            Event.asset_id.in_(asset_subq),
            Event.detected_at >= window_24h,
            Event.detected_at < now,
        )
    )
    events_now = events_now_res.all()

    # События за предыдущие 24 часа (24–48ч назад) для вычисления delta
    events_prev_res = await db.execute(
        select(Event.severity, Event.detected_at)
        .where(
            Event.asset_id.in_(asset_subq),
            Event.detected_at >= window_48h,
            Event.detected_at < window_24h,
        )
    )
    events_prev = events_prev_res.all()

    return _build_summary(org, domain_count, events_now, events_prev)


# ─── Эндпоинты ───────────────────────────────────────────────────────────────────

@router.get(
    "/clients",
    response_model=list[ClientRiskSummary],
    summary="Список клиентов MSSP (задача 9.F)",
)
async def list_mssp_clients(
    db: DBDep,
    current_user: CurrentUser,
) -> list[ClientRiskSummary]:
    """
    Возвращает список всех клиентов MSSP-оператора с Risk Score и тенденцией за 24ч.

    Доступ:
      - is_superuser → все организации (для демо и отладки)
      - is_mssp_operator → только организации, где mssp_owner_id == user.id
      - Остальные → 403

    Сортировка: сначала клиенты с наибольшей деградацией рейтинга (risk_delta_24h наименьшее).
    """
    _require_mssp_access(current_user)

    now       = datetime.now(timezone.utc)
    window_24h = now - timedelta(hours=24)
    window_48h = now - timedelta(hours=48)

    org_ids = await _get_accessible_org_ids(db, current_user)

    # Загружаем организации одним запросом
    q = select(Organization)
    if org_ids is not None:
        if not org_ids:
            # Оператор существует, но у него нет клиентов
            return []
        q = q.where(Organization.id.in_(org_ids))
    orgs_res = await db.execute(q.order_by(Organization.name))
    orgs: list[Organization] = list(orgs_res.scalars().all())

    # Строим сводку параллельно — каждая организация независима.
    # В production с сотнями клиентов можно перейти на asyncio.gather,
    # но для SQLite (тесты) последовательный вариант безопаснее.
    summaries: list[ClientRiskSummary] = []
    for org in orgs:
        summary = await _build_org_summary(db, org, now, window_24h, window_48h)
        summaries.append(summary)

    # Сортируем: наибольшая деградация наверху (delta_24h наименьшее = самое плохое)
    summaries.sort(key=lambda s: s.risk_delta_24h)

    return summaries


@router.get(
    "/clients/{org_id}",
    response_model=ClientRiskSummary,
    summary="Детали клиента MSSP",
)
async def get_mssp_client(
    org_id: str,
    db: DBDep,
    current_user: CurrentUser,
) -> ClientRiskSummary:
    """
    Детальная сводка безопасности конкретного клиента.

    Проверяет, что оператор имеет доступ к этой организации.
    """
    _require_mssp_access(current_user)

    # Загружаем организацию
    org_res = await db.execute(select(Organization).where(Organization.id == org_id))
    org: Organization | None = org_res.scalar_one_or_none()
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Организация не найдена")

    # Проверяем право доступа к конкретной организации
    if not current_user.is_superuser:
        if org.mssp_owner_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Нет доступа к этой организации",
            )

    now        = datetime.now(timezone.utc)
    window_24h = now - timedelta(hours=24)
    window_48h = now - timedelta(hours=48)

    return await _build_org_summary(db, org, now, window_24h, window_48h)


@router.post(
    "/clients/{org_id}/assign",
    summary="Привязать организацию к MSSP-оператору (только superuser)",
    status_code=status.HTTP_200_OK,
)
async def assign_client(
    org_id: str,
    body: AssignClientRequest,
    db: DBDep,
    current_user: CurrentUser,
) -> dict[str, str]:
    """
    Привязывает организацию-клиента к MSSP-оператору.

    Только superuser может выполнять эту операцию — во избежание самоназначения
    и несанкционированного расширения области видимости.

    Body: { "operator_id": "<user_id>" }
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Только для суперпользователей",
        )

    # Проверяем существование организации
    org_res = await db.execute(select(Organization).where(Organization.id == org_id))
    org: Organization | None = org_res.scalar_one_or_none()
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Организация не найдена")

    # Проверяем, что целевой пользователь существует и является MSSP-оператором
    operator_res = await db.execute(select(User).where(User.id == body.operator_id))
    operator: User | None = operator_res.scalar_one_or_none()
    if operator is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Пользователь-оператор не найден",
        )
    if not operator.is_mssp_operator:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Указанный пользователь не является MSSP-оператором",
        )

    # Выполняем привязку
    org.mssp_owner_id = body.operator_id  # type: ignore[assignment]
    await db.commit()

    return {
        "status": "ok",
        "organization_id": org_id,
        "mssp_owner_id": body.operator_id,
    }


@router.post(
    "/clients/{org_id}/unassign",
    summary="Отвязать организацию от MSSP-оператора (только superuser)",
    status_code=status.HTTP_200_OK,
)
async def unassign_client(
    org_id: str,
    db: DBDep,
    current_user: CurrentUser,
) -> dict[str, str]:
    """
    Снимает привязку организации к MSSP-оператору.

    После unassign организация перестаёт появляться в любом MSSP-dashboard.
    Только superuser может выполнять эту операцию.
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Только для суперпользователей",
        )

    org_res = await db.execute(select(Organization).where(Organization.id == org_id))
    org: Organization | None = org_res.scalar_one_or_none()
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Организация не найдена")

    org.mssp_owner_id = None  # type: ignore[assignment]
    await db.commit()

    return {"status": "ok", "organization_id": org_id, "mssp_owner_id": "null"}
