"""
Identity Risk API — MFA Bypass Risk & Session Exposure (Gap 6).

GET /api/v1/identity/exposure?org_id=...  → IdentityRiskReport
GET /api/v1/identity/users?org_id=...&min_risk=50  → AffectedUsersListResponse
"""
from datetime import datetime

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel

from app.api.deps import CurrentUser, DBDep
from app.services.identity_risk import (
    AffectedUser,
    IdentityRiskReport,
    compute_identity_risk,
    extract_affected_users,
)
from app.models.event import Event
from app.models.asset import Asset
from sqlalchemy import select

router = APIRouter(tags=["identity"])


# ─── Pydantic-схемы ответа ────────────────────────────────────────────────────

class AffectedUserResponse(BaseModel):
    email:             str
    username:          str | None
    source_types:      list[str]
    compromised_urls:  list[str]
    passwords_exposed: int
    risk_score:        int
    last_seen:         datetime


class AffectedUsersListResponse(BaseModel):
    total:           int
    high_risk_count: int                    # risk_score >= 70
    users:           list[AffectedUserResponse]


# ─── Вспомогательная функция сборки ответа ────────────────────────────────────

def _to_response(user: AffectedUser) -> AffectedUserResponse:
    """Конвертирует AffectedUser (dataclass) в Pydantic-схему ответа."""
    source_types = sorted(user._event_types) if user._event_types else [user.source_type]
    return AffectedUserResponse(
        email=user.email,
        username=user.username,
        source_types=source_types,
        compromised_urls=user.compromised_urls,
        passwords_exposed=user.passwords_exposed,
        risk_score=user.risk_score,
        last_seen=user.last_seen,
    )


def _check_org_access(current_user, org_id: str) -> None:
    """IDOR-защита: пользователь может запрашивать только свою организацию."""
    if not current_user.is_superuser and current_user.organization_id != org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Нет доступа к данным этой организации",
        )


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.get(
    "/identity/exposure",
    response_model=IdentityRiskReport,
    summary="MFA Bypass Risk & Session Exposure — Identity-Centric Security",
)
async def get_identity_exposure(
    db: DBDep,
    current_user: CurrentUser,
    org_id: str = Query(..., description="ID организации"),
) -> IdentityRiskReport:
    _check_org_access(current_user, org_id)
    return await compute_identity_risk(org_id, db)


@router.get(
    "/identity/users",
    response_model=AffectedUsersListResponse,
    summary="Пострадавшие сотрудники — список по risk score",
    description=(
        "Возвращает список сотрудников организации, чьи учётные данные или сессии "
        "были скомпрометированы. Можно фильтровать по минимальному risk score."
    ),
)
async def get_affected_users(
    db: DBDep,
    current_user: CurrentUser,
    org_id: str = Query(..., description="ID организации"),
    min_risk: int = Query(
        default=0,
        ge=0,
        le=100,
        description="Минимальный risk score (0-100). По умолчанию — все пользователи.",
    ),
) -> AffectedUsersListResponse:
    _check_org_access(current_user, org_id)

    # Получаем asset_ids организации
    from app.services.identity_risk import _ALL_IDENTITY_TYPES

    assets_result = await db.execute(
        select(Asset.id).where(
            Asset.organization_id == org_id,
            Asset.is_active == True,  # noqa: E712
        )
    )
    asset_ids = list(assets_result.scalars().all())

    if not asset_ids:
        return AffectedUsersListResponse(total=0, high_risk_count=0, users=[])

    # Загружаем все identity-события
    events_result = await db.execute(
        select(Event).where(
            Event.asset_id.in_(asset_ids),
            Event.event_type.in_(_ALL_IDENTITY_TYPES),
        )
    )
    events: list[Event] = list(events_result.scalars().all())

    if not events:
        return AffectedUsersListResponse(total=0, high_risk_count=0, users=[])

    # Извлекаем и фильтруем пострадавших
    all_users = extract_affected_users(events)
    filtered = [u for u in all_users if u.risk_score >= min_risk]

    high_risk_count = sum(1 for u in filtered if u.risk_score >= 70)

    return AffectedUsersListResponse(
        total=len(filtered),
        high_risk_count=high_risk_count,
        users=[_to_response(u) for u in filtered],
    )
