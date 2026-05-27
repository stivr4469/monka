"""
Temptation Engine API — Attacker's Perspective (Gap 4 vs Randori).

GET /api/v1/assets/{asset_id}/temptation    → одиночный актив
GET /api/v1/organizations/{org_id}/temptation → ранжированный список активов org
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import CurrentUser, DBDep, get_current_user, get_db
from app.models.asset import Asset
from app.services.temptation_engine import (
    AssetTemptation,
    OrgTemptationReport,
    compute_asset_temptation,
    compute_org_temptation,
)

router = APIRouter(tags=["temptation"])


@router.get(
    "/assets/{asset_id}/temptation",
    response_model=AssetTemptation,
    summary="Temptation Score актива (Attacker's Perspective)",
)
async def get_asset_temptation(
    asset_id: str,
    db: DBDep,
    current_user: CurrentUser,
) -> AssetTemptation:
    # IDOR-защита: проверяем принадлежность актива организации пользователя
    asset_result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = asset_result.scalar_one_or_none()
    if asset is None or asset.organization_id != current_user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Актив не найден")

    try:
        return await compute_asset_temptation(asset_id, db)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.get(
    "/organizations/{org_id}/temptation",
    response_model=OrgTemptationReport,
    summary="Ранжирование активов организации по привлекательности для атакующего",
)
async def get_org_temptation(
    org_id: str,
    db: DBDep,
    current_user: CurrentUser,
) -> OrgTemptationReport:
    # IDOR-защита: пользователь может запрашивать только свою организацию
    # (суперпользователь видит любую)
    if not current_user.is_superuser and current_user.organization_id != org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Нет доступа к этой организации",
        )
    return await compute_org_temptation(org_id, db)
