"""
Temptation Engine API — Attacker's Perspective (Gap 4 vs Randori).

GET /api/v1/assets/{asset_id}/temptation    → одиночный актив
GET /api/v1/organizations/{org_id}/temptation → ранжированный список активов org
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
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
    db: AsyncSession = Depends(get_db),
    _user=Depends(get_current_user),
) -> AssetTemptation:
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
    db: AsyncSession = Depends(get_db),
    _user=Depends(get_current_user),
) -> OrgTemptationReport:
    return await compute_org_temptation(org_id, db)
