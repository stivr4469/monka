"""
Identity Risk API — MFA Bypass Risk & Session Exposure (Gap 6).

GET /api/v1/identity/exposure?org_id=...  → IdentityRiskReport
"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.services.identity_risk import IdentityRiskReport, compute_identity_risk

router = APIRouter(tags=["identity"])


@router.get(
    "/identity/exposure",
    response_model=IdentityRiskReport,
    summary="MFA Bypass Risk & Session Exposure — Identity-Centric Security",
)
async def get_identity_exposure(
    org_id: str = Query(..., description="ID организации"),
    db: AsyncSession = Depends(get_db),
    _user=Depends(get_current_user),
) -> IdentityRiskReport:
    return await compute_identity_risk(org_id, db)
