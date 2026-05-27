"""
Identity Risk API — MFA Bypass Risk & Session Exposure (Gap 6).

GET /api/v1/identity/exposure?org_id=...  → IdentityRiskReport
"""
from fastapi import APIRouter, HTTPException, Query, status

from app.api.deps import CurrentUser, DBDep
from app.services.identity_risk import IdentityRiskReport, compute_identity_risk

router = APIRouter(tags=["identity"])


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
    # IDOR-защита: пользователь может запрашивать только свою организацию
    # (суперпользователь видит любую)
    if not current_user.is_superuser and current_user.organization_id != org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Нет доступа к данным этой организации",
        )
    return await compute_identity_risk(org_id, db)
