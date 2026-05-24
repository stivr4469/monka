"""Эндпоинт информации о тарифном плане организации (задача 8.I)."""

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import func, select

from app.api.deps import CurrentUser, DBDep
from app.core.config import PLAN_DOMAIN_LIMITS
from app.models.asset import Asset
from app.models.organization import Organization, OrgPlan

router = APIRouter(prefix="/billing", tags=["billing"])

# Отображаемые метки планов
_PLAN_LABELS: dict[str, str] = {
    OrgPlan.starter.value: "Starter",
    OrgPlan.professional.value: "Professional",
    OrgPlan.enterprise.value: "Enterprise",
}


class PlanInfo(BaseModel):
    """Информация о тарифном плане организации."""

    plan: str
    plan_label: str
    domain_limit: int
    domains_used: int
    domains_remaining: int


class PlanUpdateRequest(BaseModel):
    """Запрос на смену тарифного плана (только суперпользователи)."""

    plan: str


@router.get(
    "/plan",
    response_model=PlanInfo,
    summary="Информация о текущем тарифном плане",
    description=(
        "Возвращает тарифный план организации текущего пользователя, "
        "лимит доменов и количество использованных."
    ),
)
async def get_plan_info(db: DBDep, current_user: CurrentUser) -> PlanInfo:
    """Возвращает информацию о тарифном плане и использовании лимита доменов."""
    if current_user.organization_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Пользователь не привязан к организации",
        )

    org = await db.get(Organization, current_user.organization_id)
    if org is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Организация не найдена",
        )

    plan: str = getattr(org, "plan", "starter") or "starter"
    limit: int = PLAN_DOMAIN_LIMITS.get(plan, PLAN_DOMAIN_LIMITS["starter"])

    count_result = await db.execute(
        select(func.count(Asset.id)).where(
            Asset.organization_id == current_user.organization_id
        )
    )
    used: int = count_result.scalar_one()

    return PlanInfo(
        plan=plan,
        plan_label=_PLAN_LABELS.get(plan, plan.capitalize()),
        domain_limit=limit,
        domains_used=used,
        domains_remaining=max(0, limit - used),
    )


@router.put(
    "/plan",
    response_model=PlanInfo,
    summary="Сменить тарифный план (только суперпользователи)",
    description=(
        "Позволяет суперпользователю изменить тарифный план организации. "
        "Допустимые значения: starter, professional, enterprise."
    ),
)
async def update_plan(
    body: PlanUpdateRequest,
    db: DBDep,
    current_user: CurrentUser,
) -> PlanInfo:
    """Смена тарифного плана. Доступна только суперпользователям."""
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Смена тарифного плана доступна только администраторам",
        )

    allowed_plans = {p.value for p in OrgPlan}
    if body.plan not in allowed_plans:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Недопустимый план. Допустимые значения: {', '.join(sorted(allowed_plans))}",
        )

    if current_user.organization_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Пользователь не привязан к организации",
        )

    org = await db.get(Organization, current_user.organization_id)
    if org is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Организация не найдена",
        )

    org.plan = body.plan  # type: ignore[assignment]
    await db.commit()
    await db.refresh(org)

    limit: int = PLAN_DOMAIN_LIMITS.get(body.plan, PLAN_DOMAIN_LIMITS["starter"])

    count_result = await db.execute(
        select(func.count(Asset.id)).where(
            Asset.organization_id == current_user.organization_id
        )
    )
    used: int = count_result.scalar_one()

    return PlanInfo(
        plan=body.plan,
        plan_label=_PLAN_LABELS.get(body.plan, body.plan.capitalize()),
        domain_limit=limit,
        domains_used=used,
        domains_remaining=max(0, limit - used),
    )
