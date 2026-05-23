"""
Внутренние эндпоинты для воркеров — получение активных правил алертов.
Доступ только по INTERNAL_API_SECRET (shared secret воркеров).
"""
import logging

from fastapi import APIRouter, Depends
from sqlalchemy import select

from app.api.deps import DBDep, verify_internal_secret
from app.models.alert_rule import AlertRule
from app.schemas.alert_rule import AlertRuleRead

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/internal",
    tags=["internal"],
    dependencies=[Depends(verify_internal_secret)],
)


@router.get("/alert-rules", response_model=list[AlertRuleRead])
async def get_active_alert_rules(db: DBDep) -> list[AlertRule]:
    """
    Возвращает все активные правила алертов всех организаций.
    Используется воркером dispatch_alerts для диспетчеризации уведомлений.

    Аутентификация: Bearer INTERNAL_API_SECRET.
    """
    result = await db.execute(
        select(AlertRule)
        .where(AlertRule.is_active == True)  # noqa: E712
        .order_by(AlertRule.organization_id, AlertRule.created_at)
    )
    rules = list(result.scalars().all())
    logger.debug("Запрос активных правил алертов: найдено %d", len(rules))
    return rules


# ROUTER: api_router.include_router(internal_alerts.router)
