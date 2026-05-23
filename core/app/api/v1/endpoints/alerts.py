"""
Эндпоинты управления правилами Telegram-алертов.

Правила привязаны к организации текущего пользователя.
Каждое правило описывает фильтр событий и куда отправлять уведомления.
"""
import logging
import sys
from pathlib import Path

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select

from app.api.deps import CurrentUser, DBDep
from app.core.config import settings
from app.models.alert_rule import AlertRule
from app.schemas.alert_rule import AlertRuleCreate, AlertRuleRead, AlertRuleUpdate

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/alerts", tags=["alerts"])

# Добавляем workers в path для доступа к telegram_alerts
# parents[5] = корень монорепо Monitoring_utechek/
_WORKERS_PATH = str(Path(__file__).parents[5] / "workers")
if _WORKERS_PATH not in sys.path:
    sys.path.insert(0, _WORKERS_PATH)


def _require_org(current_user: CurrentUser) -> str:
    """Возвращает organization_id или бросает 400."""
    if current_user.organization_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Пользователь не привязан к организации",
        )
    return current_user.organization_id


@router.post("/", response_model=AlertRuleRead, status_code=status.HTTP_201_CREATED)
async def create_alert_rule(
    body: AlertRuleCreate,
    db: DBDep,
    current_user: CurrentUser,
) -> AlertRule:
    """
    Создаёт новое правило алерта для организации текущего пользователя.

    - target_domain=None → срабатывает для всех доменов организации
    - event_types=None → срабатывает для всех типов событий
    """
    org_id = _require_org(current_user)

    rule = AlertRule(
        organization_id=org_id,
        name=body.name,
        target_domain=body.target_domain,
        min_severity=body.min_severity,
        event_types=body.event_types,
        telegram_chat_id=body.telegram_chat_id,
        is_active=body.is_active,
    )
    db.add(rule)

    try:
        await db.commit()
        await db.refresh(rule)
    except Exception as exc:
        await db.rollback()
        logger.error("Ошибка создания правила алерта: %s", exc)
        raise HTTPException(status_code=500, detail="Ошибка создания правила") from exc

    logger.info("Создано правило алерта: id=%s name=%s org=%s", rule.id, rule.name, org_id)
    return rule


@router.get("/", response_model=list[AlertRuleRead])
async def list_alert_rules(
    db: DBDep,
    current_user: CurrentUser,
) -> list[AlertRule]:
    """Возвращает список всех правил алертов организации."""
    org_id = _require_org(current_user)

    result = await db.execute(
        select(AlertRule)
        .where(AlertRule.organization_id == org_id)
        .order_by(AlertRule.created_at.desc())
    )
    return list(result.scalars().all())


@router.patch("/{rule_id}", response_model=AlertRuleRead)
async def update_alert_rule(
    rule_id: str,
    body: AlertRuleUpdate,
    db: DBDep,
    current_user: CurrentUser,
) -> AlertRule:
    """Частично обновляет правило алерта."""
    org_id = _require_org(current_user)

    result = await db.execute(select(AlertRule).where(AlertRule.id == rule_id))
    rule = result.scalar_one_or_none()

    if rule is None or rule.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Правило не найдено")

    # Обновляем только переданные поля (exclude_unset=True игнорирует не переданные)
    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(rule, field, value)

    try:
        await db.commit()
        await db.refresh(rule)
    except Exception as exc:
        await db.rollback()
        logger.error("Ошибка обновления правила алерта %s: %s", rule_id, exc)
        raise HTTPException(status_code=500, detail="Ошибка обновления правила") from exc

    return rule


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_alert_rule(
    rule_id: str,
    db: DBDep,
    current_user: CurrentUser,
) -> None:
    """Удаляет правило алерта."""
    org_id = _require_org(current_user)

    result = await db.execute(select(AlertRule).where(AlertRule.id == rule_id))
    rule = result.scalar_one_or_none()

    if rule is None or rule.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Правило не найдено")

    await db.delete(rule)
    await db.commit()
    logger.info("Удалено правило алерта: id=%s org=%s", rule_id, org_id)


@router.post("/test/{rule_id}", status_code=status.HTTP_200_OK)
async def test_alert_rule(
    rule_id: str,
    db: DBDep,
    current_user: CurrentUser,
) -> dict:
    """
    Отправляет тестовое Telegram-сообщение для проверки настройки правила.
    Использует синтетическое тестовое событие.
    """
    org_id = _require_org(current_user)

    result = await db.execute(select(AlertRule).where(AlertRule.id == rule_id))
    rule = result.scalar_one_or_none()

    if rule is None or rule.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Правило не найдено")

    if not settings.TELEGRAM_BOT_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="TELEGRAM_BOT_TOKEN не настроен на сервере",
        )

    # Синтетическое тестовое событие
    test_event = {
        "event_type": "vulnerability",
        "severity": "high",
        "source_type": "nuclei",
        "source_name": "nuclei-test",
        "target_domain": rule.target_domain or "example.com",
        "payload": {
            "title": "TEST: Проверка правила алерта",
            "url": "https://example.com/test",
            "tags": ["test", "alert-check"],
        },
    }

    try:
        from tasks.telegram_alerts import send_telegram_alert

        success = send_telegram_alert(
            chat_id=rule.telegram_chat_id,
            event=test_event,
            bot_token=settings.TELEGRAM_BOT_TOKEN,
        )
    except ImportError:
        raise HTTPException(status_code=503, detail="workers/tasks не найдены")
    except Exception as exc:
        logger.error("Ошибка тестового алерта для правила %s: %s", rule_id, exc)
        raise HTTPException(status_code=502, detail=f"Ошибка отправки: {exc}") from exc

    if not success:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Telegram вернул ошибку. Проверьте chat_id и токен бота.",
        )

    return {
        "status": "sent",
        "rule_id": rule_id,
        "telegram_chat_id": rule.telegram_chat_id,
        "detail": "Тестовое сообщение отправлено в Telegram",
    }


# ROUTER: api_router.include_router(alerts.router)
