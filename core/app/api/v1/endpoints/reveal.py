"""
Расшифровка зашифрованных паролей из стилер-логов + Audit Log (задача 10.B).

GET  /api/v1/events/{event_id}/reveal  — расшифровывает password_enc, пишет audit_log.
GET  /api/v1/audit-logs                — список аудит-записей (только superuser).

Требования безопасности:
- Только для событий с source_type in (stealer, stealer_log, breach)
- Только для пользователей с plan=professional или plan=enterprise (или superuser)
- Каждый успешный вызов фиксируется в audit_logs
- Результат содержит expires_in_seconds=30 (UI должен скрыть пароль через 30с)
"""
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy import select

from app.api.deps import CurrentUser, DBDep
from app.core.config import settings
from app.core.crypto import decrypt_password
from app.models.asset import Asset
from app.models.audit_log import AuditLog
from app.models.event import Event
from app.models.organization import Organization

router = APIRouter(tags=["reveal"])

# Типы событий, которые могут содержать зашифрованный пароль
_STEALER_SOURCE_TYPES = frozenset({"stealer", "stealer_log", "breach"})

# Тарифные планы, которым доступна функция расшифровки
_ALLOWED_PLANS = frozenset({"professional", "enterprise"})


class RevealResponse(BaseModel):
    """Ответ с расшифрованным паролем."""
    event_id: str
    password: str
    login: str
    url: str
    expires_in_seconds: int = 30


class AuditLogRead(BaseModel):
    """Схема чтения записи аудит-лога."""
    id: str
    user_id: str
    action: str
    target_id: str
    ip_address: str
    user_agent: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


def _get_client_ip(request: Request) -> str:
    """
    Извлекает реальный IP клиента.
    Проверяет X-Forwarded-For (за reverse proxy), иначе берёт напрямую.
    """
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # X-Forwarded-For может содержать цепочку: "1.2.3.4, 5.6.7.8"
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def _check_plan_access(db: DBDep, user, *, event_id: str) -> None:
    """
    Проверяет, что организация пользователя имеет план professional/enterprise.
    Superuser всегда проходит без проверки.
    """
    if user.is_superuser:
        return
    if user.organization_id is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Пользователь не привязан к организации",
        )
    org = await db.get(Organization, user.organization_id)
    plan = getattr(org, "plan", "starter") if org else "starter"
    if plan not in _ALLOWED_PLANS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Функция расшифровки доступна только в планах Professional и Enterprise",
        )


async def _write_audit(
    db,
    *,
    user_id: str,
    action: str,
    target_id: str,
    ip_address: str,
    user_agent: str | None,
) -> None:
    """Записывает строку в audit_logs и делает flush (без commit — транзакция выше)."""
    entry = AuditLog(
        user_id=user_id,
        action=action,
        target_id=target_id,
        ip_address=ip_address,
        user_agent=user_agent,
        created_at=datetime.now(timezone.utc),
    )
    db.add(entry)
    await db.flush()


@router.get(
    "/events/{event_id}/reveal",
    response_model=RevealResponse,
    summary="Расшифровать пароль из стилер-лога",
)
async def reveal_password(
    event_id: str,
    request: Request,
    db: DBDep,
    current_user: CurrentUser,
) -> RevealResponse:
    """
    10.B: Расшифровывает password_enc из payload стилер-события.

    Доступно только:
    - для событий с source_type in (stealer, stealer_log, breach)
    - для плана Professional/Enterprise или superuser
    - события должны принадлежать организации текущего пользователя

    Каждый вызов фиксируется в таблице audit_logs.
    Клиент обязан скрыть пароль через expires_in_seconds секунд.
    """
    # Проверяем доступ по тарифному плану
    await _check_plan_access(db, current_user, event_id=event_id)

    # Получаем событие с проверкой принадлежности к организации
    if current_user.is_superuser:
        # Superuser видит все события без ограничения по организации
        q = select(Event).where(Event.id == event_id)
    else:
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
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Событие не найдено",
        )

    # Проверяем, что это стилер/breach событие
    if event.source_type not in _STEALER_SOURCE_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Расшифровка доступна только для событий с source_type: "
                f"{', '.join(sorted(_STEALER_SOURCE_TYPES))}. "
                f"Текущий source_type: {event.source_type}"
            ),
        )

    # Извлекаем зашифрованный пароль из payload
    payload = event.payload or {}
    password_enc = payload.get("password_enc", "")
    if not password_enc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Зашифрованный пароль не найден в payload события",
        )

    # Расшифровываем через Fernet (SHA-256 ключ из INTERNAL_API_SECRET)
    try:
        password = decrypt_password(password_enc, settings.INTERNAL_API_SECRET)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Зашифрованный пароль не найден (не удалось расшифровать)",
        )

    # Записываем факт обращения в audit_log
    ip = _get_client_ip(request)
    ua = request.headers.get("User-Agent")
    await _write_audit(
        db,
        user_id=current_user.id,
        action="reveal_password",
        target_id=event_id,
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()

    return RevealResponse(
        event_id=event_id,
        password=password,
        login=payload.get("login", ""),
        url=payload.get("url", ""),
        expires_in_seconds=30,
    )


@router.get(
    "/audit-logs",
    response_model=list[AuditLogRead],
    summary="Список аудит-записей (только superuser)",
)
async def list_audit_logs(
    db: DBDep,
    current_user: CurrentUser,
    limit: int = Query(default=50, ge=1, le=500, description="Макс. записей на страницу"),
    offset: int = Query(default=0, ge=0, description="Смещение для пагинации"),
) -> list[AuditLogRead]:
    """
    10.B: Просмотр журнала аудита расшифровок паролей.

    Только для superuser — рядовые пользователи получают 403.
    Сортировка: по created_at DESC (свежие записи первыми).
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Доступ к аудит-логу только для superuser",
        )

    q = (
        select(AuditLog)
        .order_by(AuditLog.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    result = await db.execute(q)
    rows = list(result.scalars().all())
    return [AuditLogRead.model_validate(r) for r in rows]
