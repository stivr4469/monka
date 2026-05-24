"""
API Keys management — SIEM/SOAR интеграция (задача 10.F).

Позволяет enterprise-пользователям создавать долгосрочные API-ключи
для интеграции с SIEM/SOAR системами без использования JWT.

Raw key возвращается ТОЛЬКО при создании — в БД хранится SHA-256 хеш.
"""
from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select

from app.api.deps import CurrentUser, DBDep
from app.models.api_key import ApiKey
from app.models.organization import OrgPlan

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth/api-keys", tags=["api-keys"])


# ─── Схемы запросов и ответов ────────────────────────────────────────────────

class ApiKeyCreateRequest(BaseModel):
    """Запрос на создание нового API-ключа."""
    name: str
    permissions: list[str] = ["events:read", "assets:read"]
    # expires_at опционально — None означает бессрочный ключ


class ApiKeyCreatedResponse(BaseModel):
    """Ответ при создании ключа — raw_key показывается только один раз."""
    id: str
    name: str
    key: str  # raw_key — видим только здесь
    permissions: list[str]
    created_at: datetime
    warning: str = "Сохраните ключ — он показывается только один раз"


class ApiKeyRead(BaseModel):
    """Схема чтения ключа — key_hash НЕ возвращается."""
    id: str
    name: str
    permissions: list[str]
    is_active: bool
    created_at: datetime
    last_used_at: datetime | None
    expires_at: datetime | None

    model_config = {"from_attributes": True}


# ─── Утилиты ─────────────────────────────────────────────────────────────────

def _check_enterprise(user) -> None:
    """Проверяет что пользователь имеет enterprise-план или является суперпользователем."""
    if user.is_superuser:
        return
    if user.organization is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API-ключи доступны только для Enterprise-плана",
        )
    if user.organization.plan != OrgPlan.enterprise.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API-ключи доступны только для Enterprise-плана. Обновите тариф.",
        )


def _hash_key(raw_key: str) -> str:
    """Возвращает SHA-256 хеш от raw_key в hex-формате."""
    return hashlib.sha256(raw_key.encode()).hexdigest()


# ─── Эндпоинты ───────────────────────────────────────────────────────────────

@router.post(
    "",
    response_model=ApiKeyCreatedResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Создать API-ключ для SIEM/SOAR интеграции",
)
async def create_api_key(
    body: ApiKeyCreateRequest,
    db: DBDep,
    current_user: CurrentUser,
) -> ApiKeyCreatedResponse:
    """
    Создаёт новый API-ключ.

    Доступно: Enterprise-план или суперпользователь.
    raw_key возвращается ТОЛЬКО ОДИН РАЗ — сохраните его немедленно.
    В БД хранится только SHA-256 хеш ключа.
    """
    # Загружаем организацию для проверки плана (lazy load через select)
    from sqlalchemy.orm import selectinload
    from sqlalchemy import select as sql_select
    from app.models.user import User
    result = await db.execute(
        sql_select(User).options(selectinload(User.organization)).where(User.id == current_user.id)
    )
    user_with_org = result.scalar_one_or_none()

    if not current_user.is_superuser:
        if user_with_org is None or user_with_org.organization is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="API-ключи доступны только для Enterprise-плана",
            )
        if user_with_org.organization.plan != OrgPlan.enterprise.value:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="API-ключи доступны только для Enterprise-плана. Обновите тариф.",
            )

    # Генерируем безопасный ключ с префиксом easm_
    raw_key = f"easm_{secrets.token_urlsafe(32)}"
    key_hash = _hash_key(raw_key)

    api_key = ApiKey(
        user_id=current_user.id,
        name=body.name,
        key_hash=key_hash,
        permissions=body.permissions,
        is_active=True,
    )
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)

    logger.info(
        "[api_keys] Создан новый ключ: id=%s user=%s name=%s",
        api_key.id,
        current_user.id,
        body.name,
    )

    return ApiKeyCreatedResponse(
        id=api_key.id,
        name=api_key.name,
        key=raw_key,
        permissions=api_key.permissions,
        created_at=api_key.created_at,
        warning="Сохраните ключ — он показывается только один раз",
    )


@router.get(
    "",
    response_model=list[ApiKeyRead],
    summary="Список API-ключей пользователя",
)
async def list_api_keys(
    db: DBDep,
    current_user: CurrentUser,
) -> list[ApiKeyRead]:
    """
    Возвращает список API-ключей текущего пользователя.
    key_hash НЕ включается в ответ — только метаданные.
    """
    result = await db.execute(
        select(ApiKey)
        .where(ApiKey.user_id == current_user.id)
        .order_by(ApiKey.created_at.desc())
    )
    keys = list(result.scalars().all())

    return [ApiKeyRead.model_validate(k) for k in keys]


@router.delete(
    "/{key_id}",
    status_code=status.HTTP_200_OK,
    summary="Отозвать API-ключ",
)
async def revoke_api_key(
    key_id: str,
    db: DBDep,
    current_user: CurrentUser,
) -> dict:
    """
    Деактивирует API-ключ (мягкое удаление: is_active=False).
    Ключ перестаёт работать немедленно, физически не удаляется.
    """
    result = await db.execute(
        select(ApiKey).where(
            ApiKey.id == key_id,
            ApiKey.user_id == current_user.id,
        )
    )
    api_key = result.scalar_one_or_none()

    if api_key is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API-ключ не найден")

    api_key.is_active = False
    await db.commit()

    logger.info("[api_keys] Ключ отозван: id=%s user=%s", key_id, current_user.id)
    return {"status": "revoked", "id": key_id}
