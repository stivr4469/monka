"""Модель API-ключей для SIEM/SOAR интеграции (задача 10.F)."""
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, new_uuid


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    # Владелец ключа — при удалении пользователя ключи каскадно удаляются
    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # Человекочитаемое название для идентификации ключа в списке
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    # SHA-256 хеш от raw_key — сам ключ в БД не хранится
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    # Список разрешений: ["events:read", "assets:read", "ingest:write"]
    permissions: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    # Временные метки
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    # Обновляется при каждом успешном использовании ключа
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Опциональная дата истечения — None означает бессрочный ключ
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Мягкое удаление через деактивацию вместо физического DELETE
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
