"""Модель уведомлений для центра нотификаций (задача 10.I)."""
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, new_uuid


class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    # Принадлежность организации — изолирует уведомления между тенантами
    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # Опциональная ссылка на событие породившее уведомление
    event_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    # Текст уведомления — может содержать unicode/эмодзи
    message: Mapped[str] = mapped_column(Text, nullable=False)
    # Уровень важности: info | warning | high | critical
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="info")
    # Флаг прочтения — для badge и фильтрации непрочитанных
    is_read: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # Время создания — индексировано для быстрой сортировки DESC
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
        nullable=False,
    )
