"""Модель аудит-лога для отслеживания обращений к расшифровке паролей (задача 10.B)."""
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, new_uuid


class AuditLog(Base):
    """Запись о каждом обращении к функции расшифровки пароля."""

    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)

    # Кто выполнил действие
    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Тип действия: "reveal_password" и т.д.
    action: Mapped[str] = mapped_column(String(50), nullable=False)

    # ID объекта, к которому было действие (event_id для reveal_password)
    target_id: Mapped[str] = mapped_column(String(36), nullable=False)

    # IPv4 или IPv6 адрес клиента
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)

    # User-Agent браузера/клиента (опционально)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # Время создания записи — индексировано для сортировки DESC
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    # Связь с пользователем — для JOIN-запросов в аудит-отчётах
    user: Mapped["User | None"] = relationship(foreign_keys=[user_id])  # type: ignore[name-defined]  # noqa: F821
