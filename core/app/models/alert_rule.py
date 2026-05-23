"""
Модель правил алертов для Telegram-уведомлений.
Каждое правило описывает фильтр событий и куда отправлять уведомления.
"""
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, JSON, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, new_uuid

# Допустимые уровни серьёзности в порядке возрастания
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


class AlertRule(Base):
    """
    Правило алерта: фильтрует события и отправляет уведомления в Telegram.

    Логика сопоставления:
      - target_domain == None  → правило срабатывает для ВСЕХ доменов org
      - event_types == None    → правило срабатывает для ВСЕХ типов событий
      - min_severity           → только события с severity >= min_severity
    """

    __tablename__ = "alert_rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)

    organization_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Человекочитаемое имя правила
    name: Mapped[str] = mapped_column(String(255), nullable=False)

    # None = срабатывает на все домены организации
    target_domain: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)

    # Минимальный уровень серьёзности для срабатывания
    min_severity: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")

    # None = все типы событий; список строк = только эти типы
    event_types: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)

    # Telegram chat_id куда слать сообщения (например, "-1001234567890")
    telegram_chat_id: Mapped[str] = mapped_column(String(100), nullable=False)

    # Правило активно/неактивно без удаления
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationship — не загружается жадно, только по запросу
    organization: Mapped["Organization"] = relationship()  # type: ignore[name-defined]  # noqa: F821

    def matches_event(self, event: dict[str, Any]) -> bool:
        """
        Проверяет, подходит ли событие под это правило.
        Вызывается воркером при диспетчеризации алертов.
        """
        # Проверка домена
        if self.target_domain is not None:
            event_domain = event.get("target_domain", "")
            if event_domain != self.target_domain:
                return False

        # Проверка типа события
        if self.event_types is not None:
            if event.get("event_type") not in self.event_types:
                return False

        # Проверка уровня серьёзности (min_severity — минимальный порог)
        event_severity = event.get("severity", "info")
        try:
            event_idx = SEVERITY_ORDER.index(event_severity)
            min_idx = SEVERITY_ORDER.index(self.min_severity)
        except ValueError:
            # Неизвестные severity пропускаем
            return False

        return event_idx >= min_idx
