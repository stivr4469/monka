"""
Модель расписания автоматических сканирований.

Хранит конфигурацию повторяющихся сканов для организации/актива.
Реальный запуск по расписанию — через Celery Beat (TODO: Phase 9).
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, new_uuid


class ScanFrequency(str, Enum):
    """Допустимые частоты сканирования."""
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


class ScanSchedule(Base, TimestampMixin):
    """
    Расписание сканирования.

    Связь: организация → (необязательно) конкретный актив.
    Если asset_id=None — сканируются все активные активы организации.
    """

    __tablename__ = "scan_schedules"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=new_uuid,
    )

    # Обязательная связь с организацией
    organization_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Необязательная связь с конкретным активом
    # NULL → сканировать все активы организации
    asset_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("assets.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Частота сканирования
    frequency: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default=ScanFrequency.DAILY.value,
        comment="Частота: daily | weekly | monthly",
    )

    # Время последнего запуска (None если ещё не запускалось)
    last_run_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )

    # Время следующего запуска (вычисляется при создании/обновлении)
    next_run_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )

    # Флаг активности расписания
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        index=True,
    )

    # Отношения (lazy — не загружаем автоматически)
    organization: Mapped["Organization"] = relationship(  # type: ignore[name-defined]  # noqa: F821
        back_populates="scan_schedules",
        lazy="noload",
    )
    asset: Mapped["Asset | None"] = relationship(  # type: ignore[name-defined]  # noqa: F821
        lazy="noload",
    )

    def __repr__(self) -> str:
        return (
            f"<ScanSchedule id={self.id!r} org={self.organization_id!r} "
            f"freq={self.frequency!r} active={self.is_active}>"
        )
