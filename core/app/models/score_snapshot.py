"""Снимок Security Score для истории изменений по времени (задача 11.B)."""
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, new_uuid


class ScoreSnapshot(Base):
    """Сохранённый результат расчёта Security Score Engine.

    Позволяет строить историю score актива/организации,
    отслеживать тренды и дрейф безопасности во времени.
    """

    __tablename__ = "score_snapshots"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)

    # Принадлежность организации — обязательно, изолирует данные тенантов
    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Опциональный актив — NULL означает агрегированный score всей организации
    asset_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )

    # Итоговый score 0–100
    total_score: Mapped[int] = mapped_column(Integer, nullable=False)

    # Буква-оценка: A | B | C | D | F
    grade: Mapped[str] = mapped_column(String(2), nullable=False)

    # JSON-слепок по категориям: {"network_security": {"score": 90, "penalty": 5.2, "event_count": 3}, ...}
    categories_json: Mapped[dict] = mapped_column(JSON, nullable=False)

    # Момент расчёта — индексировано для быстрой выборки истории по дате
    calculated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
