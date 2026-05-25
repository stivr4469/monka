from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, new_uuid


class Event(Base):
    """Нормализованное событие безопасности от воркера."""

    __tablename__ = "events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    event_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    source_type: Mapped[str] = mapped_column(String(50), nullable=False)
    source_name: Mapped[str] = mapped_column(String(255), nullable=False)
    target_domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    # Хэш для дедупликации (source_type + target_domain + payload key)
    dedup_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    # 9.H.3: Условие для снятия штрафа Risk Score (что нужно сделать)
    condition: Mapped[str | None] = mapped_column(Text, nullable=True)

    # 11.D: Флаг устранения уязвимости
    resolved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="0")

    # 9.H.3 / 11.D: Когда условие выполнено (NULL = не устранено)
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # 11.D: Кто пометил событие как устранённое
    resolved_by: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # 13.H: Ссылка на тикет в Jira или ServiceNow
    # Формат: "jira:SEC-123" или "servicenow:INC0001234"
    ticket_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)

    asset_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True
    )
    asset: Mapped["Asset | None"] = relationship(back_populates="events")  # type: ignore[name-defined]  # noqa: F821
