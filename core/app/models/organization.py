import enum

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, new_uuid


class OrgPlan(str, enum.Enum):
    """Тарифный план организации."""

    starter = "starter"
    professional = "professional"
    enterprise = "enterprise"


class Organization(Base, TimestampMixin):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    slug: Mapped[str] = mapped_column(String(100), nullable=False, unique=True, index=True)

    # URL для webhook-уведомлений о критических событиях.
    # Если задан — POST запрос отправляется при severity="critical".
    # Должен быть валидным HTTPS URL, принимающим POST с JSON-payload.
    webhook_url: Mapped[str | None] = mapped_column(String(2048), nullable=True, default=None)

    # Тарифный план: влияет на лимит доменов (assets).
    # starter=3, professional=10, enterprise=999999 (фактически безлимит).
    plan: Mapped[str] = mapped_column(String(32), default=OrgPlan.starter.value, nullable=False)

    users: Mapped[list["User"]] = relationship(back_populates="organization")  # type: ignore[name-defined]  # noqa: F821
    assets: Mapped[list["Asset"]] = relationship(back_populates="organization")  # type: ignore[name-defined]  # noqa: F821
    scan_schedules: Mapped[list["ScanSchedule"]] = relationship(back_populates="organization", lazy="noload")  # type: ignore[name-defined]  # noqa: F821
