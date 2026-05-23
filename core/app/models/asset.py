from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, new_uuid


class Asset(Base, TimestampMixin):
    """Отслеживаемый домен/IP, принадлежащий организации."""

    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("organization_id", "domain", name="uq_asset_org_domain"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)

    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    organization: Mapped["Organization"] = relationship(back_populates="assets")  # type: ignore[name-defined]  # noqa: F821
    events: Mapped[list["Event"]] = relationship(back_populates="asset", cascade="all, delete-orphan")  # type: ignore[name-defined]  # noqa: F821
