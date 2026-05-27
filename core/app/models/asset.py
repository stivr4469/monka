from typing import Optional

from sqlalchemy import Float, ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, new_uuid

# Допустимые типы активов (supply chain phase 12.C)
ASSET_TYPE_PRIMARY = "primary"
ASSET_TYPE_VENDOR = "vendor"
ASSET_TYPE_SUBSIDIARY = "subsidiary"
VALID_ASSET_TYPES = {ASSET_TYPE_PRIMARY, ASSET_TYPE_VENDOR, ASSET_TYPE_SUBSIDIARY}


class Asset(Base, TimestampMixin):
    """Отслеживаемый домен/IP, принадлежащий организации."""

    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("organization_id", "domain", name="uq_asset_org_domain"),
        # Покрывает list_assets: WHERE organization_id ORDER BY created_at DESC
        Index("ix_asset_org_created", "organization_id", "created_at"),
        # Покрывает поиск активов по org + домену (помимо UniqueConstraint)
        Index("ix_asset_org_domain", "organization_id", "domain"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)
    # Коэффициент важности актива для формулы risk-score (диапазон 0.1–2.0, по умолчанию 1.0)
    importance: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)

    # 12.C: Тип актива — primary (главный), vendor (партнёр/вендор), subsidiary (дочерний)
    asset_type: Mapped[str] = mapped_column(
        String(50), nullable=False, default=ASSET_TYPE_PRIMARY, server_default=ASSET_TYPE_PRIMARY
    )
    # 12.C: Ссылка на родительский primary asset для vendor/subsidiary
    parent_asset_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("assets.id"), nullable=True
    )

    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    organization: Mapped["Organization"] = relationship(back_populates="assets")  # type: ignore[name-defined]  # noqa: F821
    events: Mapped[list["Event"]] = relationship(back_populates="asset", cascade="all, delete-orphan")  # type: ignore[name-defined]  # noqa: F821

    # 12.C: Дочерние supply chain активы (vendor/subsidiary)
    supply_chain_assets: Mapped[list["Asset"]] = relationship(
        "Asset",
        foreign_keys="Asset.parent_asset_id",
        back_populates="parent_asset",
    )
    parent_asset: Mapped[Optional["Asset"]] = relationship(
        "Asset",
        foreign_keys="Asset.parent_asset_id",
        back_populates="supply_chain_assets",
        remote_side="Asset.id",
    )
