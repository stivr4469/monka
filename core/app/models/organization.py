from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, new_uuid


class Organization(Base, TimestampMixin):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    slug: Mapped[str] = mapped_column(String(100), nullable=False, unique=True, index=True)

    users: Mapped[list["User"]] = relationship(back_populates="organization")  # type: ignore[name-defined]  # noqa: F821
    assets: Mapped[list["Asset"]] = relationship(back_populates="organization")  # type: ignore[name-defined]  # noqa: F821
