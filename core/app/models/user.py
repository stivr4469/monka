from sqlalchemy import Boolean, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, new_uuid


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # MSSP-оператор: видит все организации, где mssp_owner_id == user.id
    is_mssp_operator: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    organization_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True
    )
    # foreign_keys явно указан — после добавления organizations.mssp_owner_id → users.id
    # между таблицами два FK-пути; без явного указания SQLAlchemy не знает какой использовать.
    organization: Mapped["Organization | None"] = relationship(  # type: ignore[name-defined]  # noqa: F821
        back_populates="users",
        foreign_keys="[User.organization_id]",
    )
