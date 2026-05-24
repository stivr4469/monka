"""Добавление полей MSSP Multi-Tenancy (задача 9.F).

Добавляет:
  - users.is_mssp_operator (Boolean, default False) — роль оператора ИБ-сервиса
  - organizations.mssp_owner_id (String(36), FK→users.id) — привязка клиента к MSSP-оператору

Revision ID: 20260524_add_mssp_fields
Revises: 20260524_add_org_plan
Create Date: 2026-05-24
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260524_add_mssp_fields"
down_revision: Union[str, None] = "20260524_add_org_plan"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Добавляем роль MSSP-оператора в таблицу пользователей.
    # server_default="false" обеспечивает корректное значение для существующих строк
    # без необходимости обновлять каждую запись вручную.
    op.add_column(
        "users",
        sa.Column(
            "is_mssp_operator",
            sa.Boolean(),
            nullable=False,
            server_default="false",
        ),
    )

    # Добавляем ссылку на MSSP-оператора в таблицу организаций.
    # nullable=True — не все организации являются клиентами MSSP.
    # Индекс ускоряет запрос "все клиенты оператора X".
    op.add_column(
        "organizations",
        sa.Column(
            "mssp_owner_id",
            sa.String(36),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_organizations_mssp_owner_id",
        "organizations",
        ["mssp_owner_id"],
    )
    # FK добавляем отдельно для совместимости с SQLite (используется в тестах).
    # В production (PostgreSQL) это создаёт настоящий FK с ON DELETE SET NULL.
    with op.batch_alter_table("organizations") as batch_op:
        batch_op.create_foreign_key(
            "fk_organizations_mssp_owner_id_users",
            "users",
            ["mssp_owner_id"],
            ["id"],
            ondelete="SET NULL",
        )


def downgrade() -> None:
    with op.batch_alter_table("organizations") as batch_op:
        batch_op.drop_constraint(
            "fk_organizations_mssp_owner_id_users",
            type_="foreignkey",
        )
    op.drop_index("ix_organizations_mssp_owner_id", table_name="organizations")
    op.drop_column("organizations", "mssp_owner_id")
    op.drop_column("users", "is_mssp_operator")
