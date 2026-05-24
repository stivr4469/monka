"""Добавление поля plan в таблицу organizations (задача 8.I).

Revision ID: 20260524_add_org_plan
Revises:
Create Date: 2026-05-24
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260524_add_org_plan"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Добавляем колонку plan со значением по умолчанию 'starter'.
    # server_default гарантирует корректное заполнение существующих строк.
    op.add_column(
        "organizations",
        sa.Column(
            "plan",
            sa.String(length=32),
            nullable=False,
            server_default="starter",
        ),
    )


def downgrade() -> None:
    op.drop_column("organizations", "plan")
