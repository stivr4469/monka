"""Добавление полей condition и resolved_at в таблицу events (задача 9.H.3).

Добавляет:
  - events.condition (Text, nullable) — текст условия для снятия штрафа Risk Score
  - events.resolved_at (DateTime, nullable) — дата/время устранения (NULL = не устранено)

Revision ID: 20260525_add_event_condition
Revises: 20260524_add_mssp_fields
Create Date: 2026-05-25
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260525_add_event_condition"
down_revision: Union[str, None] = "20260524_add_mssp_fields"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # batch_alter_table обязателен для SQLite — он пересоздаёт таблицу под капотом,
    # что позволяет добавлять столбцы без ограничений SQLite на ALTER TABLE.
    with op.batch_alter_table("events") as batch_op:
        # Текстовое условие для снятия штрафа Risk Score.
        # Пример: "Закройте порт 3306 на хосте example.com"
        batch_op.add_column(
            sa.Column("condition", sa.Text(), nullable=True)
        )
        # Дата/время устранения события.
        # NULL означает, что угроза ещё не устранена.
        batch_op.add_column(
            sa.Column(
                "resolved_at",
                sa.DateTime(timezone=True),
                nullable=True,
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("events") as batch_op:
        batch_op.drop_column("resolved_at")
        batch_op.drop_column("condition")
