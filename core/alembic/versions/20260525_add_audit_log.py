"""Добавление таблицы audit_logs для записи расшифровок паролей (задача 10.B).

Создаёт таблицу audit_logs:
  - id           — UUID, PK
  - user_id      — FK → users.id (CASCADE)
  - action       — тип действия ("reveal_password")
  - target_id    — ID объекта действия (event_id)
  - ip_address   — IPv4/IPv6 клиента
  - user_agent   — User-Agent (опционально)
  - created_at   — время записи (UTC, индексировано)

Revision ID: 20260525_add_audit_log
Revises: 20260525_add_event_condition
Create Date: 2026-05-25
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260525_add_audit_log"
down_revision: Union[str, None] = "20260525_add_event_condition"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Новая таблица — создаём напрямую без batch_alter_table
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column(
            "user_id",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("action", sa.String(50), nullable=False),
        sa.Column("target_id", sa.String(36), nullable=False),
        sa.Column("ip_address", sa.String(45), nullable=False),
        sa.Column("user_agent", sa.String(512), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    # Индекс по user_id для быстрой выборки аудита конкретного пользователя
    op.create_index("ix_audit_logs_user_id", "audit_logs", ["user_id"])
    # Индекс по created_at для сортировки DESC в отчётах
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_audit_logs_created_at", table_name="audit_logs")
    op.drop_index("ix_audit_logs_user_id", table_name="audit_logs")
    op.drop_table("audit_logs")
