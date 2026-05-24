"""Добавление таблицы notifications для центра уведомлений (задача 10.I).

Создаёт таблицу notifications:
  - id         — UUID, PK
  - org_id     — FK → organizations.id (CASCADE)
  - event_id   — опциональная ссылка на событие (без FK чтобы не блокировать удаление событий)
  - message    — текст уведомления
  - severity   — уровень: info | warning | high | critical
  - is_read    — прочитано ли (для badge и фильтрации)
  - created_at — время создания (UTC, индексировано для сортировки)

Revision ID: 20260525_add_notifications
Revises: 20260525_add_api_keys
Create Date: 2026-05-25
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260525_add_notifications"
down_revision: Union[str, None] = "20260525_add_api_keys"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "notifications",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column(
            "org_id",
            sa.String(36),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # event_id без FK — уведомления не удаляются каскадно при удалении событий
        sa.Column("event_id", sa.String(36), nullable=True),
        sa.Column("message", sa.Text, nullable=False),
        sa.Column("severity", sa.String(20), nullable=False, server_default="info"),
        sa.Column("is_read", sa.Boolean, nullable=False, server_default="0"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    # Индекс по org_id для быстрой фильтрации уведомлений организации
    op.create_index("ix_notifications_org_id", "notifications", ["org_id"])
    # Индекс по created_at для сортировки новейших уведомлений первыми
    op.create_index("ix_notifications_created_at", "notifications", ["created_at"])
    # Составной индекс для частого запроса: непрочитанные уведомления организации
    op.create_index(
        "ix_notifications_org_unread",
        "notifications",
        ["org_id", "is_read", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_notifications_org_unread", table_name="notifications")
    op.drop_index("ix_notifications_created_at", table_name="notifications")
    op.drop_index("ix_notifications_org_id", table_name="notifications")
    op.drop_table("notifications")
