"""Добавление таблицы api_keys для SIEM/SOAR интеграции (задача 10.F).

Создаёт таблицу api_keys:
  - id           — UUID, PK
  - user_id      — FK → users.id (CASCADE)
  - name         — человекочитаемое название ключа
  - key_hash     — SHA-256 хеш от raw_key (сам ключ не хранится)
  - permissions  — JSON-массив разрешений ["events:read", "assets:read"]
  - created_at   — время создания (UTC)
  - last_used_at — время последнего использования (NULL пока не использован)
  - expires_at   — дата истечения (NULL = бессрочный)
  - is_active    — флаг мягкого удаления (revoke без физического DELETE)

Revision ID: 20260525_add_api_keys
Revises: 20260525_add_audit_log
Create Date: 2026-05-25
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260525_add_api_keys"
down_revision: Union[str, None] = "20260525_add_audit_log"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Новая таблица — создаём напрямую без batch_alter_table
    op.create_table(
        "api_keys",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column(
            "user_id",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(255), nullable=False),
        # SHA-256 хеш — 64 hex-символа, уникальный индекс для быстрого поиска
        sa.Column("key_hash", sa.String(64), nullable=False, unique=True),
        # JSON: ["events:read", "assets:read", "ingest:write"]
        sa.Column("permissions", sa.JSON, nullable=False, server_default="[]"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default="1"),
    )
    # Индекс по user_id для списка ключей пользователя
    op.create_index("ix_api_keys_user_id", "api_keys", ["user_id"])
    # Индекс по key_hash для аутентификации по ключу (самый частый запрос)
    op.create_index("ix_api_keys_key_hash", "api_keys", ["key_hash"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_api_keys_key_hash", table_name="api_keys")
    op.drop_index("ix_api_keys_user_id", table_name="api_keys")
    op.drop_table("api_keys")
