"""Добавление таблицы score_snapshots для Security Score Engine (задача 11.B).

Создаёт таблицу score_snapshots:
  - id             — UUID, PK
  - org_id         — FK → organizations.id (CASCADE)
  - asset_id       — FK → assets.id (CASCADE), nullable — NULL = org-level score
  - total_score    — int 0–100
  - grade          — A | B | C | D | F
  - categories_json — JSON-слепок по категориям
  - calculated_at  — UTC timestamp, индексировано для выборки истории

Revision ID: 20260525_add_score_snapshots
Revises: 20260525_add_notifications
Create Date: 2026-05-25
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260525_add_score_snapshots"
down_revision: Union[str, None] = "20260525_add_notifications"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "score_snapshots",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column(
            "org_id",
            sa.String(36),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "asset_id",
            sa.String(36),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("total_score", sa.Integer, nullable=False),
        sa.Column("grade", sa.String(2), nullable=False),
        sa.Column("categories_json", sa.JSON, nullable=False),
        sa.Column(
            "calculated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    # Индекс по org_id — основная фильтрация по тенанту
    op.create_index("ix_score_snapshots_org_id", "score_snapshots", ["org_id"])
    # Индекс по asset_id — выборка истории конкретного актива
    op.create_index("ix_score_snapshots_asset_id", "score_snapshots", ["asset_id"])
    # Индекс по calculated_at — сортировка по времени (DESC для истории)
    op.create_index("ix_score_snapshots_calculated_at", "score_snapshots", ["calculated_at"])
    # Составной индекс для запроса: история актива за период
    op.create_index(
        "ix_score_snapshots_asset_time",
        "score_snapshots",
        ["asset_id", "calculated_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_score_snapshots_asset_time", table_name="score_snapshots")
    op.drop_index("ix_score_snapshots_calculated_at", table_name="score_snapshots")
    op.drop_index("ix_score_snapshots_asset_id", table_name="score_snapshots")
    op.drop_index("ix_score_snapshots_org_id", table_name="score_snapshots")
    op.drop_table("score_snapshots")
