"""Добавление asset_type и parent_asset_id к таблице assets (Phase 12.C Supply Chain).

Добавляет поля для мониторинга supply chain:
  - asset_type      — тип актива: "primary", "vendor", "subsidiary" (по умолчанию "primary")
  - parent_asset_id — FK → assets.id, ссылка на родительский primary asset

Revision ID: 20260525_add_asset_type
Revises: 20260525_add_api_keys
Create Date: 2026-05-25
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260525_add_asset_type"
down_revision: Union[str, None] = "20260525_add_api_keys"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Добавляем asset_type — NOT NULL с server_default чтобы не нарушить существующие строки
    op.add_column(
        "assets",
        sa.Column(
            "asset_type",
            sa.String(50),
            nullable=False,
            server_default="primary",
        ),
    )
    # Добавляем parent_asset_id — nullable FK на саму же таблицу assets
    op.add_column(
        "assets",
        sa.Column(
            "parent_asset_id",
            sa.String(36),
            sa.ForeignKey("assets.id"),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("assets", "parent_asset_id")
    op.drop_column("assets", "asset_type")
