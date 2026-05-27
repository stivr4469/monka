"""Добавление поля last_fired_at в alert_rules для отслеживания подавления алертов.

Поле фиксирует момент последней успешной отправки по правилу и используется
сервисом alert_suppression для реализации SUPPRESSION_WINDOW и эскалации.

Revision ID: 20260527_add_alert_last_fired
Revises: 20260525_add_score_snapshots
Create Date: 2026-05-27
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260527_add_alert_last_fired"
down_revision: Union[str, None] = "20260527_add_incident_id"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "alert_rules",
        sa.Column(
            "last_fired_at",
            sa.DateTime(timezone=True),
            nullable=True,
            comment="Время последней успешной отправки алерта по правилу (UTC). NULL = никогда не срабатывал.",
        ),
    )


def downgrade() -> None:
    op.drop_column("alert_rules", "last_fired_at")
