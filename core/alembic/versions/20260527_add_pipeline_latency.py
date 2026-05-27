"""Добавление полей ingested_at и alert_sent_at для Event Pipeline Latency Monitoring.

Поля позволяют измерять время от приёма события до отправки алерта.
ingested_at — устанавливается автоматически (server_default=now()) при вставке строки.
alert_sent_at — выставляется вручную через PATCH /api/v1/internal/events/{id}/mark-alerted.

Revision ID: 20260527_add_pipeline_latency
Revises: 20260527_add_incident_id
Create Date: 2026-05-27
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# Идентификатор этой миграции
revision: str = "20260527_add_pipeline_latency"

# Предыдущая миграция в цепочке
down_revision: Union[str, None] = "20260527_add_alert_last_fired"

branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "events",
        sa.Column(
            "ingested_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=True,
            comment="Время приёма события API",
        ),
    )
    op.add_column(
        "events",
        sa.Column(
            "alert_sent_at",
            sa.DateTime(timezone=True),
            nullable=True,
            comment="Время отправки алерта",
        ),
    )
    # Индекс для быстрой фильтрации в pipeline_latency запросах
    op.create_index(
        "ix_event_ingested_at",
        "events",
        ["ingested_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_event_ingested_at", table_name="events")
    op.drop_column("events", "alert_sent_at")
    op.drop_column("events", "ingested_at")
