"""Добавление поля incident_id в таблицу events для Correlation Engine.

Поле incident_id (String 36) хранит UUID инцидента к которому сгруппировано
событие. NULL означает изолированное событие (не прошедшее корреляцию).
Индекс ix_event_incident_id покрывает запросы get_incident_events и
get_open_incidents по incident_id.

Revision ID: 20260527_add_incident_id
Revises: 20260525_add_score_snapshots
Create Date: 2026-05-27
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "20260527_add_incident_id"
down_revision: Union[str, None] = "20260525_add_score_snapshots"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("events", sa.Column("incident_id", sa.String(36), nullable=True))
    op.create_index("ix_event_incident_id", "events", ["incident_id"])


def downgrade() -> None:
    op.drop_index("ix_event_incident_id", table_name="events")
    op.drop_column("events", "incident_id")
