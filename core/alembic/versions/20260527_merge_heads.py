"""Merge двух веток миграций в единую голову.

Revision ID: 20260527_merge_heads
Revises: 20260525_add_asset_type, 20260527_add_pipeline_latency
Create Date: 2026-05-27
"""
from typing import Union
from alembic import op

revision: str = "20260527_merge_heads"
down_revision: Union[tuple, None] = (
    "20260525_add_asset_type",
    "20260527_add_pipeline_latency",
)
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
