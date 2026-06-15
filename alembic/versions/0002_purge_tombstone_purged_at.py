"""Add explicit purge timestamp to purge tombstones.

Revision ID: 0002_purge_tombstone_purged_at
Revises: 0001_system_record_schema
Create Date: 2026-06-15
"""

from __future__ import annotations

from typing import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "0002_purge_tombstone_purged_at"
down_revision: str | None = "0001_system_record_schema"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "purge_tombstones",
        sa.Column(
            "purged_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.alter_column("purge_tombstones", "purged_at", server_default=None)
    op.create_index(
        "idx_purge_tombstones_purged_at",
        "purge_tombstones",
        [sa.text("purged_at DESC")],
    )


def downgrade() -> None:
    op.drop_index("idx_purge_tombstones_purged_at", table_name="purge_tombstones")
    op.drop_column("purge_tombstones", "purged_at")
