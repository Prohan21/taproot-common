"""Add hash-chain columns to activity_records for tamper-evidence (WO-018 T1).

Additive/backward-compatible: new nullable columns only, no rewrite of
existing rows. Pre-migration rows are left with NULL chain fields (they
predate chaining and are outside any chain); every new write populates all
four columns via the recorder (`ActivityRecorder._chain_activity_record`).

Revision ID: 0003_activity_records_hash_chain
Revises: 0002_purge_tombstone_purged_at
Create Date: 2026-07-10
"""

from __future__ import annotations

from typing import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "0003_activity_records_hash_chain"
down_revision: str | None = "0002_purge_tombstone_purged_at"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("activity_records", sa.Column("chain_key", sa.Text(), nullable=True))
    op.add_column(
        "activity_records", sa.Column("chain_seq", sa.BigInteger(), nullable=True)
    )
    op.add_column(
        "activity_records", sa.Column("prev_record_hash", sa.Text(), nullable=True)
    )
    op.add_column(
        "activity_records", sa.Column("record_hash", sa.Text(), nullable=True)
    )
    op.create_index(
        "uq_activity_records_chain_key_seq",
        "activity_records",
        ["chain_key", "chain_seq"],
        unique=True,
        postgresql_where=sa.text("chain_seq IS NOT NULL"),
    )
    op.create_index(
        "idx_activity_records_chain_key_seq_desc",
        "activity_records",
        ["chain_key", sa.text("chain_seq DESC")],
        postgresql_where=sa.text("chain_seq IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index(
        "idx_activity_records_chain_key_seq_desc", table_name="activity_records"
    )
    op.drop_index("uq_activity_records_chain_key_seq", table_name="activity_records")
    op.drop_column("activity_records", "record_hash")
    op.drop_column("activity_records", "prev_record_hash")
    op.drop_column("activity_records", "chain_seq")
    op.drop_column("activity_records", "chain_key")
