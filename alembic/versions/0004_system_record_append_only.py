"""DB-enforce append-only immutability on system_record fact tables (WO-018 T2).

Every SoR table except `retention_policies` (live editable config — it has an
`updated_at` column and is meant to be updated in place) is an append-only
fact/event log. This migration adds two independent layers so history cannot
be silently rewritten or deleted:

1. ``REVOKE UPDATE, DELETE ... FROM current_user`` — the role running this
   migration. Effective when the app connects as a role distinct from the
   table owner (a mature multi-role Postgres deployment). A no-op (wrapped in
   a DO block, ignored via ``insufficient_privilege``/``undefined_object``)
   when the running role lacks GRANT/REVOKE privilege on the table.
2. A ``BEFORE UPDATE OR DELETE`` reject-trigger — fires for every role,
   including the table owner, since object ownership in PostgreSQL bypasses
   GRANT/REVOKE checks entirely. This is the enforcement that actually holds
   in a single-role deployment (the common case here: migrations and the app
   connect as the same role).

A privileged retention/purge job (WO-018 §C5, not yet built) can perform a
legitimate delete by running ``SET LOCAL taproot.sor_retention_mode = 'on'``
within its own transaction before the mutation; the trigger checks this GUC
and allows the operation only then. Ordinary app connections never set it.

Revision ID: 0004_system_record_append_only
Revises: 0003_activity_records_hash_chain
Create Date: 2026-07-10
"""

from __future__ import annotations

from typing import Sequence

from alembic import op

from taproot_common.activity.schema import (
    SYSTEM_RECORD_APPEND_ONLY_TABLES,
    SYSTEM_RECORD_RETENTION_BYPASS_GUC,
)

revision: str = "0004_system_record_append_only"
down_revision: str | None = "0003_activity_records_hash_chain"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_REJECT_FUNCTION = "system_record_reject_mutation"


def upgrade() -> None:
    op.execute(f"""
        CREATE OR REPLACE FUNCTION {_REJECT_FUNCTION}() RETURNS trigger AS $$
        BEGIN
            IF current_setting('{SYSTEM_RECORD_RETENTION_BYPASS_GUC}', true) = 'on' THEN
                RETURN COALESCE(NEW, OLD);
            END IF;
            RAISE EXCEPTION
                'system_record.% is append-only; % is not permitted outside retention mode',
                TG_TABLE_NAME, TG_OP
                USING ERRCODE = 'insufficient_privilege';
        END;
        $$ LANGUAGE plpgsql;
    """)

    for table_name in SYSTEM_RECORD_APPEND_ONLY_TABLES:
        op.execute(f"ALTER TABLE {table_name} SET (fillfactor = 100)")
        op.execute(f"""
            CREATE TRIGGER {table_name}_append_only
            BEFORE UPDATE OR DELETE ON {table_name}
            FOR EACH ROW EXECUTE FUNCTION {_REJECT_FUNCTION}();
        """)
        op.execute(f"""
            DO $$
            BEGIN
                EXECUTE format(
                    'REVOKE UPDATE, DELETE ON {table_name} FROM %I',
                    current_user
                );
            EXCEPTION
                WHEN insufficient_privilege THEN NULL;
                WHEN undefined_object THEN NULL;
            END;
            $$
        """)


def downgrade() -> None:
    for table_name in reversed(SYSTEM_RECORD_APPEND_ONLY_TABLES):
        op.execute(f"DROP TRIGGER IF EXISTS {table_name}_append_only ON {table_name}")
    op.execute(f"DROP FUNCTION IF EXISTS {_REJECT_FUNCTION}()")
