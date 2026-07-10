"""Non-DDL metadata for the TAP-38 system record database."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

SYSTEM_RECORD_DATABASE_NAME = "system_record"
SYSTEM_RECORD_DATABASE_ENV_VAR = "SYSTEM_RECORD_DATABASE_URL"

# Every revision ever shipped, oldest first. A DB may legitimately be stamped
# at any of these while services roll forward at different paces; only a
# revision outside this set (or a stamp/table-shape mismatch) fails closed.
# Add each new migration's revision id to the end of this tuple.
ACTIVITY_SCHEMA_KNOWN_REVISIONS: tuple[str, ...] = (
    "0001_system_record_schema",
    "0002_purge_tombstone_purged_at",
    "0003_activity_records_hash_chain",
)
ACTIVITY_SCHEMA_MIGRATION_BASE = ACTIVITY_SCHEMA_KNOWN_REVISIONS[0]
ACTIVITY_SCHEMA_MIGRATION_HEAD = ACTIVITY_SCHEMA_KNOWN_REVISIONS[-1]
SYSTEM_RECORD_ALEMBIC_VERSION_TABLE = "system_record_alembic_version"
LEGACY_ACTIVITY_DEAD_LETTER_TABLE = "activity_dead_letters"

ACTIVITY_TABLES: tuple[str, ...] = (
    "retention_policies",
    "interaction_records",
    "activity_records",
    "activity_snapshots",
    "activity_diffs",
    "activity_evidence_links",
    "retention_applications",
    "purge_tombstones",
    "system_record_write_failures",
)

ACTIVITY_PARTITION_RECOMMENDATIONS: tuple[str, ...] = (
    "activity_records by occurred_at",
    "activity_evidence_links by created_at when evidence volume warrants it",
)

SYSTEM_RECORD_WRITE_FAILURE_REQUIRED_COLUMNS: frozenset[str] = frozenset(
    {
        "failure_id",
        "project_id",
        "domain_area",
        "operation_type",
        "safe_context",
        "error_type",
        "error_category",
        "created_at",
    }
)

PURGE_TOMBSTONE_REQUIRED_COLUMNS: frozenset[str] = frozenset(
    {
        "purge_tombstone_id",
        "activity_id",
        "project_id",
        "domain_area",
        "target_type",
        "target_id",
        "purge_reason",
        "purge_scope",
        "initiated_by",
        "retention_policy_id",
        "purged_evidence_classes",
        "purged_at",
        "created_at",
    }
)


def validate_system_record_migration_preflight(
    *,
    table_names: Iterable[str],
    current_revisions: Iterable[str] | None = None,
    columns_by_table: Mapping[str, Iterable[str]] | None = None,
) -> None:
    """Fail closed when a stamped system-record DB has suspicious v1 shape.

    The TAP-38 ``0001`` revision was mutated during development from the legacy
    ``activity_dead_letters`` table to ``system_record_write_failures``. A DB
    that was already stamped with the old revision can otherwise look current
    to Alembic while having the wrong failure-visibility table. This preflight
    deliberately allows only an empty DB or a DB whose visible system-record
    tables match the expected current ``0001`` shape.
    """

    tables = {name for name in table_names if name}
    expected_tables = set(ACTIVITY_TABLES)
    system_record_tables = tables & expected_tables
    has_version_table = SYSTEM_RECORD_ALEMBIC_VERSION_TABLE in tables

    if LEGACY_ACTIVITY_DEAD_LETTER_TABLE in tables:
        raise RuntimeError(
            "Refusing to run system record migrations: found legacy "
            f"{LEGACY_ACTIVITY_DEAD_LETTER_TABLE} table from an old mutated "
            "0001_system_record_schema revision. Restore from a compatible "
            "backup or run an explicit operator-approved remediation."
        )

    if not system_record_tables and not has_version_table:
        return

    if system_record_tables and not has_version_table:
        raise RuntimeError(
            "Refusing to run system record migrations: system record tables "
            "exist without system_record_alembic_version. This schema may be "
            "partially applied or manually mutated."
        )

    revisions = {revision for revision in (current_revisions or ()) if revision}
    valid_revisions = set(ACTIVITY_SCHEMA_KNOWN_REVISIONS)
    if has_version_table and (len(revisions) != 1 or not revisions <= valid_revisions):
        raise RuntimeError(
            "Refusing to run system record migrations: "
            f"{SYSTEM_RECORD_ALEMBIC_VERSION_TABLE} revisions "
            f"{sorted(revisions) or ['<empty>']} do not match expected head "
            f"{ACTIVITY_SCHEMA_MIGRATION_HEAD}."
        )

    missing_tables = expected_tables - tables
    if missing_tables:
        raise RuntimeError(
            "Refusing to run system record migrations: DB is stamped with "
            f"{ACTIVITY_SCHEMA_MIGRATION_HEAD} but is missing expected tables "
            f"{sorted(missing_tables)}."
        )

    if columns_by_table is None:
        return

    failure_columns = set(columns_by_table.get("system_record_write_failures", ()))
    missing_failure_columns = (
        SYSTEM_RECORD_WRITE_FAILURE_REQUIRED_COLUMNS - failure_columns
    )
    if missing_failure_columns:
        raise RuntimeError(
            "Refusing to run system record migrations: "
            "system_record_write_failures does not match the expected current "
            f"0001 shape; missing columns {sorted(missing_failure_columns)}."
        )

    if ACTIVITY_SCHEMA_MIGRATION_HEAD in revisions:
        tombstone_columns = set(columns_by_table.get("purge_tombstones", ()))
        missing_tombstone_columns = PURGE_TOMBSTONE_REQUIRED_COLUMNS - tombstone_columns
        if missing_tombstone_columns:
            raise RuntimeError(
                "Refusing to run system record migrations: purge_tombstones does "
                "not match the expected current head shape; missing columns "
                f"{sorted(missing_tombstone_columns)}."
            )
