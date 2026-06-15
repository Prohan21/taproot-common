"""Tests for TAP-38 migration preflight safety."""

import pytest

from taproot_common.activity.schema import (
    ACTIVITY_SCHEMA_MIGRATION_HEAD,
    ACTIVITY_TABLES,
    PURGE_TOMBSTONE_REQUIRED_COLUMNS,
    SYSTEM_RECORD_ALEMBIC_VERSION_TABLE,
    SYSTEM_RECORD_WRITE_FAILURE_REQUIRED_COLUMNS,
    validate_system_record_migration_preflight,
)


def test_migration_preflight_allows_empty_database():
    validate_system_record_migration_preflight(table_names=())


def test_migration_preflight_allows_current_expected_schema():
    validate_system_record_migration_preflight(
        table_names=(*ACTIVITY_TABLES, SYSTEM_RECORD_ALEMBIC_VERSION_TABLE),
        current_revisions=(ACTIVITY_SCHEMA_MIGRATION_HEAD,),
        columns_by_table={
            "system_record_write_failures": SYSTEM_RECORD_WRITE_FAILURE_REQUIRED_COLUMNS,
            "purge_tombstones": PURGE_TOMBSTONE_REQUIRED_COLUMNS,
        },
    )


def test_migration_preflight_fails_closed_on_old_dead_letter_shape():
    with pytest.raises(RuntimeError, match="activity_dead_letters"):
        validate_system_record_migration_preflight(
            table_names=(
                "activity_dead_letters",
                *tuple(
                    table
                    for table in ACTIVITY_TABLES
                    if table != "system_record_write_failures"
                ),
                SYSTEM_RECORD_ALEMBIC_VERSION_TABLE,
            ),
            current_revisions=(ACTIVITY_SCHEMA_MIGRATION_HEAD,),
        )


def test_migration_preflight_fails_closed_on_tables_without_version_table():
    with pytest.raises(RuntimeError, match="without system_record_alembic_version"):
        validate_system_record_migration_preflight(
            table_names=("interaction_records", "activity_records")
        )


def test_migration_preflight_fails_closed_on_stamped_table_mismatch():
    with pytest.raises(RuntimeError, match="missing expected tables"):
        validate_system_record_migration_preflight(
            table_names=(
                *tuple(
                    table
                    for table in ACTIVITY_TABLES
                    if table != "system_record_write_failures"
                ),
                SYSTEM_RECORD_ALEMBIC_VERSION_TABLE,
            ),
            current_revisions=(ACTIVITY_SCHEMA_MIGRATION_HEAD,),
        )


def test_migration_preflight_fails_closed_on_version_mismatch():
    with pytest.raises(RuntimeError, match="do not match expected head"):
        validate_system_record_migration_preflight(
            table_names=(*ACTIVITY_TABLES, SYSTEM_RECORD_ALEMBIC_VERSION_TABLE),
            current_revisions=("old_0001",),
        )


def test_migration_preflight_fails_closed_on_current_table_column_mismatch():
    with pytest.raises(RuntimeError, match="expected current 0001 shape"):
        validate_system_record_migration_preflight(
            table_names=(*ACTIVITY_TABLES, SYSTEM_RECORD_ALEMBIC_VERSION_TABLE),
            current_revisions=(ACTIVITY_SCHEMA_MIGRATION_HEAD,),
            columns_by_table={"system_record_write_failures": ("id", "created_at")},
        )


def test_migration_preflight_allows_base_revision_before_purged_at_migration():
    validate_system_record_migration_preflight(
        table_names=(*ACTIVITY_TABLES, SYSTEM_RECORD_ALEMBIC_VERSION_TABLE),
        current_revisions=("0001_system_record_schema",),
        columns_by_table={
            "system_record_write_failures": SYSTEM_RECORD_WRITE_FAILURE_REQUIRED_COLUMNS,
            "purge_tombstones": tuple(
                column
                for column in PURGE_TOMBSTONE_REQUIRED_COLUMNS
                if column != "purged_at"
            ),
        },
    )


def test_migration_preflight_fails_closed_on_current_purge_tombstone_mismatch():
    with pytest.raises(RuntimeError, match="purge_tombstones"):
        validate_system_record_migration_preflight(
            table_names=(*ACTIVITY_TABLES, SYSTEM_RECORD_ALEMBIC_VERSION_TABLE),
            current_revisions=(ACTIVITY_SCHEMA_MIGRATION_HEAD,),
            columns_by_table={
                "system_record_write_failures": SYSTEM_RECORD_WRITE_FAILURE_REQUIRED_COLUMNS,
                "purge_tombstones": ("id", "created_at"),
            },
        )
