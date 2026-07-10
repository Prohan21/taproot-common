"""Tests for TAP-38 migration preflight safety."""

import pytest

from taproot_common.activity.schema import (
    ACTIVITY_SCHEMA_KNOWN_REVISIONS,
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


def test_known_revisions_end_with_current_head():
    assert ACTIVITY_SCHEMA_KNOWN_REVISIONS[-1] == ACTIVITY_SCHEMA_MIGRATION_HEAD
    assert len(ACTIVITY_SCHEMA_KNOWN_REVISIONS) == len(
        set(ACTIVITY_SCHEMA_KNOWN_REVISIONS)
    )


def test_migration_preflight_allows_a_prior_head_revision_after_new_migrations_land():
    """A DB stamped at a formerly-current head (e.g. 0002, before this WO
    added 0003/0004) must remain a valid, non-fatal stamp for services that
    haven't re-locked and migrated yet — only an unknown/foreign revision or
    a table-shape mismatch should fail closed."""

    prior_head = "0002_purge_tombstone_purged_at"
    assert prior_head in ACTIVITY_SCHEMA_KNOWN_REVISIONS
    assert prior_head != ACTIVITY_SCHEMA_MIGRATION_HEAD

    validate_system_record_migration_preflight(
        table_names=(*ACTIVITY_TABLES, SYSTEM_RECORD_ALEMBIC_VERSION_TABLE),
        current_revisions=(prior_head,),
        columns_by_table={
            "system_record_write_failures": SYSTEM_RECORD_WRITE_FAILURE_REQUIRED_COLUMNS,
            "purge_tombstones": PURGE_TOMBSTONE_REQUIRED_COLUMNS,
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
