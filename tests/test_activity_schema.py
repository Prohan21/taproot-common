"""Smoke tests for TAP-38 system record schema metadata."""

import taproot_common.activity.schema as schema
from taproot_common.activity import (
    ACTIVITY_SCHEMA_MIGRATION_HEAD,
    ACTIVITY_PARTITION_RECOMMENDATIONS,
    ACTIVITY_TABLES,
    SYSTEM_RECORD_DATABASE_ENV_VAR,
    SYSTEM_RECORD_DATABASE_NAME,
)


def test_schema_metadata_defines_system_record_database():
    assert SYSTEM_RECORD_DATABASE_NAME == "system_record"
    assert SYSTEM_RECORD_DATABASE_ENV_VAR == "SYSTEM_RECORD_DATABASE_URL"
    assert ACTIVITY_SCHEMA_MIGRATION_HEAD == "0002_purge_tombstone_purged_at"


def test_schema_metadata_defines_all_v1_tables():
    assert ACTIVITY_TABLES == (
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


def test_schema_keeps_only_non_ddl_metadata():
    exported_names = set(dir(schema))

    assert "CREATE_ACTIVITY_TABLE_SQL" not in exported_names
    assert "CREATE_ACTIVITY_INDEX_SQL" not in exported_names
    assert "DROP_ACTIVITY_SCHEMA_SQL" not in exported_names
    assert "iter_activity_schema_sql" not in exported_names


def test_partition_recommendations_are_documented_but_not_executable_ddl():
    assert "activity_records by occurred_at" in ACTIVITY_PARTITION_RECOMMENDATIONS
    assert all(
        "partition by" not in value.lower()
        for value in ACTIVITY_PARTITION_RECOMMENDATIONS
    )
