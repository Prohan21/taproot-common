"""Smoke tests for TAP-38 activity database schema DDL."""

import re

from taproot_common.activity import (
    ACTIVITY_PARTITION_RECOMMENDATIONS,
    ACTIVITY_TABLES,
    CREATE_ACTIVITY_INDEX_SQL,
    CREATE_ACTIVITY_TABLE_SQL,
    DROP_ACTIVITY_SCHEMA_SQL,
    iter_activity_schema_sql,
)


def test_schema_defines_all_v1_tables():
    ddl = _normalized_sql(iter_activity_schema_sql())

    for table_name in ACTIVITY_TABLES:
        assert f"create table if not exists {table_name}" in ddl


def test_schema_includes_required_core_columns():
    ddl = _normalized_sql(CREATE_ACTIVITY_TABLE_SQL)

    required_columns = (
        "id bigint generated always as identity primary key",
        "interaction_id text unique not null",
        "interaction_type text not null",
        "activity_id text unique not null",
        "parent_activity_id text null",
        "primary_target jsonb not null",
        "related_targets jsonb null",
        "reconstruction_refs jsonb null",
        "retention_expires_at timestamptz null",
        "dead_letter_id text unique not null",
    )

    for column in required_columns:
        assert column in ddl
    assert ddl.count("id bigint generated always as identity primary key") == len(
        ACTIVITY_TABLES
    )


def test_schema_does_not_require_uuid_extension_for_internal_ids():
    ddl = _normalized_sql(CREATE_ACTIVITY_TABLE_SQL)

    assert "create extension" not in ddl
    assert "pgcrypto" not in ddl
    assert "gen_random_uuid" not in ddl


def test_schema_includes_timeline_target_retention_and_dead_letter_indexes():
    ddl = _normalized_sql(CREATE_ACTIVITY_INDEX_SQL)
    required_indexes = (
        "idx_activity_records_project_occurred",
        "idx_activity_records_project_interaction_occurred",
        "idx_activity_records_interaction",
        "idx_activity_records_project_target_occurred",
        "idx_activity_records_retention_expiry",
        "idx_activity_records_parent_occurred",
        "idx_retention_applications_activity",
        "idx_purge_tombstones_activity",
        "idx_activity_dead_letters_status_retry",
        "uq_activity_evidence_links_activity_evidence",
        "idx_activity_evidence_links_project_evidence",
    )

    for index_name in required_indexes:
        assert index_name in ddl


def test_schema_is_ordered_for_foreign_keys():
    statements = list(iter_activity_schema_sql())
    table_positions = {
        table_name: _statement_position(
            statements, f"CREATE TABLE IF NOT EXISTS {table_name}"
        )
        for table_name in ACTIVITY_TABLES
    }

    assert table_positions["interaction_records"] < table_positions["activity_records"]
    assert table_positions["activity_records"] < table_positions["activity_snapshots"]
    assert table_positions["activity_records"] < table_positions["activity_diffs"]
    assert (
        table_positions["activity_records"] < table_positions["activity_evidence_links"]
    )
    assert table_positions["activity_records"] < table_positions["purge_tombstones"]


def test_drop_schema_reverses_table_order():
    assert DROP_ACTIVITY_SCHEMA_SQL[0].startswith(
        "DROP TABLE IF EXISTS activity_dead_letters"
    )
    assert DROP_ACTIVITY_SCHEMA_SQL[-1].startswith(
        "DROP TABLE IF EXISTS retention_policies"
    )


def test_partition_recommendations_are_documented_but_not_forced():
    assert "activity_records by occurred_at" in ACTIVITY_PARTITION_RECOMMENDATIONS
    assert "partition by" not in _normalized_sql(CREATE_ACTIVITY_TABLE_SQL)


def _normalized_sql(statements: tuple[str, ...]) -> str:
    return re.sub(r"\s+", " ", "\n".join(statements).lower())


def _statement_position(statements: list[str], needle: str) -> int:
    for index, statement in enumerate(statements):
        if needle.lower() in statement.lower():
            return index
    raise AssertionError(f"Statement not found: {needle}")
