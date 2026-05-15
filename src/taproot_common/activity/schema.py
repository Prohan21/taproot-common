"""Non-DDL metadata for the TAP-38 system record database."""

from __future__ import annotations

SYSTEM_RECORD_DATABASE_NAME = "system_record"
SYSTEM_RECORD_DATABASE_ENV_VAR = "SYSTEM_RECORD_DATABASE_URL"
ACTIVITY_SCHEMA_MIGRATION_HEAD = "0001_system_record_schema"

ACTIVITY_TABLES: tuple[str, ...] = (
    "retention_policies",
    "interaction_records",
    "activity_records",
    "activity_snapshots",
    "activity_diffs",
    "activity_evidence_links",
    "retention_applications",
    "purge_tombstones",
    "activity_dead_letters",
)

ACTIVITY_PARTITION_RECOMMENDATIONS: tuple[str, ...] = (
    "activity_records by occurred_at",
    "activity_evidence_links by created_at when evidence volume warrants it",
)
