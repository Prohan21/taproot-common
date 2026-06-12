"""Activity storage Adapter contracts and PostgreSQL implementation."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping, Protocol, Sequence


JSONB_COLUMNS_BY_TABLE: dict[str, frozenset[str]] = {
    "retention_policies": frozenset({"config"}),
    "interaction_records": frozenset(
        {"caller_summary", "default_actor_chain", "collapse_metadata"}
    ),
    "activity_records": frozenset(
        {
            "primary_target",
            "related_targets",
            "actor_override",
            "reconstruction_refs",
            "metadata",
        }
    ),
    "activity_snapshots": frozenset({"snapshot_payload"}),
    "activity_diffs": frozenset({"diff_payload"}),
    "activity_evidence_links": frozenset({"evidence_ref"}),
    "retention_applications": frozenset({"metadata"}),
    "purge_tombstones": frozenset({"initiated_by"}),
    "system_record_write_failures": frozenset({"safe_context"}),
}


class ActivityDbExecutor(Protocol):
    """Minimal async executor protocol implemented by common Postgres drivers."""

    async def execute(self, query: str, *args: Any) -> Any:
        """Execute a SQL statement."""
        ...


class ActivityStorageAdapter(Protocol):
    """Storage Adapter Interface for TAP-38 activity persistence."""

    async def write_interaction_record(
        self, record: Mapping[str, Any]
    ) -> StorageWriteResult: ...

    async def write_activity_record(
        self, record: Mapping[str, Any]
    ) -> StorageWriteResult: ...

    async def write_snapshot(self, record: Mapping[str, Any]) -> StorageWriteResult: ...

    async def write_diff(self, record: Mapping[str, Any]) -> StorageWriteResult: ...

    async def write_evidence_link(
        self, record: Mapping[str, Any]
    ) -> StorageWriteResult: ...

    async def write_retention_policy(
        self, record: Mapping[str, Any]
    ) -> StorageWriteResult: ...

    async def write_retention_application(
        self, record: Mapping[str, Any]
    ) -> StorageWriteResult: ...

    async def write_purge_tombstone(
        self, record: Mapping[str, Any]
    ) -> StorageWriteResult: ...

    async def write_system_record_write_failure(
        self, record: Mapping[str, Any]
    ) -> StorageWriteResult: ...


@dataclass(frozen=True)
class StorageWriteResult:
    """Result of an idempotent storage write."""

    table_name: str
    idempotency_key: str
    created: bool | None = None


class ActivityStorageError(RuntimeError):
    """Raised when activity storage rejects a write before reaching the DB."""


class ActivityStorageConflictError(ActivityStorageError):
    """Raised when an idempotency key is reused with a different payload."""


@dataclass(frozen=True)
class PostgresActivityStorageAdapter:
    """PostgreSQL activity storage Adapter.

    The Adapter depends on a tiny async ``execute`` protocol instead of a
    concrete driver. ``asyncpg.Connection``, connection-pool proxies, or test
    fakes can satisfy the protocol without adding a dependency here.
    """

    executor: ActivityDbExecutor

    async def write_interaction_record(
        self, record: Mapping[str, Any]
    ) -> StorageWriteResult:
        return await self._insert(
            table_name="interaction_records",
            columns=(
                "interaction_id",
                "interaction_type",
                "project_id",
                "domain_area",
                "caller_summary",
                "default_actor_chain",
                "root_agent_id",
                "source_entry_point",
                "retention_policy_id",
                "collapse_metadata",
                "started_at",
            ),
            required=("interaction_id", "interaction_type", "started_at"),
            record=record,
            conflict_columns=("interaction_id",),
            compare_columns=(
                "interaction_type",
                "project_id",
                "domain_area",
                "caller_summary",
                "default_actor_chain",
                "root_agent_id",
                "source_entry_point",
                "retention_policy_id",
                "collapse_metadata",
            ),
        )

    async def write_activity_record(
        self, record: Mapping[str, Any]
    ) -> StorageWriteResult:
        return await self._insert(
            table_name="activity_records",
            columns=(
                "activity_id",
                "interaction_id",
                "parent_activity_id",
                "project_id",
                "domain_area",
                "target_type",
                "target_id",
                "action_family",
                "action",
                "lifecycle_phase",
                "outcome",
                "durability",
                "evidence_class",
                "event_label",
                "primary_target",
                "related_targets",
                "actor_override",
                "reconstruction_refs",
                "metadata",
                "retention_policy_id",
                "retention_expires_at",
                "occurred_at",
            ),
            required=(
                "activity_id",
                "domain_area",
                "target_type",
                "target_id",
                "action_family",
                "action",
                "lifecycle_phase",
                "outcome",
                "durability",
                "event_label",
                "primary_target",
                "occurred_at",
            ),
            record=record,
            conflict_columns=("activity_id",),
        )

    async def write_snapshot(self, record: Mapping[str, Any]) -> StorageWriteResult:
        return await self._insert(
            table_name="activity_snapshots",
            columns=(
                "snapshot_id",
                "activity_id",
                "project_id",
                "domain_area",
                "target_type",
                "target_id",
                "snapshot_kind",
                "snapshot_payload",
                "payload_hash",
                "retention_policy_id",
                "retention_expires_at",
            ),
            required=(
                "snapshot_id",
                "activity_id",
                "domain_area",
                "target_type",
                "target_id",
                "snapshot_kind",
                "snapshot_payload",
                "payload_hash",
            ),
            record=record,
            conflict_columns=("snapshot_id",),
        )

    async def write_diff(self, record: Mapping[str, Any]) -> StorageWriteResult:
        return await self._insert(
            table_name="activity_diffs",
            columns=(
                "diff_id",
                "activity_id",
                "project_id",
                "domain_area",
                "target_type",
                "target_id",
                "diff_payload",
                "payload_hash",
            ),
            required=(
                "diff_id",
                "activity_id",
                "domain_area",
                "target_type",
                "target_id",
                "diff_payload",
                "payload_hash",
            ),
            record=record,
            conflict_columns=("diff_id",),
        )

    async def write_evidence_link(
        self, record: Mapping[str, Any]
    ) -> StorageWriteResult:
        return await self._insert(
            table_name="activity_evidence_links",
            columns=(
                "activity_id",
                "project_id",
                "domain_area",
                "evidence_type",
                "evidence_id",
                "evidence_ref",
                "content_hash",
                "metadata_hash",
            ),
            required=(
                "activity_id",
                "domain_area",
                "evidence_type",
                "evidence_id",
                "evidence_ref",
            ),
            record=record,
            conflict_columns=("activity_id", "evidence_type", "evidence_id"),
            idempotency_key=_evidence_link_key(record),
        )

    async def write_retention_policy(
        self, record: Mapping[str, Any]
    ) -> StorageWriteResult:
        return await self._insert(
            table_name="retention_policies",
            columns=(
                "retention_policy_id",
                "project_id",
                "domain_area",
                "policy_name",
                "enabled",
                "default_days",
                "evidence_days",
                "hard_purge_after_days",
                "compliance_hold",
                "config",
            ),
            required=("retention_policy_id", "domain_area", "policy_name"),
            record=record,
            conflict_columns=("retention_policy_id",),
        )

    async def write_retention_application(
        self, record: Mapping[str, Any]
    ) -> StorageWriteResult:
        return await self._insert(
            table_name="retention_applications",
            columns=(
                "application_id",
                "retention_policy_id",
                "activity_id",
                "project_id",
                "domain_area",
                "target_type",
                "target_id",
                "action_taken",
                "applied_at",
                "metadata",
            ),
            required=(
                "application_id",
                "retention_policy_id",
                "domain_area",
                "target_type",
                "target_id",
                "action_taken",
                "applied_at",
            ),
            record=record,
            conflict_columns=("application_id",),
        )

    async def write_purge_tombstone(
        self, record: Mapping[str, Any]
    ) -> StorageWriteResult:
        return await self._insert(
            table_name="purge_tombstones",
            columns=(
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
            ),
            required=(
                "purge_tombstone_id",
                "activity_id",
                "domain_area",
                "target_type",
                "target_id",
                "purge_reason",
                "purge_scope",
            ),
            record=record,
            conflict_columns=("purge_tombstone_id",),
        )

    async def write_system_record_write_failure(
        self, record: Mapping[str, Any]
    ) -> StorageWriteResult:
        return await self._insert(
            table_name="system_record_write_failures",
            columns=(
                "failure_id",
                "project_id",
                "domain_area",
                "operation_type",
                "safe_context",
                "error_type",
                "error_category",
                "created_at",
            ),
            required=(
                "failure_id",
                "operation_type",
                "error_type",
            ),
            record=record,
            conflict_columns=("failure_id",),
        )

    async def _insert(
        self,
        *,
        table_name: str,
        columns: Sequence[str],
        required: Sequence[str],
        record: Mapping[str, Any],
        conflict_columns: Sequence[str],
        idempotency_key: str | None = None,
        compare_columns: Sequence[str] | None = None,
    ) -> StorageWriteResult:
        _require_fields(record, required)
        values = tuple(
            _storage_value(table_name, column, record.get(column)) for column in columns
        )
        query = _build_insert_sql(
            table_name,
            columns,
            conflict_columns,
            compare_columns=compare_columns,
        )
        result = await self.executor.execute(query, *values)
        resolved_idempotency_key = idempotency_key
        if resolved_idempotency_key is None:
            resolved_idempotency_key = ":".join(
                str(record[column]) for column in conflict_columns
            )

        created = _created_from_execute_result(result)
        if created is False:
            raise ActivityStorageConflictError(
                f"Idempotency key conflict for {table_name}: {resolved_idempotency_key}"
            )

        return StorageWriteResult(
            table_name=table_name,
            idempotency_key=resolved_idempotency_key or table_name,
            created=created,
        )


def _build_insert_sql(
    table_name: str,
    columns: Sequence[str],
    conflict_columns: Sequence[str],
    *,
    compare_columns: Sequence[str] | None = None,
) -> str:
    column_sql = ", ".join(columns)
    placeholder_sql = ", ".join(f"${index}" for index in range(1, len(columns) + 1))
    conflict_column_sql = ", ".join(conflict_columns)
    resolved_compare_columns = compare_columns
    if resolved_compare_columns is None:
        resolved_compare_columns = [
            column for column in columns if column not in conflict_columns
        ]
    compare_sql = " AND ".join(
        f"{table_name}.{column} IS NOT DISTINCT FROM EXCLUDED.{column}"
        for column in resolved_compare_columns
    )
    first_conflict_column = conflict_columns[0]
    conflict_sql = f"ON CONFLICT ({conflict_column_sql}) DO UPDATE SET "
    conflict_sql += f"{first_conflict_column} = {table_name}.{first_conflict_column}"
    if compare_sql:
        conflict_sql += f" WHERE {compare_sql}"
    return f"INSERT INTO {table_name} ({column_sql}) VALUES ({placeholder_sql}) {conflict_sql};"


def _require_fields(record: Mapping[str, Any], fields: Sequence[str]) -> None:
    missing = [field for field in fields if record.get(field) is None]
    if missing:
        raise ActivityStorageError(
            f"Missing required activity storage fields: {', '.join(missing)}"
        )


def _storage_value(table_name: str, column: str, value: Any) -> Any:
    if value is None:
        return None
    if column not in JSONB_COLUMNS_BY_TABLE.get(table_name, frozenset()):
        return value
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, default=str)


def _created_from_execute_result(result: Any) -> bool | None:
    if not isinstance(result, str):
        return None
    parts = result.split()
    if len(parts) == 3 and parts[0].upper() == "INSERT":
        return parts[-1] != "0"
    return None


def _evidence_link_key(record: Mapping[str, Any]) -> str:
    return ":".join(
        str(record.get(key, ""))
        for key in ("activity_id", "evidence_type", "evidence_id")
    )
