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
    "activity_dead_letters": frozenset({"payload"}),
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

    async def write_dead_letter(
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
            idempotency_column="interaction_id",
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
            idempotency_column="activity_id",
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
            idempotency_column="snapshot_id",
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
            idempotency_column="diff_id",
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
            idempotency_column=None,
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
            idempotency_column="retention_policy_id",
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
            idempotency_column="application_id",
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
            idempotency_column="purge_tombstone_id",
        )

    async def write_dead_letter(self, record: Mapping[str, Any]) -> StorageWriteResult:
        return await self._insert(
            table_name="activity_dead_letters",
            columns=(
                "dead_letter_id",
                "project_id",
                "domain_area",
                "operation_type",
                "payload",
                "error_type",
                "error_message",
                "attempt_count",
                "status",
                "next_retry_at",
            ),
            required=(
                "dead_letter_id",
                "operation_type",
                "payload",
                "error_type",
                "status",
            ),
            record=record,
            idempotency_column="dead_letter_id",
        )

    async def _insert(
        self,
        *,
        table_name: str,
        columns: Sequence[str],
        required: Sequence[str],
        record: Mapping[str, Any],
        idempotency_column: str | None,
        idempotency_key: str | None = None,
    ) -> StorageWriteResult:
        _require_fields(record, required)
        values = tuple(
            _storage_value(table_name, column, record.get(column)) for column in columns
        )
        query = _build_insert_sql(table_name, columns, idempotency_column)
        result = await self.executor.execute(query, *values)
        resolved_idempotency_key = idempotency_key
        if resolved_idempotency_key is None and idempotency_column is not None:
            resolved_idempotency_key = str(record[idempotency_column])

        return StorageWriteResult(
            table_name=table_name,
            idempotency_key=resolved_idempotency_key or table_name,
            created=_created_from_execute_result(result),
        )


def _build_insert_sql(
    table_name: str, columns: Sequence[str], idempotency_column: str | None
) -> str:
    column_sql = ", ".join(columns)
    placeholder_sql = ", ".join(f"${index}" for index in range(1, len(columns) + 1))
    conflict_sql = (
        f"ON CONFLICT ({idempotency_column}) DO NOTHING"
        if idempotency_column
        else "ON CONFLICT DO NOTHING"
    )
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
