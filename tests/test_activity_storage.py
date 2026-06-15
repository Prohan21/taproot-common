"""Tests for TAP-38 activity storage Adapters."""

import json
from datetime import datetime, timezone
from typing import Any

import pytest

from taproot_common.activity import (
    ActivityStorageConflictError,
    ActivityStorageError,
    PostgresActivityStorageAdapter,
    StorageWriteResult,
)


class FakeExecutor:
    def __init__(self, result: str = "INSERT 0 1") -> None:
        self.result = result
        self.calls: list[tuple[str, tuple[Any, ...]]] = []

    async def execute(self, query: str, *args: Any) -> str:
        self.calls.append((query, args))
        return self.result


@pytest.mark.asyncio
async def test_write_interaction_record_inserts_idempotently():
    executor = FakeExecutor()
    adapter = PostgresActivityStorageAdapter(executor)

    result = await adapter.write_interaction_record(
        {
            "interaction_id": "int-1",
            "interaction_type": "agent_run",
            "project_id": "project-1",
            "domain_area": "front",
            "started_at": datetime(2026, 5, 12, tzinfo=timezone.utc),
        }
    )

    query, args = executor.calls[0]
    assert "INSERT INTO interaction_records" in query
    assert "ON CONFLICT (interaction_id) DO UPDATE" in query
    assert (
        "interaction_records.interaction_type IS NOT DISTINCT FROM EXCLUDED.interaction_type"
        in query
    )
    assert args[0] == "int-1"
    assert result == StorageWriteResult(
        table_name="interaction_records", idempotency_key="int-1", created=True
    )


@pytest.mark.asyncio
async def test_write_activity_record_includes_required_timeline_fields():
    executor = FakeExecutor()
    adapter = PostgresActivityStorageAdapter(executor)

    result = await adapter.write_activity_record(
        {
            "activity_id": "act-1",
            "interaction_id": "int-1",
            "project_id": "project-1",
            "domain_area": "prompt",
            "target_type": "prompt",
            "target_id": "prompt-1",
            "action_family": "update",
            "action": "assign_label",
            "lifecycle_phase": "completed",
            "outcome": "succeeded",
            "durability": "critical",
            "event_label": "Label Assigned",
            "primary_target": {"target_type": "prompt", "target_id": "prompt-1"},
            "occurred_at": datetime(2026, 5, 12, tzinfo=timezone.utc),
        }
    )

    query, args = executor.calls[0]
    assert "INSERT INTO activity_records" in query
    assert "ON CONFLICT (activity_id) DO UPDATE" in query
    assert "activity_records.action IS NOT DISTINCT FROM EXCLUDED.action" in query
    assert "primary_target" in query
    assert args[0] == "act-1"
    assert result.created is True


@pytest.mark.asyncio
async def test_conflicting_duplicate_payload_raises_storage_conflict():
    executor = FakeExecutor("INSERT 0 0")
    adapter = PostgresActivityStorageAdapter(executor)

    with pytest.raises(ActivityStorageConflictError, match="activity_records: act-1"):
        await adapter.write_activity_record(
            {
                "activity_id": "act-1",
                "domain_area": "prompt",
                "target_type": "prompt",
                "target_id": "prompt-1",
                "action_family": "update",
                "action": "assign_label",
                "lifecycle_phase": "completed",
                "outcome": "succeeded",
                "durability": "critical",
                "event_label": "Label Assigned",
                "primary_target": {"target_type": "prompt", "target_id": "prompt-1"},
                "occurred_at": datetime(2026, 5, 12, tzinfo=timezone.utc),
            }
        )


@pytest.mark.asyncio
async def test_missing_required_field_raises_before_db_call():
    executor = FakeExecutor()
    adapter = PostgresActivityStorageAdapter(executor)

    with pytest.raises(ActivityStorageError, match="activity_id"):
        await adapter.write_activity_record(
            {
                "domain_area": "prompt",
                "target_type": "prompt",
                "target_id": "prompt-1",
                "action_family": "update",
                "action": "assign_label",
                "lifecycle_phase": "completed",
                "outcome": "succeeded",
                "durability": "critical",
                "event_label": "Label Assigned",
                "primary_target": {"target_type": "prompt", "target_id": "prompt-1"},
                "occurred_at": datetime(2026, 5, 12, tzinfo=timezone.utc),
            }
        )

    assert executor.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method_name", "record", "expected_table"),
    (
        (
            "write_snapshot",
            {
                "snapshot_id": "snap-1",
                "activity_id": "act-1",
                "domain_area": "prompt",
                "target_type": "prompt",
                "target_id": "prompt-1",
                "snapshot_kind": "label_assignment",
                "snapshot_payload": {"label": "prod"},
                "payload_hash": "sha256:abc",
            },
            "activity_snapshots",
        ),
        (
            "write_diff",
            {
                "diff_id": "diff-1",
                "activity_id": "act-1",
                "domain_area": "prompt",
                "target_type": "prompt",
                "target_id": "prompt-1",
                "diff_payload": {"before": {}, "after": {}},
                "payload_hash": "sha256:def",
            },
            "activity_diffs",
        ),
        (
            "write_retention_policy",
            {
                "retention_policy_id": "ret-1",
                "domain_area": "prompt",
                "policy_name": "default",
            },
            "retention_policies",
        ),
        (
            "write_retention_application",
            {
                "application_id": "app-1",
                "retention_policy_id": "ret-1",
                "domain_area": "prompt",
                "target_type": "prompt",
                "target_id": "prompt-1",
                "action_taken": "expired",
                "applied_at": datetime(2026, 5, 12, tzinfo=timezone.utc),
            },
            "retention_applications",
        ),
        (
            "write_purge_tombstone",
            {
                "purge_tombstone_id": "purge-1",
                "activity_id": "act-1",
                "domain_area": "prompt",
                "target_type": "prompt",
                "target_id": "prompt-1",
                "purge_reason": "retention_expired",
                "purge_scope": "evidence",
                "purged_at": datetime(2026, 5, 12, tzinfo=timezone.utc),
            },
            "purge_tombstones",
        ),
        (
            "write_system_record_write_failure",
            {
                "failure_id": "failure-1",
                "operation_type": "activity_record",
                "safe_context": {"activity_id": "act-1"},
                "error_type": "TimeoutError",
                "error_category": "timeout",
            },
            "system_record_write_failures",
        ),
    ),
)
async def test_storage_methods_insert_expected_tables(
    method_name: str, record: dict[str, Any], expected_table: str
):
    executor = FakeExecutor()
    adapter = PostgresActivityStorageAdapter(executor)

    method = getattr(adapter, method_name)
    result = await method(record)

    assert f"INSERT INTO {expected_table}" in executor.calls[0][0]
    assert result.table_name == expected_table


@pytest.mark.asyncio
async def test_evidence_link_uses_composite_idempotency_key():
    executor = FakeExecutor()
    adapter = PostgresActivityStorageAdapter(executor)

    result = await adapter.write_evidence_link(
        {
            "activity_id": "act-1",
            "domain_area": "retrieval",
            "evidence_type": "chunk",
            "evidence_id": "chunk-1",
            "evidence_ref": {"rank": 1},
        }
    )

    query, _ = executor.calls[0]
    assert "INSERT INTO activity_evidence_links" in query
    assert "ON CONFLICT (activity_id, evidence_type, evidence_id) DO UPDATE" in query
    assert (
        "activity_evidence_links.evidence_ref IS NOT DISTINCT FROM EXCLUDED.evidence_ref"
        in query
    )
    assert result.idempotency_key == "act-1:chunk:chunk-1"


@pytest.mark.asyncio
async def test_activity_record_serializes_jsonb_columns_for_postgres():
    executor = FakeExecutor()
    adapter = PostgresActivityStorageAdapter(executor)

    await adapter.write_activity_record(
        {
            "activity_id": "act-1",
            "domain_area": "prompt",
            "target_type": "prompt",
            "target_id": "prompt-1",
            "action_family": "update",
            "action": "assign_label",
            "lifecycle_phase": "completed",
            "outcome": "succeeded",
            "durability": "critical",
            "event_label": "Label Assigned",
            "primary_target": {"target_type": "prompt", "target_id": "prompt-1"},
            "related_targets": [
                {
                    "role": "label",
                    "target": {"target_type": "label", "target_id": "prod"},
                }
            ],
            "metadata": {"safe_summary": "label prod"},
            "occurred_at": datetime(2026, 5, 12, tzinfo=timezone.utc),
        }
    )

    _, args = executor.calls[0]
    assert json.loads(args[14]) == {"target_id": "prompt-1", "target_type": "prompt"}
    assert json.loads(args[15]) == [
        {"role": "label", "target": {"target_id": "prod", "target_type": "label"}}
    ]
    assert json.loads(args[18]) == {"safe_summary": "label prod"}


@pytest.mark.asyncio
async def test_interaction_record_serializes_jsonb_columns_for_postgres():
    executor = FakeExecutor()
    adapter = PostgresActivityStorageAdapter(executor)

    await adapter.write_interaction_record(
        {
            "interaction_id": "int-1",
            "interaction_type": "agent_run",
            "caller_summary": {"actor_type": "user", "actor_id": "user-1"},
            "default_actor_chain": {"caller": {"actor_id": "user-1"}},
            "collapse_metadata": {"correlation_id": "corr-1"},
            "started_at": datetime(2026, 5, 12, tzinfo=timezone.utc),
        }
    )

    _, args = executor.calls[0]
    assert json.loads(args[4]) == {"actor_id": "user-1", "actor_type": "user"}
    assert json.loads(args[5]) == {"caller": {"actor_id": "user-1"}}
    assert json.loads(args[9]) == {"correlation_id": "corr-1"}


@pytest.mark.asyncio
async def test_non_jsonb_array_column_remains_native_list():
    executor = FakeExecutor()
    adapter = PostgresActivityStorageAdapter(executor)

    await adapter.write_purge_tombstone(
        {
            "purge_tombstone_id": "purge-1",
            "activity_id": "act-1",
            "domain_area": "prompt",
            "target_type": "prompt",
            "target_id": "prompt-1",
            "purge_reason": "retention_expired",
            "purge_scope": "evidence",
            "initiated_by": {"actor_type": "system", "actor_id": "retention"},
            "purged_evidence_classes": ["snapshot", "diff"],
            "purged_at": datetime(2026, 5, 12, tzinfo=timezone.utc),
        }
    )

    _, args = executor.calls[0]
    assert json.loads(args[8]) == {"actor_id": "retention", "actor_type": "system"}
    assert args[10] == ["snapshot", "diff"]
    assert args[11] == datetime(2026, 5, 12, tzinfo=timezone.utc)


@pytest.mark.asyncio
async def test_system_record_write_failure_safe_context_serializes_for_jsonb():
    executor = FakeExecutor()
    adapter = PostgresActivityStorageAdapter(executor)

    await adapter.write_system_record_write_failure(
        {
            "failure_id": "failure-1",
            "operation_type": "activity_record",
            "safe_context": {"activity_id": "act-1", "error": {"type": "timeout"}},
            "error_type": "TimeoutError",
            "error_category": "timeout",
        }
    )

    _, args = executor.calls[0]
    assert json.loads(args[4]) == {
        "activity_id": "act-1",
        "error": {"type": "timeout"},
    }
