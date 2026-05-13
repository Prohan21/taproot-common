"""Tests for legacy audit to TAP-38 activity compatibility."""

import asyncio
from collections.abc import Mapping
from typing import Any

import pytest

from taproot_common.activity import (
    ActivityRecorder,
    InteractionContext,
    InteractionType,
    StorageWriteResult,
    clear_activity_recorder,
    clear_interaction_context,
    set_activity_recorder,
    set_interaction_context,
)
from taproot_common.audit import (
    ActivityAuditPublisher,
    AuditPublisherNotConfigured,
    AuditEvent,
    InMemoryAuditPublisher,
    publish_audit_event,
    reset_audit_publisher,
    set_audit_publisher,
)


class FakeStorage:
    def __init__(self) -> None:
        self.activity_records: list[Mapping[str, Any]] = []
        self.dead_letters: list[Mapping[str, Any]] = []

    async def write_interaction_record(
        self, record: Mapping[str, Any]
    ) -> StorageWriteResult:
        return _stored("interaction_records", record, "interaction_id")

    async def write_activity_record(
        self, record: Mapping[str, Any]
    ) -> StorageWriteResult:
        self.activity_records.append(dict(record))
        return _stored("activity_records", record, "activity_id")

    async def write_snapshot(self, record: Mapping[str, Any]) -> StorageWriteResult:
        return _stored("activity_snapshots", record, "snapshot_id")

    async def write_diff(self, record: Mapping[str, Any]) -> StorageWriteResult:
        return _stored("activity_diffs", record, "diff_id")

    async def write_evidence_link(
        self, record: Mapping[str, Any]
    ) -> StorageWriteResult:
        return StorageWriteResult(
            table_name="activity_evidence_links",
            idempotency_key=f"{record['activity_id']}:{record['evidence_type']}:{record['evidence_id']}",
            created=True,
        )

    async def write_retention_policy(
        self, record: Mapping[str, Any]
    ) -> StorageWriteResult:
        return _stored("retention_policies", record, "retention_policy_id")

    async def write_retention_application(
        self, record: Mapping[str, Any]
    ) -> StorageWriteResult:
        return _stored("retention_applications", record, "application_id")

    async def write_purge_tombstone(
        self, record: Mapping[str, Any]
    ) -> StorageWriteResult:
        return _stored("purge_tombstones", record, "purge_tombstone_id")

    async def write_dead_letter(self, record: Mapping[str, Any]) -> StorageWriteResult:
        self.dead_letters.append(dict(record))
        return _stored("activity_dead_letters", record, "dead_letter_id")


def _stored(
    table_name: str,
    record: Mapping[str, Any],
    idempotency_column: str,
) -> StorageWriteResult:
    return StorageWriteResult(
        table_name=table_name,
        idempotency_key=str(record[idempotency_column]),
        created=True,
    )


@pytest.mark.asyncio
async def test_activity_audit_publisher_maps_legacy_event_to_activity():
    storage = FakeStorage()
    publisher = ActivityAuditPublisher(ActivityRecorder(storage))

    await publisher.publish(
        AuditEvent(
            service="prompt-s",
            action="UPDATE",
            entity_type="PROMPT",
            entity_id="prompt-1",
            performed_by="user-1",
            tenant_id="project-1",
            old_value={"label": "dev"},
            new_value={"label": "prod"},
            changed_fields=("label",),
            agent_id="agent-1",
            trace_id="trace-1",
            correlation_id="corr-1",
            metadata={"safe_summary": "label changed"},
            timestamp="2026-05-12T00:00:00+00:00",
        )
    )

    record = storage.activity_records[0]
    assert record["project_id"] == "project-1"
    assert record["domain_area"] == "prompt"
    assert record["target_type"] == "prompt"
    assert record["target_id"] == "prompt-1"
    assert record["action_family"] == "update"
    assert record["action"] == "update"
    assert record["durability"] == "async"
    assert record["event_label"] == "Update Prompt"
    assert record["metadata"]["legacy_changed_fields"] == ("label",)
    assert record["metadata"]["legacy_metadata"] == {"safe_summary": "label changed"}
    assert record["metadata"]["legacy_old_value_hash"].startswith("sha256:")
    assert record["metadata"]["legacy_new_value_hash"].startswith("sha256:")
    assert "old_value" not in record["metadata"]
    assert "new_value" not in record["metadata"]


@pytest.mark.asyncio
async def test_activity_audit_publisher_handles_missing_entity_id():
    storage = FakeStorage()
    publisher = ActivityAuditPublisher(ActivityRecorder(storage))

    await publisher.publish(
        AuditEvent(
            service="unknown-service",
            action="ENABLE_SUPPORT",
            entity_type="PROJECT",
            performed_by="support-1",
            tenant_id="project-1",
        )
    )

    record = storage.activity_records[0]
    assert record["domain_area"] == "common"
    assert record["target_id"] == "unknown"
    assert record["action_family"] == "access"
    assert record["metadata"]["legacy_performed_by"] == "support-1"


@pytest.mark.asyncio
async def test_activity_audit_publisher_sanitizes_legacy_metadata_raw_keys():
    storage = FakeStorage()
    publisher = ActivityAuditPublisher(ActivityRecorder(storage))

    await publisher.publish(
        AuditEvent(
            service="retrieval-s",
            action="ACCESS",
            entity_type="DOCUMENT",
            entity_id="doc-1",
            performed_by="user-1",
            tenant_id="project-1",
            metadata={
                "safe": "kept",
                "raw_payload": "removed",
                "content_preview": "removed",
                "nested": {
                    "checked_content": "removed",
                    "prompt": "removed",
                    "safe_nested": "kept",
                },
            },
        )
    )

    legacy_metadata = storage.activity_records[0]["metadata"]["legacy_metadata"]
    assert legacy_metadata == {"safe": "kept", "nested": {"safe_nested": "kept"}}


@pytest.mark.asyncio
async def test_activity_audit_publisher_uses_event_project_when_context_lacks_scope():
    storage = FakeStorage()
    publisher = ActivityAuditPublisher(ActivityRecorder(storage))
    set_interaction_context(
        InteractionContext(
            interaction_id="int-without-project",
            interaction_type=InteractionType.SERVICE_REQUEST,
        )
    )

    try:
        await publisher.publish(
            AuditEvent(
                service="prompt-s",
                action="UPDATE",
                entity_type="PROMPT",
                entity_id="prompt-1",
                performed_by="user-1",
                tenant_id="project-1",
            )
        )
    finally:
        clear_interaction_context()

    record = storage.activity_records[0]
    assert record["interaction_id"] == "int-without-project"
    assert record["project_id"] == "project-1"
    assert record["domain_area"] == "prompt"


@pytest.mark.asyncio
async def test_publish_audit_event_uses_activity_publisher_override():
    storage = FakeStorage()
    set_audit_publisher(ActivityAuditPublisher(ActivityRecorder(storage)))

    try:
        await publish_audit_event(
            service="toolbox-s",
            action="CREATE",
            entity_type="TOOL",
            entity_id="tool-1",
            performed_by="user-1",
            tenant_id="project-1",
            new_value={"name": "weather"},
        )
        await asyncio.sleep(0)
    finally:
        reset_audit_publisher()

    assert len(storage.activity_records) == 1
    assert storage.activity_records[0]["domain_area"] == "toolbox"
    assert storage.activity_records[0]["action_family"] == "create"


@pytest.mark.asyncio
async def test_publish_audit_event_uses_configured_activity_recorder_by_default():
    storage = FakeStorage()
    set_activity_recorder(ActivityRecorder(storage))

    try:
        await publish_audit_event(
            service="prompt-s",
            action="UPDATE",
            entity_type="PROMPT",
            entity_id="prompt-1",
            performed_by="user-1",
            tenant_id="project-1",
        )
        await asyncio.sleep(0)
    finally:
        clear_activity_recorder()
        reset_audit_publisher()

    assert len(storage.activity_records) == 1
    assert storage.activity_records[0]["domain_area"] == "prompt"
    assert storage.activity_records[0]["action_family"] == "update"


@pytest.mark.asyncio
async def test_publish_audit_event_fails_without_activity_recorder_or_explicit_publisher():
    clear_activity_recorder()
    reset_audit_publisher()

    with pytest.raises(AuditPublisherNotConfigured, match="fallback is disabled"):
        await publish_audit_event(
            service="retrieval-s",
            action="ACCESS",
            entity_type="DOCUMENT",
            entity_id="doc-1",
            performed_by="user-1",
            tenant_id="project-1",
        )


@pytest.mark.asyncio
async def test_explicit_audit_publisher_takes_precedence_over_activity_recorder():
    storage = FakeStorage()
    explicit_publisher = InMemoryAuditPublisher()
    set_activity_recorder(ActivityRecorder(storage))
    set_audit_publisher(explicit_publisher)

    try:
        await publish_audit_event(
            service="toolbox-s",
            action="CREATE",
            entity_type="TOOL",
            entity_id="tool-1",
            performed_by="user-1",
            tenant_id="project-1",
        )
        await asyncio.sleep(0)
    finally:
        clear_activity_recorder()
        reset_audit_publisher()

    assert len(explicit_publisher.events) == 1
    assert storage.activity_records == []
