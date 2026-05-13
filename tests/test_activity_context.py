"""Tests for TAP-38 interaction context propagation helpers."""

from typing import Any, Mapping
from uuid import UUID

import pytest

from taproot_common.activity import (
    HEADER_ACTIVITY_VERSION,
    HEADER_CALLER_ID,
    HEADER_CALLER_TYPE,
    HEADER_CORRELATION_ID,
    HEADER_INTERACTION_ID,
    HEADER_INTERACTION_TYPE,
    HEADER_PARENT_ACTIVITY_ID,
    HEADER_ROOT_AGENT_ID,
    HEADER_SOURCE_AGENT_ID,
    HEADER_TRACEPARENT,
    ACTIVITY_HEADER_VERSION,
    ActorRef,
    ActivityRecorder,
    DomainArea,
    InteractionContext,
    InteractionType,
    StorageWriteResult,
    clear_activity_recorder,
    bind_interaction_context_from_headers,
    clear_interaction_context,
    create_interaction_id,
    ensure_interaction_context,
    get_interaction_context,
    set_activity_recorder,
    interaction_context_from_headers,
    merge_propagation_headers,
    propagation_headers,
    reset_interaction_context,
    set_interaction_context,
)


class FakeStorage:
    def __init__(self, *, fail_interaction_times: int = 0) -> None:
        self.fail_interaction_times = fail_interaction_times
        self.interaction_attempts: list[Mapping[str, Any]] = []
        self.interaction_records: list[Mapping[str, Any]] = []
        self.dead_letters: list[Mapping[str, Any]] = []

    async def write_interaction_record(
        self, record: Mapping[str, Any]
    ) -> StorageWriteResult:
        self.interaction_attempts.append(dict(record))
        if len(self.interaction_attempts) <= self.fail_interaction_times:
            raise TimeoutError("interaction db timeout")
        self.interaction_records.append(dict(record))
        return _stored("interaction_records", record, "interaction_id")

    async def write_activity_record(
        self, record: Mapping[str, Any]
    ) -> StorageWriteResult:
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


def test_create_interaction_id_returns_uuid_string():
    first = create_interaction_id()
    second = create_interaction_id()

    assert UUID(first)
    assert UUID(second)
    assert first != second


@pytest.mark.asyncio
async def test_ensure_interaction_context_creates_and_binds_context():
    context = await ensure_interaction_context(
        interaction_type=InteractionType.AGENT_RUN,
        interaction_id="int-1",
        project_id="project-1",
        domain_area=DomainArea.FRONT,
        caller=ActorRef("user", "user-1"),
        source_agent_id="agent-1",
        correlation_id="corr-1",
    )

    try:
        assert context.interaction_id == "int-1"
        assert get_interaction_context() == context

        reused = await ensure_interaction_context(
            interaction_type=InteractionType.SERVICE_REQUEST,
            interaction_id="ignored",
        )
        assert reused == context
    finally:
        clear_interaction_context()


@pytest.mark.asyncio
async def test_ensure_interaction_context_records_new_context_with_explicit_recorder():
    storage = FakeStorage()
    recorder = ActivityRecorder(storage)

    try:
        context = await ensure_interaction_context(
            interaction_type=InteractionType.AGENT_RUN,
            interaction_id="int-explicit",
            project_id="project-1",
            domain_area=DomainArea.FRONT,
            caller=ActorRef("user", "user-1"),
            recorder=recorder,
        )
    finally:
        clear_interaction_context()

    assert context.interaction_id == "int-explicit"
    assert storage.interaction_records[0]["interaction_id"] == "int-explicit"
    assert storage.interaction_records[0]["caller_summary"] == {
        "actor_type": "user",
        "actor_id": "user-1",
    }


@pytest.mark.asyncio
async def test_ensure_interaction_context_uses_configured_default_recorder():
    storage = FakeStorage()
    set_activity_recorder(ActivityRecorder(storage))

    try:
        await ensure_interaction_context(
            interaction_type=InteractionType.BACKGROUND_JOB,
            interaction_id="int-default",
        )
    finally:
        clear_interaction_context()
        clear_activity_recorder()

    assert storage.interaction_records[0]["interaction_id"] == "int-default"
    assert storage.interaction_records[0]["interaction_type"] == "background_job"


@pytest.mark.asyncio
async def test_ensure_interaction_context_without_recorder_preserves_existing_behavior():
    clear_activity_recorder()

    try:
        context = await ensure_interaction_context(
            interaction_type=InteractionType.WEBHOOK,
            interaction_id="int-no-recorder",
        )
    finally:
        clear_interaction_context()

    assert context.interaction_id == "int-no-recorder"


@pytest.mark.asyncio
async def test_ensure_interaction_context_dead_letters_failure_without_failing_creation():
    storage = FakeStorage(fail_interaction_times=1)
    recorder = ActivityRecorder(storage, max_attempts=1)

    try:
        context = await ensure_interaction_context(
            interaction_type=InteractionType.SERVICE_REQUEST,
            interaction_id="int-dead-letter",
            recorder=recorder,
        )
    finally:
        clear_interaction_context()

    assert context.interaction_id == "int-dead-letter"
    assert storage.interaction_records == []
    assert storage.dead_letters[0]["operation_type"] == "interaction_record"
    assert storage.dead_letters[0]["payload"]["interaction_id"] == "int-dead-letter"


@pytest.mark.asyncio
async def test_ensure_interaction_context_reuses_existing_context_without_duplicate_record():
    storage = FakeStorage()
    recorder = ActivityRecorder(storage)

    try:
        first = await ensure_interaction_context(
            interaction_type=InteractionType.SERVICE_REQUEST,
            interaction_id="int-reused",
            recorder=recorder,
        )
        second = await ensure_interaction_context(
            interaction_type=InteractionType.AGENT_RUN,
            interaction_id="ignored",
            recorder=recorder,
        )
    finally:
        clear_interaction_context()

    assert second == first
    assert len(storage.interaction_records) == 1


def test_set_and_reset_interaction_context():
    context = InteractionContext("int-1", InteractionType.SERVICE_REQUEST)
    token = set_interaction_context(context)

    assert get_interaction_context() == context

    reset_interaction_context(token)
    assert get_interaction_context() is None


def test_interaction_context_from_headers_is_case_insensitive():
    context = interaction_context_from_headers(
        {
            "x-taproot-interaction-id": "int-1",
            "x-taproot-interaction-type": "agent_run",
            "x-taproot-caller-id": "user-1",
            "x-taproot-caller-type": "user",
            "x-taproot-source-agent-id": "agent-1",
            "x-taproot-root-agent-id": "root-agent",
            "x-taproot-parent-activity-id": "act-parent",
            "x-correlation-id": "corr-1",
            "traceparent": "00-trace-span-01",
        },
        project_id="project-1",
        domain_area=DomainArea.FRONT,
        source_entry_point="front.agent.execute",
    )

    assert context == InteractionContext(
        interaction_id="int-1",
        interaction_type=InteractionType.AGENT_RUN,
        project_id="project-1",
        domain_area=DomainArea.FRONT,
        caller=ActorRef("user", "user-1"),
        source_agent_id="agent-1",
        root_agent_id="root-agent",
        source_entry_point="front.agent.execute",
        correlation_id="corr-1",
        trace_id="00-trace-span-01",
        parent_activity_id="act-parent",
    )


def test_interaction_context_from_headers_generates_missing_identity():
    context = interaction_context_from_headers(
        {}, default_interaction_type=InteractionType.BACKGROUND_JOB
    )

    assert UUID(context.interaction_id)
    assert context.interaction_type is InteractionType.BACKGROUND_JOB


def test_bind_interaction_context_from_headers_returns_resettable_token():
    context, token = bind_interaction_context_from_headers(
        {HEADER_INTERACTION_ID: "int-1", HEADER_INTERACTION_TYPE: "service_request"}
    )

    assert get_interaction_context() == context

    reset_interaction_context(token)
    assert get_interaction_context() is None


def test_propagation_headers_include_context_fields():
    headers = propagation_headers(
        InteractionContext(
            interaction_id="int-1",
            interaction_type=InteractionType.AGENT_RUN,
            caller=ActorRef("user", "user-1"),
            source_agent_id="agent-1",
            root_agent_id="root-agent",
            correlation_id="corr-1",
            trace_id="00-trace-span-01",
            parent_activity_id="act-parent",
        )
    )

    assert headers == {
        HEADER_ACTIVITY_VERSION: str(ACTIVITY_HEADER_VERSION),
        HEADER_INTERACTION_ID: "int-1",
        HEADER_INTERACTION_TYPE: "agent_run",
        HEADER_CALLER_ID: "user-1",
        HEADER_CALLER_TYPE: "user",
        HEADER_SOURCE_AGENT_ID: "agent-1",
        HEADER_ROOT_AGENT_ID: "root-agent",
        HEADER_PARENT_ACTIVITY_ID: "act-parent",
        HEADER_CORRELATION_ID: "corr-1",
        HEADER_TRACEPARENT: "00-trace-span-01",
    }


def test_merge_propagation_headers_preserves_explicit_values_by_default():
    context = InteractionContext(
        interaction_id="int-new",
        interaction_type=InteractionType.AGENT_RUN,
        correlation_id="corr-new",
    )

    merged = merge_propagation_headers(
        {"x-taproot-interaction-id": "int-existing", "Authorization": "Bearer token"},
        context=context,
    )

    assert merged["x-taproot-interaction-id"] == "int-existing"
    assert merged["Authorization"] == "Bearer token"
    assert merged[HEADER_INTERACTION_TYPE] == "agent_run"
    assert merged[HEADER_CORRELATION_ID] == "corr-new"


def test_merge_propagation_headers_can_overwrite_existing_values():
    context = InteractionContext("int-new", InteractionType.SDK_OPERATION)

    merged = merge_propagation_headers(
        {HEADER_INTERACTION_ID: "int-old"}, context=context, overwrite=True
    )

    assert merged[HEADER_INTERACTION_ID] == "int-new"
