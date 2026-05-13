"""Tests for TAP-38 activity recording APIs."""

import asyncio
from datetime import UTC, datetime
from typing import Any, Mapping

import pytest

from taproot_common.activity import (
    ActionFamily,
    ActivityPublishResult,
    ActivityRecorder,
    ActivityRecorderError,
    ActivityTaxonomy,
    ActorRef,
    DomainArea,
    Durability,
    EvidenceClass,
    InteractionContext,
    InteractionRecordResult,
    InteractionType,
    LifecyclePhase,
    Outcome,
    ReconstructionContent,
    StorageWriteResult,
    TargetRef,
    clear_activity_recorder,
    clear_interaction_context,
    get_activity_recorder,
    record_activity,
    record_critical_activity,
    set_activity_recorder,
    set_interaction_context,
)


class FakeStorage:
    def __init__(
        self,
        *,
        fail_activity_times: int = 0,
        fail_interaction_times: int = 0,
        fail_dead_letter: bool = False,
        activity_created: bool = True,
        activity_delay_seconds: float = 0.0,
    ) -> None:
        self.fail_activity_times = fail_activity_times
        self.fail_interaction_times = fail_interaction_times
        self.fail_dead_letter = fail_dead_letter
        self.activity_created = activity_created
        self.activity_delay_seconds = activity_delay_seconds
        self.interaction_attempts: list[Mapping[str, Any]] = []
        self.interaction_records: list[Mapping[str, Any]] = []
        self.activity_attempts: list[Mapping[str, Any]] = []
        self.activity_records: list[Mapping[str, Any]] = []
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
        if self.activity_delay_seconds:
            await asyncio.sleep(self.activity_delay_seconds)
        self.activity_attempts.append(dict(record))
        if len(self.activity_attempts) <= self.fail_activity_times:
            raise TimeoutError("activity db timeout")
        self.activity_records.append(dict(record))
        return _stored(
            "activity_records",
            record,
            "activity_id",
            created=self.activity_created,
        )

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
        if self.fail_dead_letter:
            raise RuntimeError("dead letter unavailable")
        self.dead_letters.append(dict(record))
        return _stored("activity_dead_letters", record, "dead_letter_id")


def _stored(
    table_name: str,
    record: Mapping[str, Any],
    idempotency_column: str,
    *,
    created: bool = True,
) -> StorageWriteResult:
    return StorageWriteResult(
        table_name=table_name,
        idempotency_key=str(record[idempotency_column]),
        created=created,
    )


def _taxonomy(*, durability: Durability = Durability.ASYNC) -> ActivityTaxonomy:
    return ActivityTaxonomy(
        domain_area=DomainArea.PROMPT,
        target_type="prompt",
        action_family=ActionFamily.UPDATE,
        action="assign_label",
        lifecycle_phase=LifecyclePhase.COMPLETED,
        outcome=Outcome.SUCCEEDED,
        durability=durability,
        event_label="Label Assigned",
        evidence_class=EvidenceClass.VERSIONED_RESOURCE,
    )


def _critical_taxonomy(
    *, action_family: ActionFamily = ActionFamily.CREATE
) -> ActivityTaxonomy:
    return ActivityTaxonomy(
        domain_area=DomainArea.PROMPT,
        target_type="prompt",
        action_family=action_family,
        action="create_prompt",
        lifecycle_phase=LifecyclePhase.COMPLETED,
        outcome=Outcome.SUCCEEDED,
        durability=Durability.CRITICAL,
        event_label="Prompt Created",
        evidence_class=EvidenceClass.VERSIONED_RESOURCE,
    )


def _reconstruction(
    *, metadata: Mapping[str, Any] | None = None
) -> ReconstructionContent:
    return ReconstructionContent(
        primary_target=TargetRef(target_type="prompt", target_id="prompt-1"),
        version_refs=("prompt-version-1",),
        metadata=metadata or {},
    )


def _interaction() -> InteractionContext:
    return InteractionContext(
        interaction_id="int-1",
        interaction_type=InteractionType.AGENT_RUN,
        project_id="project-1",
        domain_area=DomainArea.PROMPT,
        caller=ActorRef(actor_type="user", actor_id="user-1"),
        source_agent_id="agent-1",
        root_agent_id="root-agent-1",
        source_entry_point="front.chat",
        correlation_id="corr-1",
        trace_id="trace-1",
        retention_policy_id="ret-1",
        parent_activity_id="parent-act-1",
    )


@pytest.mark.asyncio
async def test_record_interaction_writes_interaction_record():
    storage = FakeStorage()
    recorder = ActivityRecorder(storage)

    result = await recorder.record_interaction(
        _interaction(), started_at=datetime(2026, 5, 12, tzinfo=UTC)
    )

    assert result == InteractionRecordResult(
        interaction_id="int-1",
        accepted=True,
        attempts=1,
        storage_result=StorageWriteResult(
            table_name="interaction_records", idempotency_key="int-1", created=True
        ),
    )
    record = storage.interaction_records[0]
    assert record["interaction_id"] == "int-1"
    assert record["interaction_type"] == "agent_run"
    assert record["project_id"] == "project-1"
    assert record["domain_area"] == "prompt"
    assert record["caller_summary"] == {"actor_type": "user", "actor_id": "user-1"}
    assert record["default_actor_chain"]["caller"] == {
        "actor_type": "user",
        "actor_id": "user-1",
    }
    assert record["collapse_metadata"]["correlation_id"] == "corr-1"
    assert record["collapse_metadata"]["trace_id"] == "trace-1"


@pytest.mark.asyncio
async def test_record_interaction_retries_then_dead_letters_on_failure():
    storage = FakeStorage(fail_interaction_times=2)
    recorder = ActivityRecorder(storage, max_attempts=2)

    result = await recorder.record_interaction(_interaction())

    assert result.accepted is False
    assert result.dead_lettered is True
    assert result.error_type == "TimeoutError"
    assert len(storage.interaction_attempts) == 2
    assert storage.dead_letters[0]["operation_type"] == "interaction_record"
    assert storage.dead_letters[0]["payload"]["interaction_id"] == "int-1"


@pytest.mark.asyncio
async def test_record_interaction_dead_letter_failure_does_not_raise():
    storage = FakeStorage(fail_interaction_times=1, fail_dead_letter=True)
    recorder = ActivityRecorder(storage, max_attempts=1)

    result = await recorder.record_interaction(_interaction())

    assert result.accepted is False
    assert result.dead_lettered is False
    assert result.error_type == "TimeoutError"


@pytest.mark.asyncio
async def test_record_activity_enriches_from_current_interaction_context():
    storage = FakeStorage()
    recorder = ActivityRecorder(storage)
    token = set_interaction_context(_interaction())

    try:
        result = await recorder.record_activity(
            taxonomy=_taxonomy(),
            reconstruction=_reconstruction(metadata={"safe_summary": "label prod"}),
            activity_id="act-1",
            occurred_at=datetime(2026, 5, 12, tzinfo=UTC),
        )
    finally:
        clear_interaction_context()

    record = storage.activity_records[0]
    assert result == ActivityPublishResult(
        activity_id="act-1",
        durability=Durability.ASYNC,
        accepted=True,
        attempts=1,
        storage_result=StorageWriteResult(
            table_name="activity_records", idempotency_key="act-1", created=True
        ),
    )
    assert token is not None
    assert record["interaction_id"] == "int-1"
    assert record["parent_activity_id"] == "parent-act-1"
    assert record["project_id"] == "project-1"
    assert record["retention_policy_id"] == "ret-1"
    assert record["metadata"]["correlation_id"] == "corr-1"
    assert record["metadata"]["trace_id"] == "trace-1"
    assert record["metadata"]["safe_summary"] == "label prod"


@pytest.mark.asyncio
async def test_record_critical_activity_awaits_storage_acceptance():
    storage = FakeStorage()
    recorder = ActivityRecorder(storage)

    result = await recorder.record_critical_activity(
        taxonomy=_critical_taxonomy(),
        reconstruction=_reconstruction(),
        interaction=_interaction(),
        activity_id="act-critical-1",
    )

    assert result.accepted is True
    assert result.durability == Durability.CRITICAL
    assert result.attempts == 1
    assert storage.activity_records[0]["durability"] == "critical"


@pytest.mark.asyncio
async def test_record_critical_activity_rejects_non_critical_action_family():
    recorder = ActivityRecorder(FakeStorage())

    with pytest.raises(
        ActivityRecorderError, match="Unsupported critical action family"
    ):
        await recorder.record_critical_activity(
            taxonomy=_critical_taxonomy(action_family=ActionFamily.QUERY),
            reconstruction=_reconstruction(),
            interaction=_interaction(),
        )


@pytest.mark.asyncio
async def test_record_activity_retries_then_dead_letters_on_failure():
    storage = FakeStorage(fail_activity_times=2)
    recorder = ActivityRecorder(storage, max_attempts=2)

    result = await recorder.record_activity(
        taxonomy=_taxonomy(),
        reconstruction=_reconstruction(),
        interaction=_interaction(),
        activity_id="act-failure-1",
    )

    assert result.accepted is False
    assert result.dead_lettered is True
    assert result.error_type == "TimeoutError"
    assert len(storage.activity_attempts) == 2
    assert storage.dead_letters[0]["operation_type"] == "activity_record"
    assert storage.dead_letters[0]["payload"]["activity_id"] == "act-failure-1"
    assert storage.dead_letters[0]["attempt_count"] == 2


@pytest.mark.asyncio
async def test_record_activity_surfaces_idempotent_duplicate_result():
    storage = FakeStorage(activity_created=False)
    recorder = ActivityRecorder(storage)

    result = await recorder.record_activity(
        taxonomy=_taxonomy(),
        reconstruction=_reconstruction(),
        interaction=_interaction(),
        activity_id="act-duplicate-1",
    )

    assert result.accepted is True
    assert result.storage_result == StorageWriteResult(
        table_name="activity_records",
        idempotency_key="act-duplicate-1",
        created=False,
    )


@pytest.mark.asyncio
async def test_record_activity_timeout_dead_letters_failure():
    storage = FakeStorage(activity_delay_seconds=0.05)
    recorder = ActivityRecorder(storage, max_attempts=1, write_timeout_seconds=0.001)

    result = await recorder.record_activity(
        taxonomy=_taxonomy(),
        reconstruction=_reconstruction(),
        interaction=_interaction(),
        activity_id="act-timeout-1",
    )

    assert result.accepted is False
    assert result.dead_lettered is True
    assert result.error_type == "TimeoutError"
    assert storage.dead_letters[0]["operation_type"] == "activity_record"


@pytest.mark.asyncio
async def test_record_critical_activity_raises_on_storage_failure():
    storage = FakeStorage(fail_activity_times=1)
    recorder = ActivityRecorder(storage)

    with pytest.raises(TimeoutError, match="activity db timeout"):
        await recorder.record_critical_activity(
            taxonomy=_critical_taxonomy(),
            reconstruction=_reconstruction(),
            interaction=_interaction(),
        )

    assert storage.dead_letters == []


@pytest.mark.asyncio
async def test_record_activity_rejects_raw_payload_fields_by_default():
    storage = FakeStorage()
    recorder = ActivityRecorder(storage)

    with pytest.raises(ActivityRecorderError, match="Raw payload fields"):
        await recorder.record_activity(
            taxonomy=_taxonomy(),
            reconstruction=_reconstruction(
                metadata={"raw_payload": {"secret": "value"}}
            ),
            interaction=_interaction(),
        )

    assert storage.activity_records == []


@pytest.mark.asyncio
@pytest.mark.parametrize("raw_key", ["content_preview", "checked_content"])
async def test_record_activity_rejects_sensitive_payload_aliases(raw_key: str):
    storage = FakeStorage()
    recorder = ActivityRecorder(storage)

    with pytest.raises(ActivityRecorderError, match="Raw payload fields"):
        await recorder.record_activity(
            taxonomy=_taxonomy(),
            reconstruction=_reconstruction(metadata={"safe": {raw_key: "secret"}}),
            interaction=_interaction(),
        )

    assert storage.activity_records == []


@pytest.mark.asyncio
async def test_module_functions_use_configured_recorder():
    storage = FakeStorage()
    recorder = ActivityRecorder(storage)
    set_activity_recorder(recorder)

    try:
        assert get_activity_recorder() is recorder
        async_result = await record_activity(
            taxonomy=_taxonomy(),
            reconstruction=_reconstruction(),
            interaction=_interaction(),
            activity_id="act-module-1",
        )
        critical_result = await record_critical_activity(
            taxonomy=_critical_taxonomy(),
            reconstruction=_reconstruction(),
            interaction=_interaction(),
            activity_id="act-module-2",
        )
    finally:
        clear_activity_recorder()

    assert get_activity_recorder() is None

    assert async_result.activity_id == "act-module-1"
    assert critical_result.activity_id == "act-module-2"
    assert [record["activity_id"] for record in storage.activity_records] == [
        "act-module-1",
        "act-module-2",
    ]


@pytest.mark.asyncio
async def test_module_function_requires_configured_recorder():
    clear_activity_recorder()

    with pytest.raises(ActivityRecorderError, match="No activity recorder configured"):
        await record_activity(
            taxonomy=_taxonomy(),
            reconstruction=_reconstruction(),
            interaction=_interaction(),
        )
