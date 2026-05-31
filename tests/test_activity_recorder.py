"""Tests for TAP-38 activity recording APIs."""

import asyncio
import logging
from dataclasses import replace
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
    DiffRecordInput,
    DomainArea,
    Durability,
    EvidenceClass,
    EvidenceRef,
    InteractionContext,
    InteractionRecordResult,
    InteractionType,
    LifecyclePhase,
    Outcome,
    ProjectIsolationError,
    ReconstructionContent,
    RecordScope,
    SnapshotRecordInput,
    StorageWriteResult,
    TargetRef,
    clear_activity_recorder,
    clear_interaction_context,
    get_activity_recorder,
    record_activity,
    record_critical_activity,
    record_diff,
    record_snapshot,
    set_activity_recorder,
    set_interaction_context,
)


class FakeStorage:
    def __init__(
        self,
        *,
        fail_activity_times: int = 0,
        fail_evidence_times: int = 0,
        fail_interaction_times: int = 0,
        fail_snapshot_times: int = 0,
        fail_diff_times: int = 0,
        fail_dead_letter: bool = False,
        fail_activity_message: str = "activity db timeout",
        fail_interaction_message: str = "interaction db timeout",
        fail_dead_letter_message: str = "dead letter unavailable",
        activity_created: bool = True,
        activity_delay_seconds: float = 0.0,
    ) -> None:
        self.fail_activity_times = fail_activity_times
        self.fail_evidence_times = fail_evidence_times
        self.fail_interaction_times = fail_interaction_times
        self.fail_snapshot_times = fail_snapshot_times
        self.fail_diff_times = fail_diff_times
        self.fail_dead_letter = fail_dead_letter
        self.fail_activity_message = fail_activity_message
        self.fail_interaction_message = fail_interaction_message
        self.fail_dead_letter_message = fail_dead_letter_message
        self.activity_created = activity_created
        self.activity_delay_seconds = activity_delay_seconds
        self.interaction_attempts: list[Mapping[str, Any]] = []
        self.interaction_records: list[Mapping[str, Any]] = []
        self.activity_attempts: list[Mapping[str, Any]] = []
        self.activity_records: list[Mapping[str, Any]] = []
        self.snapshot_records: list[Mapping[str, Any]] = []
        self.snapshot_attempts: list[Mapping[str, Any]] = []
        self.diff_records: list[Mapping[str, Any]] = []
        self.diff_attempts: list[Mapping[str, Any]] = []
        self.evidence_links: list[Mapping[str, Any]] = []
        self.evidence_attempts: list[Mapping[str, Any]] = []
        self.dead_letters: list[Mapping[str, Any]] = []

    async def write_interaction_record(
        self, record: Mapping[str, Any]
    ) -> StorageWriteResult:
        self.interaction_attempts.append(dict(record))
        if len(self.interaction_attempts) <= self.fail_interaction_times:
            raise TimeoutError(self.fail_interaction_message)
        self.interaction_records.append(dict(record))
        return _stored("interaction_records", record, "interaction_id")

    async def write_activity_record(
        self, record: Mapping[str, Any]
    ) -> StorageWriteResult:
        if self.activity_delay_seconds:
            await asyncio.sleep(self.activity_delay_seconds)
        self.activity_attempts.append(dict(record))
        if len(self.activity_attempts) <= self.fail_activity_times:
            raise TimeoutError(self.fail_activity_message)
        self.activity_records.append(dict(record))
        return _stored(
            "activity_records",
            record,
            "activity_id",
            created=self.activity_created,
        )

    async def write_snapshot(self, record: Mapping[str, Any]) -> StorageWriteResult:
        self.snapshot_attempts.append(dict(record))
        if len(self.snapshot_attempts) <= self.fail_snapshot_times:
            raise TimeoutError("snapshot db timeout")
        self.snapshot_records.append(dict(record))
        return _stored("activity_snapshots", record, "snapshot_id")

    async def write_diff(self, record: Mapping[str, Any]) -> StorageWriteResult:
        self.diff_attempts.append(dict(record))
        if len(self.diff_attempts) <= self.fail_diff_times:
            raise TimeoutError("diff db timeout")
        self.diff_records.append(dict(record))
        return _stored("activity_diffs", record, "diff_id")

    async def write_evidence_link(
        self, record: Mapping[str, Any]
    ) -> StorageWriteResult:
        self.evidence_attempts.append(dict(record))
        if len(self.evidence_attempts) <= self.fail_evidence_times:
            raise TimeoutError("evidence db timeout")
        self.evidence_links.append(dict(record))
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
            raise RuntimeError(self.fail_dead_letter_message)
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
    *,
    metadata: Mapping[str, Any] | None = None,
    evidence_refs: tuple[EvidenceRef, ...] = (),
) -> ReconstructionContent:
    return ReconstructionContent(
        primary_target=TargetRef(target_type="prompt", target_id="prompt-1"),
        version_refs=("prompt-version-1",),
        evidence_refs=evidence_refs,
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
    assert record["collapse_metadata"]["record_scope"] == "project"
    assert record["default_actor_chain"]["caller"] == {
        "actor_type": "user",
        "actor_id": "user-1",
    }
    assert record["collapse_metadata"]["correlation_id"] == "corr-1"
    assert record["collapse_metadata"]["trace_id"] == "trace-1"


@pytest.mark.asyncio
async def test_record_interaction_retries_then_dead_letters_on_failure(caplog):
    raw_marker = "raw-customer-payload-interaction"
    storage = FakeStorage(
        fail_interaction_times=2,
        fail_interaction_message=raw_marker,
    )
    recorder = ActivityRecorder(storage, max_attempts=2)
    interaction = replace(
        _interaction(),
        caller=ActorRef(
            actor_type="user",
            actor_id="user-1",
            display_name=raw_marker,
        ),
    )
    caplog.set_level(logging.ERROR, logger="taproot_common.activity.recorder")

    result = await recorder.record_interaction(interaction)

    assert result.accepted is False
    assert result.dead_lettered is True
    assert result.error_type == "TimeoutError"
    assert len(storage.interaction_attempts) == 2
    assert storage.dead_letters[0]["operation_type"] == "interaction_record"
    assert storage.dead_letters[0]["payload"]["interaction_id"] == "int-1"
    assert "activity.interaction_record_write_failed" in caplog.text
    assert '"interaction_id": "int-1"' in caplog.text
    assert '"error_message": "redacted"' in caplog.text
    assert '"operation_type": "interaction_record"' in caplog.text
    assert '"severity": "severe"' in caplog.text
    assert raw_marker not in caplog.text


@pytest.mark.asyncio
async def test_record_interaction_dead_letter_failure_does_not_raise(caplog):
    raw_marker = "raw-customer-payload-dead-letter"
    storage = FakeStorage(
        fail_interaction_times=1,
        fail_dead_letter=True,
        fail_interaction_message=raw_marker,
        fail_dead_letter_message=raw_marker,
    )
    recorder = ActivityRecorder(storage, max_attempts=1)
    interaction = replace(
        _interaction(),
        caller=ActorRef(
            actor_type="user",
            actor_id="user-1",
            display_name=raw_marker,
        ),
    )
    caplog.set_level(logging.ERROR, logger="taproot_common.activity.recorder")

    result = await recorder.record_interaction(interaction)

    assert result.accepted is False
    assert result.dead_lettered is False
    assert result.error_type == "TimeoutError"
    assert "activity.system_record_dead_letter_write_failed" in caplog.text
    assert '"dead_letter_error_type": "RuntimeError"' in caplog.text
    assert '"dead_letter_error_message": "redacted"' in caplog.text
    assert '"error_message": "redacted"' in caplog.text
    assert '"operation_type": "interaction_record"' in caplog.text
    assert '"severity": "severe"' in caplog.text
    assert raw_marker not in caplog.text


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
    assert record["metadata"]["record_scope"] == "project"
    assert record["retention_policy_id"] == "ret-1"
    assert record["metadata"]["correlation_id"] == "corr-1"
    assert record["metadata"]["trace_id"] == "trace-1"
    assert record["metadata"]["safe_summary"] == "label prod"


@pytest.mark.asyncio
async def test_record_activity_persists_normalized_evidence_links():
    storage = FakeStorage()
    recorder = ActivityRecorder(storage)

    evidence = EvidenceRef(
        evidence_type="prompt_version",
        evidence_id="prompt-version-1",
        domain_area=DomainArea.PROMPT,
        content_hash="sha256:content",
        metadata_hash="sha256:metadata",
        ref={"label": "prod", "version_id": "prompt-version-1"},
    )

    result = await recorder.record_activity(
        taxonomy=_taxonomy(),
        reconstruction=_reconstruction(evidence_refs=(evidence,)),
        interaction=_interaction(),
        activity_id="act-evidence-1",
    )

    assert result.accepted is True
    assert len(result.evidence_results) == 1
    assert result.evidence_results[0].table_name == "activity_evidence_links"
    assert storage.evidence_links == [
        {
            "activity_id": "act-evidence-1",
            "project_id": "project-1",
            "domain_area": "prompt",
            "evidence_type": "prompt_version",
            "evidence_id": "prompt-version-1",
            "evidence_ref": {"label": "prod", "version_id": "prompt-version-1"},
            "content_hash": "sha256:content",
            "metadata_hash": "sha256:metadata",
        }
    ]


@pytest.mark.asyncio
async def test_record_critical_activity_persists_normalized_evidence_links():
    storage = FakeStorage()
    recorder = ActivityRecorder(storage)

    result = await recorder.record_critical_activity(
        taxonomy=_critical_taxonomy(),
        reconstruction=_reconstruction(
            evidence_refs=(
                EvidenceRef(
                    evidence_type="prompt_version",
                    evidence_id="prompt-version-1",
                    domain_area=DomainArea.PROMPT,
                ),
            )
        ),
        interaction=_interaction(),
        activity_id="act-critical-evidence-1",
    )

    assert result.accepted is True
    assert storage.evidence_links[0]["activity_id"] == "act-critical-evidence-1"


@pytest.mark.asyncio
async def test_record_snapshot_writes_safe_snapshot_with_payload_hash():
    storage = FakeStorage()
    recorder = ActivityRecorder(storage)

    result = await recorder.record_snapshot(
        activity_id="act-1",
        target=TargetRef(target_type="prompt", target_id="prompt-1"),
        domain_area=DomainArea.PROMPT,
        snapshot_kind="label_assignment",
        snapshot_payload={"label": "prod", "version_id": "prompt-version-1"},
        project_id="project-1",
        retention_policy_id="ret-1",
        snapshot_id="snap-1",
    )

    assert result.snapshot_id == "snap-1"
    assert result.storage_result.table_name == "activity_snapshots"
    record = storage.snapshot_records[0]
    assert record["snapshot_payload"] == {
        "label": "prod",
        "version_id": "prompt-version-1",
    }
    assert record["payload_hash"].startswith("sha256:")
    assert record["project_id"] == "project-1"


@pytest.mark.asyncio
async def test_record_diff_writes_safe_diff_with_payload_hash():
    storage = FakeStorage()
    recorder = ActivityRecorder(storage)

    result = await recorder.record_diff(
        activity_id="act-1",
        target=TargetRef(target_type="prompt", target_id="prompt-1"),
        domain_area=DomainArea.PROMPT,
        diff_payload={"changed_fields": ["label"], "after_hash": "sha256:after"},
        project_id="project-1",
        diff_id="diff-1",
    )

    assert result.diff_id == "diff-1"
    assert result.storage_result.table_name == "activity_diffs"
    record = storage.diff_records[0]
    assert record["diff_payload"] == {
        "changed_fields": ["label"],
        "after_hash": "sha256:after",
    }
    assert record["payload_hash"].startswith("sha256:")
    assert record["project_id"] == "project-1"


@pytest.mark.asyncio
async def test_record_activity_package_writes_related_rows_together():
    storage = FakeStorage()
    recorder = ActivityRecorder(storage)

    result = await recorder.record_activity(
        taxonomy=_taxonomy(),
        reconstruction=_reconstruction(
            evidence_refs=(
                EvidenceRef(
                    evidence_type="prompt_version",
                    evidence_id="prompt-version-1",
                    domain_area=DomainArea.PROMPT,
                    ref={"version_id": "prompt-version-1"},
                ),
            )
        ),
        interaction=_interaction(),
        activity_id="act-package-1",
        snapshots=(
            SnapshotRecordInput(
                target=TargetRef(target_type="prompt", target_id="prompt-1"),
                domain_area=DomainArea.PROMPT,
                snapshot_kind="label_assignment",
                snapshot_payload={"label": "prod"},
                snapshot_id="snap-package-1",
            ),
        ),
        diffs=(
            DiffRecordInput(
                target=TargetRef(target_type="prompt", target_id="prompt-1"),
                domain_area=DomainArea.PROMPT,
                diff_payload={"changed_fields": ["label"]},
                diff_id="diff-package-1",
            ),
        ),
    )

    assert result.accepted is True
    assert result.storage_result is not None
    assert result.storage_result.table_name == "activity_records"
    assert [item.table_name for item in result.evidence_results] == [
        "activity_evidence_links"
    ]
    assert [item.idempotency_key for item in result.snapshot_results] == [
        "snap-package-1"
    ]
    assert [item.idempotency_key for item in result.diff_results] == ["diff-package-1"]
    assert storage.activity_records[0]["activity_id"] == "act-package-1"
    assert storage.evidence_links[0]["activity_id"] == "act-package-1"
    assert storage.snapshot_records[0]["activity_id"] == "act-package-1"
    assert storage.snapshot_records[0]["snapshot_payload"] == {"label": "prod"}
    assert storage.diff_records[0]["activity_id"] == "act-package-1"
    assert storage.diff_records[0]["diff_payload"] == {"changed_fields": ["label"]}


@pytest.mark.asyncio
async def test_record_activity_package_retries_missing_related_rows():
    storage = FakeStorage(fail_evidence_times=1)
    recorder = ActivityRecorder(storage, max_attempts=2)

    result = await recorder.record_activity(
        taxonomy=_taxonomy(),
        reconstruction=_reconstruction(
            evidence_refs=(
                EvidenceRef(
                    evidence_type="prompt_version",
                    evidence_id="prompt-version-1",
                    domain_area=DomainArea.PROMPT,
                ),
            )
        ),
        interaction=_interaction(),
        activity_id="act-package-retry-1",
    )

    assert result.accepted is True
    assert result.attempts == 2
    assert len(storage.activity_attempts) == 2
    assert len(storage.evidence_attempts) == 2
    assert storage.evidence_links[0]["activity_id"] == "act-package-retry-1"


@pytest.mark.asyncio
async def test_record_activity_package_dead_letters_related_write_failure():
    storage = FakeStorage(fail_snapshot_times=1)
    recorder = ActivityRecorder(storage, max_attempts=1)

    result = await recorder.record_activity(
        taxonomy=_taxonomy(),
        reconstruction=_reconstruction(),
        interaction=_interaction(),
        activity_id="act-package-failure-1",
        snapshots=(
            SnapshotRecordInput(
                target=TargetRef(target_type="prompt", target_id="prompt-1"),
                domain_area=DomainArea.PROMPT,
                snapshot_kind="label_assignment",
                snapshot_payload={"label": "prod"},
                snapshot_id="snap-package-failure-1",
            ),
        ),
    )

    assert result.accepted is False
    assert result.storage_result is not None
    assert result.failed_related_write_type == "activity_snapshot"
    assert result.failed_related_write_key == "snap-package-failure-1"
    assert storage.activity_records[0]["activity_id"] == "act-package-failure-1"
    assert storage.dead_letters[0]["operation_type"] == "activity_package"
    assert storage.dead_letters[0]["payload"]["package_failure"] == {
        "failed_related_write_type": "activity_snapshot",
        "failed_related_write_key": "snap-package-failure-1",
        "error_type": "TimeoutError",
        "error_message": "snapshot db timeout",
    }


@pytest.mark.asyncio
async def test_record_critical_activity_package_raises_related_write_failure():
    storage = FakeStorage(fail_diff_times=1)
    recorder = ActivityRecorder(storage)

    with pytest.raises(
        ActivityRecorderError, match="activity_diff diff-package-failure-1"
    ):
        await recorder.record_critical_activity(
            taxonomy=_critical_taxonomy(),
            reconstruction=_reconstruction(),
            interaction=_interaction(),
            activity_id="act-critical-package-failure-1",
            diffs=(
                DiffRecordInput(
                    target=TargetRef(target_type="prompt", target_id="prompt-1"),
                    domain_area=DomainArea.PROMPT,
                    diff_payload={"changed_fields": ["label"]},
                    diff_id="diff-package-failure-1",
                ),
            ),
        )

    assert (
        storage.activity_records[0]["activity_id"] == "act-critical-package-failure-1"
    )
    assert storage.dead_letters == []


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
async def test_record_interaction_rejects_project_scoped_record_without_project_id():
    storage = FakeStorage()
    recorder = ActivityRecorder(storage)

    with pytest.raises(ProjectIsolationError, match="requires project_id"):
        await recorder.record_interaction(
            InteractionContext(
                interaction_id="int-missing-project",
                interaction_type=InteractionType.SERVICE_REQUEST,
            )
        )

    assert storage.interaction_records == []
    assert storage.dead_letters == []


@pytest.mark.asyncio
async def test_record_interaction_allows_explicit_system_scoped_record():
    storage = FakeStorage()
    recorder = ActivityRecorder(storage)

    result = await recorder.record_interaction(
        InteractionContext(
            interaction_id="int-system",
            interaction_type=InteractionType.RETENTION_JOB,
            domain_area=DomainArea.COMMON,
            record_scope=RecordScope.SYSTEM,
        )
    )

    assert result.accepted is True
    record = storage.interaction_records[0]
    assert record["project_id"] is None
    assert record["collapse_metadata"]["record_scope"] == "system"


@pytest.mark.asyncio
async def test_record_activity_rejects_project_scoped_record_without_project_id():
    storage = FakeStorage()
    recorder = ActivityRecorder(storage, max_attempts=1)

    with pytest.raises(ProjectIsolationError, match="requires project_id"):
        await recorder.record_activity(
            taxonomy=_taxonomy(),
            reconstruction=_reconstruction(),
            activity_id="act-missing-project",
        )

    assert storage.activity_records == []
    assert storage.dead_letters == []


@pytest.mark.asyncio
async def test_record_activity_allows_explicit_system_scoped_record():
    storage = FakeStorage()
    recorder = ActivityRecorder(storage)

    result = await recorder.record_activity(
        taxonomy=_taxonomy(),
        reconstruction=_reconstruction(),
        record_scope=RecordScope.SYSTEM,
        activity_id="act-system",
    )

    assert result.accepted is True
    record = storage.activity_records[0]
    assert record["project_id"] is None
    assert record["metadata"]["record_scope"] == "system"


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
async def test_record_activity_retries_then_dead_letters_on_failure(caplog):
    raw_marker = "raw-customer-payload-activity"
    storage = FakeStorage(
        fail_activity_times=2,
        fail_activity_message=raw_marker,
    )
    recorder = ActivityRecorder(storage, max_attempts=2)
    caplog.set_level(logging.ERROR, logger="taproot_common.activity.recorder")

    result = await recorder.record_activity(
        taxonomy=_taxonomy(),
        reconstruction=_reconstruction(metadata={"safe_note": raw_marker}),
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
    assert "activity.system_record_write_failed" in caplog.text
    assert '"activity_id": "act-failure-1"' in caplog.text
    assert '"action_family": "update"' in caplog.text
    assert '"error_message": "redacted"' in caplog.text
    assert '"operation_type": "activity_record"' in caplog.text
    assert '"severity": "severe"' in caplog.text
    assert raw_marker not in caplog.text


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
async def test_record_activity_rejects_raw_payload_fields_in_evidence_refs():
    storage = FakeStorage()
    recorder = ActivityRecorder(storage)

    with pytest.raises(ActivityRecorderError, match="Raw payload fields"):
        await recorder.record_activity(
            taxonomy=_taxonomy(),
            reconstruction=_reconstruction(
                evidence_refs=(
                    EvidenceRef(
                        evidence_type="prompt_version",
                        evidence_id="prompt-version-1",
                        domain_area=DomainArea.PROMPT,
                        ref={"raw_payload": "prompt text"},
                    ),
                )
            ),
            interaction=_interaction(),
        )

    assert storage.activity_records == []
    assert storage.evidence_links == []


@pytest.mark.asyncio
async def test_record_snapshot_rejects_raw_payload_fields_by_default():
    storage = FakeStorage()
    recorder = ActivityRecorder(storage)

    with pytest.raises(ActivityRecorderError, match="Raw payload fields"):
        await recorder.record_snapshot(
            activity_id="act-1",
            target=TargetRef(target_type="prompt", target_id="prompt-1"),
            domain_area=DomainArea.PROMPT,
            snapshot_kind="unsafe_state",
            snapshot_payload={"content": "raw prompt"},
        )

    assert storage.snapshot_records == []


@pytest.mark.asyncio
async def test_record_diff_rejects_raw_payload_fields_by_default():
    storage = FakeStorage()
    recorder = ActivityRecorder(storage)

    with pytest.raises(ActivityRecorderError, match="Raw payload fields"):
        await recorder.record_diff(
            activity_id="act-1",
            target=TargetRef(target_type="prompt", target_id="prompt-1"),
            domain_area=DomainArea.PROMPT,
            diff_payload={"raw_payload": {"secret": "value"}},
        )

    assert storage.diff_records == []


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
        snapshot_result = await record_snapshot(
            activity_id="act-module-2",
            target=TargetRef(target_type="prompt", target_id="prompt-1"),
            domain_area=DomainArea.PROMPT,
            snapshot_kind="safe_state",
            snapshot_payload={"version_id": "prompt-version-1"},
            project_id="project-1",
            snapshot_id="snap-module-1",
        )
        diff_result = await record_diff(
            activity_id="act-module-2",
            target=TargetRef(target_type="prompt", target_id="prompt-1"),
            domain_area=DomainArea.PROMPT,
            diff_payload={"changed_fields": ["label"]},
            project_id="project-1",
            diff_id="diff-module-1",
        )
    finally:
        clear_activity_recorder()

    assert get_activity_recorder() is None

    assert async_result.activity_id == "act-module-1"
    assert critical_result.activity_id == "act-module-2"
    assert snapshot_result.snapshot_id == "snap-module-1"
    assert diff_result.diff_id == "diff-module-1"
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
