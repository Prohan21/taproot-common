"""Shared activity recording APIs for TAP-38."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from taproot_common.activity.context import get_interaction_context
from taproot_common.activity.models import (
    ActionFamily,
    ActorChain,
    ActivityTaxonomy,
    DomainArea,
    Durability,
    EvidenceRef,
    InteractionContext,
    RecordScope,
    ReconstructionContent,
    TargetRef,
    validate_record_project_scope,
)
from taproot_common.activity.storage import (
    ActivityStorageAdapter,
    ActivityStorageConflictError,
    ActivityStorageError,
    StorageWriteResult,
)

CRITICAL_ACTION_FAMILIES: frozenset[ActionFamily] = frozenset(
    {
        ActionFamily.CREATE,
        ActionFamily.UPDATE,
        ActionFamily.DELETE,
        ActionFamily.RESTORE,
        ActionFamily.PURGE,
        ActionFamily.RETAIN,
    }
)

RAW_PAYLOAD_KEYS: frozenset[str] = frozenset(
    {
        "content",
        "content_preview",
        "content_sample",
        "checked_content",
        "checked_input",
        "checked_output",
        "checked_text",
        "document_content",
        "input",
        "output",
        "payload",
        "prompt",
        "prompt_text",
        "query_text",
        "response_text",
        "raw_content",
        "raw_input",
        "raw_output",
        "raw_payload",
        "raw_text",
    }
)

logger = logging.getLogger(__name__)

_REDACTED_LOG_ERROR_MESSAGE = "redacted"


@dataclass(frozen=True)
class ActivityPublishResult:
    """Result returned after activity publication is accepted or failure-visible."""

    activity_id: str
    durability: Durability
    accepted: bool
    attempts: int
    storage_result: StorageWriteResult | None = None
    evidence_results: tuple[StorageWriteResult, ...] = ()
    snapshot_results: tuple[StorageWriteResult, ...] = ()
    diff_results: tuple[StorageWriteResult, ...] = ()
    failure_visible: bool = False
    failure_visibility_result: StorageWriteResult | None = None
    error_type: str | None = None
    error_message: str | None = None
    failed_related_write_type: str | None = None
    failed_related_write_key: str | None = None


@dataclass(frozen=True)
class InteractionRecordResult:
    """Result returned after interaction record publication is attempted."""

    interaction_id: str
    accepted: bool
    attempts: int
    storage_result: StorageWriteResult | None = None
    failure_visible: bool = False
    failure_visibility_result: StorageWriteResult | None = None
    error_type: str | None = None
    error_message: str | None = None


@dataclass(frozen=True)
class SnapshotRecordResult:
    """Result returned after a reconstruction snapshot is recorded."""

    snapshot_id: str
    storage_result: StorageWriteResult


@dataclass(frozen=True)
class DiffRecordResult:
    """Result returned after a reconstruction diff is recorded."""

    diff_id: str
    storage_result: StorageWriteResult


@dataclass(frozen=True)
class RetentionApplicationRecordResult:
    """Result returned after a retention application is recorded."""

    application_id: str
    storage_result: StorageWriteResult


@dataclass(frozen=True)
class PurgeTombstoneRecordResult:
    """Result returned after a safe purge tombstone is recorded."""

    purge_tombstone_id: str
    storage_result: StorageWriteResult


@dataclass(frozen=True)
class SnapshotRecordInput:
    """Snapshot row to write as part of one activity package."""

    target: TargetRef
    domain_area: DomainArea
    snapshot_kind: str
    snapshot_payload: Mapping[str, Any]
    project_id: str | None = None
    retention_policy_id: str | None = None
    retention_expires_at: datetime | None = None
    snapshot_id: str | None = None
    record_scope: RecordScope = RecordScope.PROJECT


@dataclass(frozen=True)
class DiffRecordInput:
    """Diff row to write as part of one activity package."""

    target: TargetRef
    domain_area: DomainArea
    diff_payload: Mapping[str, Any]
    project_id: str | None = None
    diff_id: str | None = None
    record_scope: RecordScope = RecordScope.PROJECT


@dataclass(frozen=True)
class RetentionApplicationInput:
    """Safe retention-policy application fact to persist."""

    activity_id: str
    retention_policy_id: str
    domain_area: DomainArea
    target: TargetRef
    action_taken: str
    project_id: str | None = None
    application_id: str | None = None
    applied_at: datetime | None = None
    metadata: Mapping[str, Any] | None = None
    record_scope: RecordScope = RecordScope.PROJECT


@dataclass(frozen=True)
class PurgeTombstoneInput:
    """Safe tombstone fact left after a service-owned hard purge."""

    activity_id: str
    domain_area: DomainArea
    target: TargetRef
    purge_reason: str
    purge_scope: str
    initiated_by: Mapping[str, Any]
    purged_evidence_classes: Sequence[str]
    project_id: str | None = None
    purge_tombstone_id: str | None = None
    retention_policy_id: str | None = None
    record_scope: RecordScope = RecordScope.PROJECT


@dataclass(frozen=True)
class RelatedWriteFailure:
    """Context for a failed related row in an activity package."""

    write_type: str
    key: str
    error_type: str
    error_message: str


class ActivityRecorderError(RuntimeError):
    """Raised when activity recording cannot satisfy caller semantics."""


class ActivityPackageWriteError(ActivityRecorderError):
    """Raised when one logical activity package is only partially accepted."""

    def __init__(
        self,
        message: str,
        *,
        failure: RelatedWriteFailure,
        storage_result: StorageWriteResult | None = None,
        evidence_results: Sequence[StorageWriteResult] = (),
        snapshot_results: Sequence[StorageWriteResult] = (),
        diff_results: Sequence[StorageWriteResult] = (),
    ) -> None:
        super().__init__(message)
        self.failure = failure
        self.storage_result = storage_result
        self.evidence_results = tuple(evidence_results)
        self.snapshot_results = tuple(snapshot_results)
        self.diff_results = tuple(diff_results)


class ActivityRecorder:
    """Records TAP-38 activity through an activity storage Adapter."""

    def __init__(
        self,
        storage: ActivityStorageAdapter,
        *,
        max_attempts: int = 3,
        retry_delay_seconds: float = 0.0,
        write_timeout_seconds: float | None = 5.0,
    ) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")

        self._storage = storage
        self._max_attempts = max_attempts
        self._retry_delay_seconds = retry_delay_seconds
        self._write_timeout_seconds = write_timeout_seconds

    async def record_interaction(
        self,
        context: InteractionContext,
        *,
        started_at: datetime | None = None,
    ) -> InteractionRecordResult:
        """Record an interaction without failing the caller on storage failure."""

        record = _build_interaction_record(context, started_at=started_at)
        try:
            storage_result, attempts = await self._write_interaction_with_retry(record)
        except Exception as exc:  # noqa: BLE001 - interaction creation is non-critical.
            failure_visibility_result = await self._write_system_record_write_failure(
                record,
                exc,
                operation_type="interaction_record",
                failure_phase="interaction_create",
            )
            _log_system_record_failure(
                "activity.interaction_record_write_failed",
                record,
                operation_type="interaction_record",
                error=exc,
                failure_visible=failure_visibility_result is not None,
            )
            return InteractionRecordResult(
                interaction_id=context.interaction_id,
                accepted=False,
                attempts=self._max_attempts,
                failure_visible=failure_visibility_result is not None,
                failure_visibility_result=failure_visibility_result,
                error_type=type(exc).__name__,
                error_message=_safe_error_message(exc),
            )

        return InteractionRecordResult(
            interaction_id=context.interaction_id,
            accepted=True,
            attempts=attempts,
            storage_result=storage_result,
        )

    async def record_activity(
        self,
        *,
        taxonomy: ActivityTaxonomy,
        reconstruction: ReconstructionContent,
        interaction: InteractionContext | None = None,
        actor_override: ActorChain | None = None,
        parent_activity_id: str | None = None,
        sequence: int | None = None,
        occurred_at: datetime | None = None,
        metadata: Mapping[str, Any] | None = None,
        activity_id: str | None = None,
        record_scope: RecordScope = RecordScope.PROJECT,
        snapshots: Sequence[SnapshotRecordInput] = (),
        diffs: Sequence[DiffRecordInput] = (),
    ) -> ActivityPublishResult:
        """Record non-critical activity with bounded retry and safe failure visibility."""

        if taxonomy.durability != Durability.ASYNC:
            raise ActivityRecorderError("record_activity requires async durability")

        resolved_activity_id = activity_id or _create_activity_id()
        resolved_interaction = interaction or get_interaction_context()
        record = _build_activity_record(
            activity_id=resolved_activity_id,
            taxonomy=taxonomy,
            reconstruction=reconstruction,
            interaction=resolved_interaction,
            actor_override=actor_override,
            parent_activity_id=parent_activity_id,
            sequence=sequence,
            occurred_at=occurred_at,
            metadata=metadata,
            record_scope=record_scope,
        )

        try:
            (
                storage_result,
                evidence_results,
                snapshot_results,
                diff_results,
                attempts,
            ) = await self._write_activity_with_retry(
                record,
                reconstruction.evidence_refs,
                snapshots,
                diffs,
                interaction=resolved_interaction,
                record_scope=_record_scope_from_activity_record(record, record_scope),
            )
        except Exception as exc:  # noqa: BLE001 - non-critical path records failures.
            failure = (
                exc.failure if isinstance(exc, ActivityPackageWriteError) else None
            )
            operation_type = "activity_package" if failure else "activity_record"
            failure_visibility_result = await self._write_system_record_write_failure(
                record,
                exc,
                operation_type=operation_type,
                failure=failure,
                failure_phase=_activity_failure_phase(
                    exc,
                    default="package_write" if failure else "activity_write",
                ),
            )
            _log_system_record_failure(
                "activity.system_record_write_failed",
                record,
                operation_type=operation_type,
                error=exc,
                failure=failure,
                failure_visible=failure_visibility_result is not None,
            )
            return ActivityPublishResult(
                activity_id=resolved_activity_id,
                durability=taxonomy.durability,
                accepted=False,
                attempts=self._max_attempts,
                storage_result=exc.storage_result
                if isinstance(exc, ActivityPackageWriteError)
                else None,
                evidence_results=exc.evidence_results
                if isinstance(exc, ActivityPackageWriteError)
                else (),
                snapshot_results=exc.snapshot_results
                if isinstance(exc, ActivityPackageWriteError)
                else (),
                diff_results=exc.diff_results
                if isinstance(exc, ActivityPackageWriteError)
                else (),
                failure_visible=failure_visibility_result is not None,
                failure_visibility_result=failure_visibility_result,
                error_type=type(exc).__name__,
                error_message=_safe_error_message(exc),
                failed_related_write_type=failure.write_type if failure else None,
                failed_related_write_key=failure.key if failure else None,
            )

        return ActivityPublishResult(
            activity_id=resolved_activity_id,
            durability=taxonomy.durability,
            accepted=True,
            attempts=attempts,
            storage_result=storage_result,
            evidence_results=evidence_results,
            snapshot_results=snapshot_results,
            diff_results=diff_results,
        )

    async def record_critical_activity(
        self,
        *,
        taxonomy: ActivityTaxonomy,
        reconstruction: ReconstructionContent,
        interaction: InteractionContext | None = None,
        actor_override: ActorChain | None = None,
        parent_activity_id: str | None = None,
        sequence: int | None = None,
        occurred_at: datetime | None = None,
        metadata: Mapping[str, Any] | None = None,
        activity_id: str | None = None,
        record_scope: RecordScope = RecordScope.PROJECT,
        snapshots: Sequence[SnapshotRecordInput] = (),
        diffs: Sequence[DiffRecordInput] = (),
    ) -> ActivityPublishResult:
        """Record critical activity and raise if the system record DB write fails."""

        if taxonomy.durability != Durability.CRITICAL:
            raise ActivityRecorderError(
                "record_critical_activity requires critical durability"
            )
        if taxonomy.action_family not in CRITICAL_ACTION_FAMILIES:
            raise ActivityRecorderError(
                f"Unsupported critical action family: {taxonomy.action_family.value}"
            )

        resolved_activity_id = activity_id or _create_activity_id()
        resolved_interaction = interaction or get_interaction_context()
        record = _build_activity_record(
            activity_id=resolved_activity_id,
            taxonomy=taxonomy,
            reconstruction=reconstruction,
            interaction=resolved_interaction,
            actor_override=actor_override,
            parent_activity_id=parent_activity_id,
            sequence=sequence,
            occurred_at=occurred_at,
            metadata=metadata,
            record_scope=record_scope,
        )
        (
            storage_result,
            evidence_results,
            snapshot_results,
            diff_results,
        ) = await self._write_activity_once(
            record,
            reconstruction.evidence_refs,
            snapshots,
            diffs,
            interaction=resolved_interaction,
            record_scope=_record_scope_from_activity_record(record, record_scope),
        )

        return ActivityPublishResult(
            activity_id=resolved_activity_id,
            durability=taxonomy.durability,
            accepted=True,
            attempts=1,
            storage_result=storage_result,
            evidence_results=evidence_results,
            snapshot_results=snapshot_results,
            diff_results=diff_results,
        )

    async def record_snapshot(
        self,
        *,
        activity_id: str,
        target: TargetRef,
        domain_area: DomainArea,
        snapshot_kind: str,
        snapshot_payload: Mapping[str, Any],
        project_id: str | None = None,
        retention_policy_id: str | None = None,
        retention_expires_at: datetime | None = None,
        snapshot_id: str | None = None,
        record_scope: RecordScope = RecordScope.PROJECT,
    ) -> SnapshotRecordResult:
        """Record a safe reconstruction snapshot through the storage Adapter."""

        if not activity_id.strip():
            raise ActivityRecorderError("Snapshot activity_id is required")
        if not snapshot_kind.strip():
            raise ActivityRecorderError("Snapshot snapshot_kind is required")
        if _contains_raw_payload_key(snapshot_payload):
            raise ActivityRecorderError("Raw payload fields are not allowed by default")

        interaction = get_interaction_context()
        snapshot = SnapshotRecordInput(
            target=target,
            domain_area=domain_area,
            snapshot_kind=snapshot_kind,
            snapshot_payload=snapshot_payload,
            project_id=project_id,
            retention_policy_id=retention_policy_id,
            retention_expires_at=retention_expires_at,
            snapshot_id=snapshot_id,
            record_scope=record_scope,
        )
        record = _build_snapshot_record(
            activity_id=activity_id,
            snapshot=snapshot,
            interaction=interaction,
            default_project_id=None,
            default_retention_policy_id=None,
            default_record_scope=record_scope,
        )
        storage_result = await self._write_snapshot_once(record)
        return SnapshotRecordResult(
            snapshot_id=str(record["snapshot_id"]),
            storage_result=storage_result,
        )

    async def record_diff(
        self,
        *,
        activity_id: str,
        target: TargetRef,
        domain_area: DomainArea,
        diff_payload: Mapping[str, Any],
        project_id: str | None = None,
        diff_id: str | None = None,
        record_scope: RecordScope = RecordScope.PROJECT,
    ) -> DiffRecordResult:
        """Record a safe reconstruction diff through the storage Adapter."""

        if not activity_id.strip():
            raise ActivityRecorderError("Diff activity_id is required")
        if _contains_raw_payload_key(diff_payload):
            raise ActivityRecorderError("Raw payload fields are not allowed by default")

        interaction = get_interaction_context()
        diff = DiffRecordInput(
            target=target,
            domain_area=domain_area,
            diff_payload=diff_payload,
            project_id=project_id,
            diff_id=diff_id,
            record_scope=record_scope,
        )
        record = _build_diff_record(
            activity_id=activity_id,
            diff=diff,
            interaction=interaction,
            default_project_id=None,
            default_record_scope=record_scope,
        )
        storage_result = await self._write_diff_once(record)
        return DiffRecordResult(
            diff_id=str(record["diff_id"]), storage_result=storage_result
        )

    async def record_retention_application(
        self,
        *,
        activity_id: str,
        retention_policy_id: str,
        domain_area: DomainArea,
        target: TargetRef,
        action_taken: str,
        project_id: str | None = None,
        application_id: str | None = None,
        applied_at: datetime | None = None,
        metadata: Mapping[str, Any] | None = None,
        record_scope: RecordScope = RecordScope.PROJECT,
    ) -> RetentionApplicationRecordResult:
        """Record a safe retention-policy application fact."""

        application = RetentionApplicationInput(
            activity_id=activity_id,
            retention_policy_id=retention_policy_id,
            domain_area=domain_area,
            target=target,
            action_taken=action_taken,
            project_id=project_id,
            application_id=application_id,
            applied_at=applied_at,
            metadata=metadata,
            record_scope=record_scope,
        )
        record = _build_retention_application_record(
            application,
            interaction=get_interaction_context(),
        )
        storage_result = await self._write_retention_application_once(record)
        return RetentionApplicationRecordResult(
            application_id=str(record["application_id"]),
            storage_result=storage_result,
        )

    async def record_purge_tombstone(
        self,
        *,
        activity_id: str,
        domain_area: DomainArea,
        target: TargetRef,
        purge_reason: str,
        purge_scope: str,
        initiated_by: Mapping[str, Any],
        purged_evidence_classes: Sequence[str],
        project_id: str | None = None,
        purge_tombstone_id: str | None = None,
        retention_policy_id: str | None = None,
        record_scope: RecordScope = RecordScope.PROJECT,
    ) -> PurgeTombstoneRecordResult:
        """Record a mandatory safe tombstone for service-owned hard purge."""

        tombstone = PurgeTombstoneInput(
            activity_id=activity_id,
            domain_area=domain_area,
            target=target,
            purge_reason=purge_reason,
            purge_scope=purge_scope,
            initiated_by=initiated_by,
            purged_evidence_classes=purged_evidence_classes,
            project_id=project_id,
            purge_tombstone_id=purge_tombstone_id,
            retention_policy_id=retention_policy_id,
            record_scope=record_scope,
        )
        record = _build_purge_tombstone_record(
            tombstone,
            interaction=get_interaction_context(),
        )
        storage_result = await self._write_purge_tombstone_once(record)
        return PurgeTombstoneRecordResult(
            purge_tombstone_id=str(record["purge_tombstone_id"]),
            storage_result=storage_result,
        )

    async def _write_activity_with_retry(
        self,
        record: Mapping[str, Any],
        evidence_refs: Sequence[EvidenceRef],
        snapshots: Sequence[SnapshotRecordInput],
        diffs: Sequence[DiffRecordInput],
        *,
        interaction: InteractionContext | None,
        record_scope: RecordScope,
    ) -> tuple[
        StorageWriteResult,
        tuple[StorageWriteResult, ...],
        tuple[StorageWriteResult, ...],
        tuple[StorageWriteResult, ...],
        int,
    ]:
        last_error: Exception | None = None
        for attempt in range(1, self._max_attempts + 1):
            try:
                (
                    storage_result,
                    evidence_results,
                    snapshot_results,
                    diff_results,
                ) = await self._write_activity_once(
                    record,
                    evidence_refs,
                    snapshots,
                    diffs,
                    interaction=interaction,
                    record_scope=record_scope,
                )
                return (
                    storage_result,
                    evidence_results,
                    snapshot_results,
                    diff_results,
                    attempt,
                )
            except Exception as exc:  # noqa: BLE001 - retry policy handles adapter errors.
                last_error = exc
                if attempt < self._max_attempts and self._retry_delay_seconds:
                    await asyncio.sleep(self._retry_delay_seconds)

        if last_error is None:
            raise ActivityRecorderError("Activity write failed without an exception")
        raise last_error

    async def _write_interaction_with_retry(
        self, record: Mapping[str, Any]
    ) -> tuple[StorageWriteResult, int]:
        last_error: Exception | None = None
        for attempt in range(1, self._max_attempts + 1):
            try:
                return await self._write_interaction_once(record), attempt
            except Exception as exc:  # noqa: BLE001 - retry policy handles adapter errors.
                last_error = exc
                if attempt < self._max_attempts and self._retry_delay_seconds:
                    await asyncio.sleep(self._retry_delay_seconds)

        if last_error is None:
            raise ActivityRecorderError("Interaction write failed without an exception")
        raise last_error

    async def _write_interaction_once(
        self, record: Mapping[str, Any]
    ) -> StorageWriteResult:
        write = self._storage.write_interaction_record(record)
        if self._write_timeout_seconds is None:
            return await write
        return await asyncio.wait_for(write, timeout=self._write_timeout_seconds)

    async def _write_activity_once(
        self,
        record: Mapping[str, Any],
        evidence_refs: Sequence[EvidenceRef],
        snapshots: Sequence[SnapshotRecordInput],
        diffs: Sequence[DiffRecordInput],
        *,
        interaction: InteractionContext | None,
        record_scope: RecordScope,
    ) -> tuple[
        StorageWriteResult,
        tuple[StorageWriteResult, ...],
        tuple[StorageWriteResult, ...],
        tuple[StorageWriteResult, ...],
    ]:
        await self._ensure_activity_interaction(interaction)
        write = self._storage.write_activity_record(record)
        if self._write_timeout_seconds is None:
            storage_result = await write
        else:
            storage_result = await asyncio.wait_for(
                write,
                timeout=self._write_timeout_seconds,
            )
        evidence_results: list[StorageWriteResult] = []
        snapshot_results: list[StorageWriteResult] = []
        diff_results: list[StorageWriteResult] = []
        for evidence_ref in evidence_refs:
            evidence_record = _build_evidence_link_record(record, evidence_ref)
            try:
                evidence_results.append(
                    await self._write_evidence_link_once(evidence_record)
                )
            except Exception as exc:  # noqa: BLE001 - preserve partial context.
                raise _package_error(
                    exc,
                    write_type="activity_evidence_link",
                    key=_evidence_link_key(evidence_record),
                    storage_result=storage_result,
                    evidence_results=evidence_results,
                    snapshot_results=snapshot_results,
                    diff_results=diff_results,
                ) from exc
        for snapshot in snapshots:
            snapshot_record = _build_snapshot_record(
                activity_id=str(record["activity_id"]),
                snapshot=snapshot,
                interaction=get_interaction_context(),
                default_project_id=record.get("project_id"),
                default_retention_policy_id=record.get("retention_policy_id"),
                default_record_scope=record_scope,
            )
            try:
                snapshot_results.append(
                    await self._write_snapshot_once(snapshot_record)
                )
            except Exception as exc:  # noqa: BLE001 - preserve partial context.
                raise _package_error(
                    exc,
                    write_type="activity_snapshot",
                    key=str(snapshot_record["snapshot_id"]),
                    storage_result=storage_result,
                    evidence_results=evidence_results,
                    snapshot_results=snapshot_results,
                    diff_results=diff_results,
                ) from exc
        for diff in diffs:
            diff_record = _build_diff_record(
                activity_id=str(record["activity_id"]),
                diff=diff,
                interaction=get_interaction_context(),
                default_project_id=record.get("project_id"),
                default_record_scope=record_scope,
            )
            try:
                diff_results.append(await self._write_diff_once(diff_record))
            except Exception as exc:  # noqa: BLE001 - preserve partial context.
                raise _package_error(
                    exc,
                    write_type="activity_diff",
                    key=str(diff_record["diff_id"]),
                    storage_result=storage_result,
                    evidence_results=evidence_results,
                    snapshot_results=snapshot_results,
                    diff_results=diff_results,
                ) from exc
        return (
            storage_result,
            tuple(evidence_results),
            tuple(snapshot_results),
            tuple(diff_results),
        )

    async def _ensure_activity_interaction(
        self,
        interaction: InteractionContext | None,
    ) -> StorageWriteResult | None:
        if interaction is None:
            return None
        record = _build_interaction_record(interaction, started_at=None)
        try:
            return await self._write_interaction_once(record)
        except Exception as exc:  # noqa: BLE001 - caller retry/fail-visibility handles it.
            _set_activity_failure_phase(exc, "interaction_ensure")
            raise

    async def _write_evidence_link_once(
        self, record: Mapping[str, Any]
    ) -> StorageWriteResult:
        write = self._storage.write_evidence_link(record)
        if self._write_timeout_seconds is None:
            return await write
        return await asyncio.wait_for(write, timeout=self._write_timeout_seconds)

    async def _write_snapshot_once(
        self, record: Mapping[str, Any]
    ) -> StorageWriteResult:
        write = self._storage.write_snapshot(record)
        if self._write_timeout_seconds is None:
            return await write
        return await asyncio.wait_for(write, timeout=self._write_timeout_seconds)

    async def _write_diff_once(self, record: Mapping[str, Any]) -> StorageWriteResult:
        write = self._storage.write_diff(record)
        if self._write_timeout_seconds is None:
            return await write
        return await asyncio.wait_for(write, timeout=self._write_timeout_seconds)

    async def _write_retention_application_once(
        self, record: Mapping[str, Any]
    ) -> StorageWriteResult:
        write = self._storage.write_retention_application(record)
        if self._write_timeout_seconds is None:
            return await write
        return await asyncio.wait_for(write, timeout=self._write_timeout_seconds)

    async def _write_purge_tombstone_once(
        self, record: Mapping[str, Any]
    ) -> StorageWriteResult:
        write = self._storage.write_purge_tombstone(record)
        if self._write_timeout_seconds is None:
            return await write
        return await asyncio.wait_for(write, timeout=self._write_timeout_seconds)

    async def _write_system_record_write_failure(
        self,
        record: Mapping[str, Any],
        error: Exception,
        *,
        operation_type: str,
        failure: RelatedWriteFailure | None = None,
        failure_phase: str,
    ) -> StorageWriteResult | None:
        safe_context = _safe_failure_context(
            record,
            operation_type=operation_type,
            error=error,
            failure=failure,
        )
        safe_context.pop("error_message", None)
        safe_context["attempt_count"] = self._max_attempts
        safe_context["failure_phase"] = failure_phase

        write_failure = {
            "failure_id": _create_activity_id(),
            "project_id": record.get("project_id"),
            "domain_area": record.get("domain_area"),
            "operation_type": operation_type,
            "safe_context": safe_context,
            "error_type": type(error).__name__,
            "error_category": _safe_error_category(error),
            "created_at": datetime.now(UTC),
        }
        try:
            return await self._storage.write_system_record_write_failure(write_failure)
        except Exception as exc:  # noqa: BLE001 - failure visibility fallback failed.
            context = _safe_failure_context(
                record,
                operation_type=operation_type,
                error=error,
                failure=failure,
            )
            context["failure_visibility_error_type"] = type(exc).__name__
            context["failure_visibility_error_category"] = _safe_error_category(exc)
            _log_failure_context(
                "activity.system_record_failure_visibility_write_failed",
                context,
            )
            return None


_default_recorder: ActivityRecorder | None = None


def set_activity_recorder(recorder: ActivityRecorder) -> None:
    """Set the process default activity recorder used by module functions."""

    global _default_recorder
    _default_recorder = recorder


def clear_activity_recorder() -> None:
    """Clear the process default activity recorder."""

    global _default_recorder
    _default_recorder = None


def get_activity_recorder() -> ActivityRecorder | None:
    """Return the process default activity recorder, if configured."""

    return _default_recorder


async def record_activity(
    *,
    taxonomy: ActivityTaxonomy,
    reconstruction: ReconstructionContent,
    interaction: InteractionContext | None = None,
    actor_override: ActorChain | None = None,
    parent_activity_id: str | None = None,
    sequence: int | None = None,
    occurred_at: datetime | None = None,
    metadata: Mapping[str, Any] | None = None,
    activity_id: str | None = None,
    record_scope: RecordScope = RecordScope.PROJECT,
    snapshots: Sequence[SnapshotRecordInput] = (),
    diffs: Sequence[DiffRecordInput] = (),
    recorder: ActivityRecorder | None = None,
) -> ActivityPublishResult:
    """Record async activity through an explicit or configured recorder."""

    return await _resolve_recorder(recorder).record_activity(
        taxonomy=taxonomy,
        reconstruction=reconstruction,
        interaction=interaction,
        actor_override=actor_override,
        parent_activity_id=parent_activity_id,
        sequence=sequence,
        occurred_at=occurred_at,
        metadata=metadata,
        activity_id=activity_id,
        record_scope=record_scope,
        snapshots=snapshots,
        diffs=diffs,
    )


async def record_critical_activity(
    *,
    taxonomy: ActivityTaxonomy,
    reconstruction: ReconstructionContent,
    interaction: InteractionContext | None = None,
    actor_override: ActorChain | None = None,
    parent_activity_id: str | None = None,
    sequence: int | None = None,
    occurred_at: datetime | None = None,
    metadata: Mapping[str, Any] | None = None,
    activity_id: str | None = None,
    record_scope: RecordScope = RecordScope.PROJECT,
    snapshots: Sequence[SnapshotRecordInput] = (),
    diffs: Sequence[DiffRecordInput] = (),
    recorder: ActivityRecorder | None = None,
) -> ActivityPublishResult:
    """Record critical activity through an explicit or configured recorder."""

    return await _resolve_recorder(recorder).record_critical_activity(
        taxonomy=taxonomy,
        reconstruction=reconstruction,
        interaction=interaction,
        actor_override=actor_override,
        parent_activity_id=parent_activity_id,
        sequence=sequence,
        occurred_at=occurred_at,
        metadata=metadata,
        activity_id=activity_id,
        record_scope=record_scope,
        snapshots=snapshots,
        diffs=diffs,
    )


async def record_snapshot(
    *,
    activity_id: str,
    target: TargetRef,
    domain_area: DomainArea,
    snapshot_kind: str,
    snapshot_payload: Mapping[str, Any],
    project_id: str | None = None,
    retention_policy_id: str | None = None,
    retention_expires_at: datetime | None = None,
    snapshot_id: str | None = None,
    record_scope: RecordScope = RecordScope.PROJECT,
    recorder: ActivityRecorder | None = None,
) -> SnapshotRecordResult:
    """Record a reconstruction snapshot through an explicit or configured recorder."""

    return await _resolve_recorder(recorder).record_snapshot(
        activity_id=activity_id,
        target=target,
        domain_area=domain_area,
        snapshot_kind=snapshot_kind,
        snapshot_payload=snapshot_payload,
        project_id=project_id,
        retention_policy_id=retention_policy_id,
        retention_expires_at=retention_expires_at,
        snapshot_id=snapshot_id,
        record_scope=record_scope,
    )


async def record_diff(
    *,
    activity_id: str,
    target: TargetRef,
    domain_area: DomainArea,
    diff_payload: Mapping[str, Any],
    project_id: str | None = None,
    diff_id: str | None = None,
    record_scope: RecordScope = RecordScope.PROJECT,
    recorder: ActivityRecorder | None = None,
) -> DiffRecordResult:
    """Record a reconstruction diff through an explicit or configured recorder."""

    return await _resolve_recorder(recorder).record_diff(
        activity_id=activity_id,
        target=target,
        domain_area=domain_area,
        diff_payload=diff_payload,
        project_id=project_id,
        diff_id=diff_id,
        record_scope=record_scope,
    )


async def record_retention_application(
    *,
    activity_id: str,
    retention_policy_id: str,
    domain_area: DomainArea,
    target: TargetRef,
    action_taken: str,
    project_id: str | None = None,
    application_id: str | None = None,
    applied_at: datetime | None = None,
    metadata: Mapping[str, Any] | None = None,
    record_scope: RecordScope = RecordScope.PROJECT,
    recorder: ActivityRecorder | None = None,
) -> RetentionApplicationRecordResult:
    """Record a retention application through an explicit or configured recorder."""

    return await _resolve_recorder(recorder).record_retention_application(
        activity_id=activity_id,
        retention_policy_id=retention_policy_id,
        domain_area=domain_area,
        target=target,
        action_taken=action_taken,
        project_id=project_id,
        application_id=application_id,
        applied_at=applied_at,
        metadata=metadata,
        record_scope=record_scope,
    )


async def record_purge_tombstone(
    *,
    activity_id: str,
    domain_area: DomainArea,
    target: TargetRef,
    purge_reason: str,
    purge_scope: str,
    initiated_by: Mapping[str, Any],
    purged_evidence_classes: Sequence[str],
    project_id: str | None = None,
    purge_tombstone_id: str | None = None,
    retention_policy_id: str | None = None,
    record_scope: RecordScope = RecordScope.PROJECT,
    recorder: ActivityRecorder | None = None,
) -> PurgeTombstoneRecordResult:
    """Record a safe purge tombstone through an explicit or configured recorder."""

    return await _resolve_recorder(recorder).record_purge_tombstone(
        activity_id=activity_id,
        domain_area=domain_area,
        target=target,
        purge_reason=purge_reason,
        purge_scope=purge_scope,
        initiated_by=initiated_by,
        purged_evidence_classes=purged_evidence_classes,
        project_id=project_id,
        purge_tombstone_id=purge_tombstone_id,
        retention_policy_id=retention_policy_id,
        record_scope=record_scope,
    )


def _resolve_recorder(recorder: ActivityRecorder | None) -> ActivityRecorder:
    resolved = recorder or _default_recorder
    if resolved is None:
        raise ActivityRecorderError("No activity recorder configured")
    return resolved


def _build_snapshot_record(
    *,
    activity_id: str,
    snapshot: SnapshotRecordInput,
    interaction: InteractionContext | None,
    default_project_id: Any,
    default_retention_policy_id: Any,
    default_record_scope: RecordScope,
) -> dict[str, Any]:
    if not activity_id.strip():
        raise ActivityRecorderError("Snapshot activity_id is required")
    if not snapshot.snapshot_kind.strip():
        raise ActivityRecorderError("Snapshot snapshot_kind is required")
    if _contains_raw_payload_key(snapshot.snapshot_payload):
        raise ActivityRecorderError("Raw payload fields are not allowed by default")

    project_id = snapshot.project_id or _string_or_none(default_project_id)
    if project_id is None and interaction:
        project_id = interaction.project_id
    record_scope = interaction.record_scope if interaction else snapshot.record_scope
    if record_scope is RecordScope.PROJECT:
        record_scope = default_record_scope
    validate_record_project_scope(
        record_type="activity_snapshot",
        project_id=project_id,
        record_scope=record_scope,
    )
    snapshot_payload = dict(snapshot.snapshot_payload)
    retention_policy_id = (
        snapshot.retention_policy_id
        or _string_or_none(default_retention_policy_id)
        or (interaction.retention_policy_id if interaction else None)
    )
    return {
        "snapshot_id": snapshot.snapshot_id or _create_activity_id(),
        "activity_id": activity_id,
        "project_id": project_id,
        "domain_area": snapshot.domain_area.value,
        "target_type": snapshot.target.target_type,
        "target_id": snapshot.target.target_id,
        "snapshot_kind": snapshot.snapshot_kind,
        "snapshot_payload": snapshot_payload,
        "payload_hash": _payload_hash(snapshot_payload),
        "retention_policy_id": retention_policy_id,
        "retention_expires_at": snapshot.retention_expires_at,
    }


def _build_diff_record(
    *,
    activity_id: str,
    diff: DiffRecordInput,
    interaction: InteractionContext | None,
    default_project_id: Any,
    default_record_scope: RecordScope,
) -> dict[str, Any]:
    if not activity_id.strip():
        raise ActivityRecorderError("Diff activity_id is required")
    if _contains_raw_payload_key(diff.diff_payload):
        raise ActivityRecorderError("Raw payload fields are not allowed by default")

    project_id = diff.project_id or _string_or_none(default_project_id)
    if project_id is None and interaction:
        project_id = interaction.project_id
    record_scope = interaction.record_scope if interaction else diff.record_scope
    if record_scope is RecordScope.PROJECT:
        record_scope = default_record_scope
    validate_record_project_scope(
        record_type="activity_diff",
        project_id=project_id,
        record_scope=record_scope,
    )
    diff_payload = dict(diff.diff_payload)
    return {
        "diff_id": diff.diff_id or _create_activity_id(),
        "activity_id": activity_id,
        "project_id": project_id,
        "domain_area": diff.domain_area.value,
        "target_type": diff.target.target_type,
        "target_id": diff.target.target_id,
        "diff_payload": diff_payload,
        "payload_hash": _payload_hash(diff_payload),
    }


def _build_retention_application_record(
    application: RetentionApplicationInput,
    *,
    interaction: InteractionContext | None,
) -> dict[str, Any]:
    if not application.activity_id.strip():
        raise ActivityRecorderError("Retention application activity_id is required")
    if not application.retention_policy_id.strip():
        raise ActivityRecorderError(
            "Retention application retention_policy_id is required"
        )
    if not application.action_taken.strip():
        raise ActivityRecorderError("Retention application action_taken is required")
    _validate_safe_target(application.target, record_type="retention_application")
    if _contains_raw_payload_key(application.metadata or {}):
        raise ActivityRecorderError("Raw payload fields are not allowed by default")

    project_id = _resolve_project_id(application.project_id, interaction)
    validate_record_project_scope(
        record_type="retention_application",
        project_id=project_id,
        record_scope=_resolve_record_scope(application.record_scope, interaction),
    )
    metadata = dict(application.metadata) if application.metadata else None
    return {
        "application_id": application.application_id or _create_activity_id(),
        "retention_policy_id": application.retention_policy_id,
        "activity_id": application.activity_id,
        "project_id": project_id,
        "domain_area": _domain_area_value(
            application.domain_area,
            record_type="retention_application",
        ),
        "target_type": application.target.target_type,
        "target_id": application.target.target_id,
        "action_taken": application.action_taken,
        "applied_at": application.applied_at or datetime.now(UTC),
        "metadata": metadata,
    }


def _build_purge_tombstone_record(
    tombstone: PurgeTombstoneInput,
    *,
    interaction: InteractionContext | None,
) -> dict[str, Any]:
    if not tombstone.activity_id.strip():
        raise ActivityRecorderError("Purge tombstone activity_id is required")
    if not tombstone.purge_reason.strip():
        raise ActivityRecorderError("Purge tombstone purge_reason is required")
    if not tombstone.purge_scope.strip():
        raise ActivityRecorderError("Purge tombstone purge_scope is required")
    _validate_safe_target(tombstone.target, record_type="purge_tombstone")
    _validate_initiated_by(tombstone.initiated_by)
    if isinstance(tombstone.purged_evidence_classes, (str, bytes)):
        raise ActivityRecorderError(
            "Purge tombstone purged_evidence_classes must be a sequence"
        )
    purged_evidence_classes = [
        str(evidence_class) for evidence_class in tombstone.purged_evidence_classes
    ]
    if not purged_evidence_classes or any(
        not evidence_class.strip() for evidence_class in purged_evidence_classes
    ):
        raise ActivityRecorderError(
            "Purge tombstone purged_evidence_classes is required"
        )

    project_id = _resolve_project_id(tombstone.project_id, interaction)
    validate_record_project_scope(
        record_type="purge_tombstone",
        project_id=project_id,
        record_scope=_resolve_record_scope(tombstone.record_scope, interaction),
    )
    initiated_by = dict(tombstone.initiated_by)
    return {
        "purge_tombstone_id": tombstone.purge_tombstone_id or _create_activity_id(),
        "activity_id": tombstone.activity_id,
        "project_id": project_id,
        "domain_area": _domain_area_value(
            tombstone.domain_area,
            record_type="purge_tombstone",
        ),
        "target_type": tombstone.target.target_type,
        "target_id": tombstone.target.target_id,
        "purge_reason": tombstone.purge_reason,
        "purge_scope": tombstone.purge_scope,
        "initiated_by": initiated_by,
        "retention_policy_id": tombstone.retention_policy_id,
        "purged_evidence_classes": purged_evidence_classes,
    }


def _build_activity_record(
    *,
    activity_id: str,
    taxonomy: ActivityTaxonomy,
    reconstruction: ReconstructionContent,
    interaction: InteractionContext | None,
    actor_override: ActorChain | None,
    parent_activity_id: str | None,
    sequence: int | None,
    occurred_at: datetime | None,
    metadata: Mapping[str, Any] | None,
    record_scope: RecordScope,
) -> dict[str, Any]:
    _validate_activity_input(taxonomy, reconstruction, metadata)

    record_metadata = dict(reconstruction.metadata)
    record_metadata.update(metadata or {})
    resolved_project_id = interaction.project_id if interaction else None
    resolved_scope = validate_record_project_scope(
        record_type="activity_record",
        project_id=resolved_project_id,
        record_scope=interaction.record_scope if interaction else record_scope,
    )
    record_metadata.setdefault("record_scope", resolved_scope.value)
    if interaction:
        _add_if_present(record_metadata, "correlation_id", interaction.correlation_id)
        _add_if_present(record_metadata, "trace_id", interaction.trace_id)
        _add_if_present(record_metadata, "source_agent_id", interaction.source_agent_id)
        _add_if_present(record_metadata, "root_agent_id", interaction.root_agent_id)
        _add_if_present(
            record_metadata,
            "source_entry_point",
            interaction.source_entry_point,
        )
        if interaction.provenance:
            record_metadata.setdefault(
                "context_provenance", interaction.provenance.to_dict()
            )
        if interaction.observed_context:
            record_metadata.setdefault(
                "observed_context", interaction.observed_context.to_dict()
            )
    if sequence is not None:
        record_metadata.setdefault("sequence", sequence)

    return {
        "activity_id": activity_id,
        "interaction_id": interaction.interaction_id if interaction else None,
        "parent_activity_id": parent_activity_id
        or (interaction.parent_activity_id if interaction else None),
        "project_id": resolved_project_id,
        "domain_area": taxonomy.domain_area.value,
        "target_type": taxonomy.target_type,
        "target_id": reconstruction.primary_target.target_id,
        "action_family": taxonomy.action_family.value,
        "action": taxonomy.action,
        "lifecycle_phase": taxonomy.lifecycle_phase.value,
        "outcome": taxonomy.outcome.value,
        "durability": taxonomy.durability.value,
        "evidence_class": taxonomy.evidence_class.value
        if taxonomy.evidence_class
        else None,
        "event_label": taxonomy.event_label,
        "primary_target": reconstruction.primary_target.to_dict(),
        "related_targets": [
            target.to_dict() for target in reconstruction.related_targets
        ]
        or None,
        "actor_override": actor_override.to_dict() if actor_override else None,
        "reconstruction_refs": _reconstruction_refs(reconstruction),
        "metadata": record_metadata or None,
        "retention_policy_id": interaction.retention_policy_id if interaction else None,
        "retention_expires_at": None,
        "occurred_at": occurred_at or datetime.now(UTC),
    }


def _build_evidence_link_record(
    activity_record: Mapping[str, Any],
    evidence: EvidenceRef,
) -> dict[str, Any]:
    if _contains_raw_payload_key(evidence.ref):
        raise ActivityRecorderError("Raw payload fields are not allowed by default")
    return {
        "activity_id": activity_record["activity_id"],
        "project_id": activity_record.get("project_id"),
        "domain_area": evidence.domain_area.value,
        "evidence_type": evidence.evidence_type,
        "evidence_id": evidence.evidence_id,
        "evidence_ref": dict(evidence.ref),
        "content_hash": evidence.content_hash,
        "metadata_hash": evidence.metadata_hash,
    }


def _build_interaction_record(
    context: InteractionContext,
    *,
    started_at: datetime | None,
) -> dict[str, Any]:
    resolved_scope = validate_record_project_scope(
        record_type="interaction_record",
        project_id=context.project_id,
        record_scope=context.record_scope,
    )
    collapse_metadata: dict[str, Any] = {}
    collapse_metadata["record_scope"] = resolved_scope.value
    _add_if_present(collapse_metadata, "correlation_id", context.correlation_id)
    _add_if_present(collapse_metadata, "trace_id", context.trace_id)
    _add_if_present(collapse_metadata, "source_agent_id", context.source_agent_id)
    _add_if_present(collapse_metadata, "parent_activity_id", context.parent_activity_id)
    if context.provenance:
        collapse_metadata.setdefault("context_provenance", context.provenance.to_dict())
    if context.observed_context:
        collapse_metadata.setdefault(
            "observed_context", context.observed_context.to_dict()
        )

    return {
        "interaction_id": context.interaction_id,
        "interaction_type": context.interaction_type.value,
        "project_id": context.project_id,
        "domain_area": context.domain_area.value if context.domain_area else None,
        "caller_summary": context.caller.to_dict() if context.caller else None,
        "default_actor_chain": ActorChain(caller=context.caller).to_dict()
        if context.caller
        else None,
        "root_agent_id": context.root_agent_id,
        "source_entry_point": context.source_entry_point,
        "retention_policy_id": context.retention_policy_id,
        "collapse_metadata": collapse_metadata or None,
        "started_at": started_at or datetime.now(UTC),
    }


def _validate_activity_input(
    taxonomy: ActivityTaxonomy,
    reconstruction: ReconstructionContent,
    metadata: Mapping[str, Any] | None,
) -> None:
    if not taxonomy.action.strip():
        raise ActivityRecorderError("Activity action is required")
    if not taxonomy.event_label.strip():
        raise ActivityRecorderError("Activity event_label is required")
    if taxonomy.target_type != reconstruction.primary_target.target_type:
        raise ActivityRecorderError("Taxonomy target_type must match primary_target")
    if _contains_raw_payload_key(reconstruction.to_dict()) or _contains_raw_payload_key(
        metadata or {}
    ):
        raise ActivityRecorderError("Raw payload fields are not allowed by default")


def _validate_safe_target(target: TargetRef, *, record_type: str) -> None:
    if not target.target_type.strip():
        raise ActivityRecorderError(f"{record_type} target_type is required")
    if not target.target_id.strip():
        raise ActivityRecorderError(f"{record_type} target_id is required")
    if _contains_raw_payload_key(target.to_dict()):
        raise ActivityRecorderError("Raw payload fields are not allowed by default")


def _domain_area_value(domain_area: DomainArea | None, *, record_type: str) -> str:
    if domain_area is None:
        raise ActivityRecorderError(f"{record_type} domain_area is required")
    return domain_area.value


def _validate_initiated_by(initiated_by: Mapping[str, Any]) -> None:
    if not initiated_by:
        raise ActivityRecorderError("Purge tombstone initiated_by is required")
    if not str(initiated_by.get("actor_type", "")).strip():
        raise ActivityRecorderError(
            "Purge tombstone initiated_by.actor_type is required"
        )
    if not str(initiated_by.get("actor_id", "")).strip():
        raise ActivityRecorderError("Purge tombstone initiated_by.actor_id is required")
    if _contains_raw_payload_key(initiated_by):
        raise ActivityRecorderError("Raw payload fields are not allowed by default")


def _reconstruction_refs(
    reconstruction: ReconstructionContent,
) -> dict[str, Any] | None:
    refs = {
        "snapshot_ref": reconstruction.snapshot_ref,
        "diff_ref": reconstruction.diff_ref,
        "version_refs": list(reconstruction.version_refs) or None,
    }
    filtered = {key: value for key, value in refs.items() if value is not None}
    return filtered or None


def _contains_raw_payload_key(value: Any) -> bool:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if str(key).lower() in RAW_PAYLOAD_KEYS:
                return True
            if _contains_raw_payload_key(item):
                return True
    elif isinstance(value, (list, tuple)):
        return any(_contains_raw_payload_key(item) for item in value)
    return False


def _payload_hash(payload: Mapping[str, Any]) -> str:
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return f"sha256:{hashlib.sha256(serialized.encode('utf-8')).hexdigest()}"


def _package_error(
    error: Exception,
    *,
    write_type: str,
    key: str,
    storage_result: StorageWriteResult,
    evidence_results: Sequence[StorageWriteResult],
    snapshot_results: Sequence[StorageWriteResult],
    diff_results: Sequence[StorageWriteResult],
) -> ActivityPackageWriteError:
    failure = RelatedWriteFailure(
        write_type=write_type,
        key=key,
        error_type=type(error).__name__,
        error_message=str(error),
    )
    return ActivityPackageWriteError(
        f"Activity package related write failed: {write_type} {key}: {error}",
        failure=failure,
        storage_result=storage_result,
        evidence_results=evidence_results,
        snapshot_results=snapshot_results,
        diff_results=diff_results,
    )


def _log_system_record_failure(
    event_name: str,
    record: Mapping[str, Any],
    *,
    operation_type: str,
    error: Exception,
    failure: RelatedWriteFailure | None = None,
    failure_visible: bool | None = None,
) -> None:
    context = _safe_failure_context(
        record,
        operation_type=operation_type,
        error=error,
        failure=failure,
    )
    if failure_visible is not None:
        context["failure_visible"] = failure_visible
    _log_failure_context(event_name, context)


def _log_failure_context(event_name: str, context: Mapping[str, Any]) -> None:
    logger.error(
        "%s %s",
        event_name,
        json.dumps(context, sort_keys=True, default=str),
        extra=dict(context),
    )


def _safe_failure_context(
    record: Mapping[str, Any],
    *,
    operation_type: str,
    error: Exception,
    failure: RelatedWriteFailure | None = None,
) -> dict[str, Any]:
    context: dict[str, Any] = {
        "operation_type": operation_type,
        "severity": "severe",
        "error_type": type(error).__name__,
        "error_category": _safe_error_category(error),
        "error_message": _safe_error_message(error),
    }
    for key in (
        "activity_id",
        "interaction_id",
        "project_id",
        "domain_area",
        "action_family",
        "action",
        "durability",
    ):
        value = record.get(key)
        if value is not None:
            context[key] = value
    if failure is not None:
        context["failed_related_write_type"] = failure.write_type
        context["failed_related_write_key"] = failure.key
        context["failed_related_error_type"] = failure.error_type
    return context


def _safe_error_message(error: Exception) -> str:
    if str(error):
        return _REDACTED_LOG_ERROR_MESSAGE
    return ""


def _safe_error_category(error: Exception) -> str:
    if isinstance(error, (TimeoutError, asyncio.TimeoutError)):
        return "timeout"
    if isinstance(error, ActivityStorageConflictError):
        return "conflict"
    if isinstance(error, ActivityStorageError):
        return "storage"
    if isinstance(error, ActivityRecorderError):
        return "recorder"
    return "unexpected"


def _set_activity_failure_phase(error: Exception, failure_phase: str) -> None:
    try:
        setattr(error, "_taproot_activity_failure_phase", failure_phase)
    except Exception:  # noqa: BLE001 - failure tagging must never mask the error.
        return


def _activity_failure_phase(error: Exception, *, default: str) -> str:
    return str(getattr(error, "_taproot_activity_failure_phase", default))


def _evidence_link_key(record: Mapping[str, Any]) -> str:
    return ":".join(
        str(record.get(key, ""))
        for key in ("activity_id", "evidence_type", "evidence_id")
    )


def _string_or_none(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _resolve_project_id(
    project_id: str | None,
    interaction: InteractionContext | None,
) -> str | None:
    return project_id or (interaction.project_id if interaction else None)


def _resolve_record_scope(
    record_scope: RecordScope,
    interaction: InteractionContext | None,
) -> RecordScope:
    return interaction.record_scope if interaction else record_scope


def _record_scope_from_activity_record(
    record: Mapping[str, Any], default: RecordScope
) -> RecordScope:
    metadata = record.get("metadata")
    if isinstance(metadata, Mapping):
        value = metadata.get("record_scope")
        if value:
            return RecordScope(str(value))
    return default


def _add_if_present(target: dict[str, Any], key: str, value: Any) -> None:
    if value is not None:
        target.setdefault(key, value)


def _create_activity_id() -> str:
    return str(uuid4())
