"""Shared activity recording APIs for TAP-38."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from taproot_common.activity.context import get_interaction_context
from taproot_common.activity.models import (
    ActionFamily,
    ActorChain,
    ActivityTaxonomy,
    Durability,
    InteractionContext,
    ReconstructionContent,
)
from taproot_common.activity.storage import (
    ActivityStorageAdapter,
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


@dataclass(frozen=True)
class ActivityPublishResult:
    """Result returned after activity publication is accepted or dead-lettered."""

    activity_id: str
    durability: Durability
    accepted: bool
    attempts: int
    storage_result: StorageWriteResult | None = None
    dead_lettered: bool = False
    dead_letter_result: StorageWriteResult | None = None
    error_type: str | None = None
    error_message: str | None = None


@dataclass(frozen=True)
class InteractionRecordResult:
    """Result returned after interaction record publication is attempted."""

    interaction_id: str
    accepted: bool
    attempts: int
    storage_result: StorageWriteResult | None = None
    dead_lettered: bool = False
    dead_letter_result: StorageWriteResult | None = None
    error_type: str | None = None
    error_message: str | None = None


class ActivityRecorderError(RuntimeError):
    """Raised when activity recording cannot satisfy caller semantics."""


class ActivityRecorder:
    """Records TAP-38 activity through an activity storage Adapter."""

    def __init__(
        self,
        storage: ActivityStorageAdapter,
        *,
        max_attempts: int = 3,
        retry_delay_seconds: float = 0.0,
        write_timeout_seconds: float | None = 5.0,
        max_concurrent_writes: int = 10,
    ) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        if max_concurrent_writes < 1:
            raise ValueError("max_concurrent_writes must be at least 1")

        self._storage = storage
        self._max_attempts = max_attempts
        self._retry_delay_seconds = retry_delay_seconds
        self._write_timeout_seconds = write_timeout_seconds
        self._semaphore = asyncio.Semaphore(max_concurrent_writes)

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
            dead_letter_result = await self._write_dead_letter(
                record,
                exc,
                operation_type="interaction_record",
            )
            return InteractionRecordResult(
                interaction_id=context.interaction_id,
                accepted=False,
                attempts=self._max_attempts,
                dead_lettered=dead_letter_result is not None,
                dead_letter_result=dead_letter_result,
                error_type=type(exc).__name__,
                error_message=str(exc),
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
    ) -> ActivityPublishResult:
        """Record non-critical activity with bounded retry and dead-letter fallback."""

        if taxonomy.durability != Durability.ASYNC:
            raise ActivityRecorderError("record_activity requires async durability")

        resolved_activity_id = activity_id or _create_activity_id()
        record = _build_activity_record(
            activity_id=resolved_activity_id,
            taxonomy=taxonomy,
            reconstruction=reconstruction,
            interaction=interaction or get_interaction_context(),
            actor_override=actor_override,
            parent_activity_id=parent_activity_id,
            sequence=sequence,
            occurred_at=occurred_at,
            metadata=metadata,
        )

        try:
            storage_result, attempts = await self._write_activity_with_retry(record)
        except Exception as exc:  # noqa: BLE001 - non-critical path records failures.
            dead_letter_result = await self._write_dead_letter(
                record,
                exc,
                operation_type="activity_record",
            )
            return ActivityPublishResult(
                activity_id=resolved_activity_id,
                durability=taxonomy.durability,
                accepted=False,
                attempts=self._max_attempts,
                dead_lettered=dead_letter_result is not None,
                dead_letter_result=dead_letter_result,
                error_type=type(exc).__name__,
                error_message=str(exc),
            )

        return ActivityPublishResult(
            activity_id=resolved_activity_id,
            durability=taxonomy.durability,
            accepted=True,
            attempts=attempts,
            storage_result=storage_result,
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
        record = _build_activity_record(
            activity_id=resolved_activity_id,
            taxonomy=taxonomy,
            reconstruction=reconstruction,
            interaction=interaction or get_interaction_context(),
            actor_override=actor_override,
            parent_activity_id=parent_activity_id,
            sequence=sequence,
            occurred_at=occurred_at,
            metadata=metadata,
        )
        storage_result = await self._write_activity_once(record)

        return ActivityPublishResult(
            activity_id=resolved_activity_id,
            durability=taxonomy.durability,
            accepted=True,
            attempts=1,
            storage_result=storage_result,
        )

    async def _write_activity_with_retry(
        self, record: Mapping[str, Any]
    ) -> tuple[StorageWriteResult, int]:
        last_error: Exception | None = None
        for attempt in range(1, self._max_attempts + 1):
            try:
                return await self._write_activity_once(record), attempt
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
        async with self._semaphore:
            write = self._storage.write_interaction_record(record)
            if self._write_timeout_seconds is None:
                return await write
            return await asyncio.wait_for(write, timeout=self._write_timeout_seconds)

    async def _write_activity_once(
        self, record: Mapping[str, Any]
    ) -> StorageWriteResult:
        async with self._semaphore:
            write = self._storage.write_activity_record(record)
            if self._write_timeout_seconds is None:
                return await write
            return await asyncio.wait_for(write, timeout=self._write_timeout_seconds)

    async def _write_dead_letter(
        self,
        record: Mapping[str, Any],
        error: Exception,
        *,
        operation_type: str,
    ) -> StorageWriteResult | None:
        dead_letter = {
            "dead_letter_id": _create_activity_id(),
            "project_id": record.get("project_id"),
            "domain_area": record.get("domain_area"),
            "operation_type": operation_type,
            "payload": dict(record),
            "error_type": type(error).__name__,
            "error_message": str(error),
            "attempt_count": self._max_attempts,
            "status": "pending",
        }
        try:
            return await self._storage.write_dead_letter(dead_letter)
        except Exception:
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
    )


def _resolve_recorder(recorder: ActivityRecorder | None) -> ActivityRecorder:
    resolved = recorder or _default_recorder
    if resolved is None:
        raise ActivityRecorderError("No activity recorder configured")
    return resolved


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
) -> dict[str, Any]:
    _validate_activity_input(taxonomy, reconstruction, metadata)

    record_metadata = dict(reconstruction.metadata)
    record_metadata.update(metadata or {})
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
        "project_id": interaction.project_id if interaction else None,
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


def _build_interaction_record(
    context: InteractionContext,
    *,
    started_at: datetime | None,
) -> dict[str, Any]:
    collapse_metadata: dict[str, Any] = {}
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


def _reconstruction_refs(
    reconstruction: ReconstructionContent,
) -> dict[str, Any] | None:
    refs = {
        "snapshot_ref": reconstruction.snapshot_ref,
        "diff_ref": reconstruction.diff_ref,
        "version_refs": list(reconstruction.version_refs) or None,
        "evidence_refs": [
            evidence.to_dict() for evidence in reconstruction.evidence_refs
        ]
        or None,
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


def _add_if_present(target: dict[str, Any], key: str, value: Any) -> None:
    if value is not None:
        target.setdefault(key, value)


def _create_activity_id() -> str:
    return str(uuid4())
