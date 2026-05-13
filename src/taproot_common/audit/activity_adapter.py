"""Compatibility Adapter from legacy audit events to TAP-38 activity records."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

from taproot_common.activity import (
    ActionFamily,
    ActivityRecorder,
    ActivityTaxonomy,
    ActorRef,
    DomainArea,
    Durability,
    EvidenceClass,
    InteractionContext,
    InteractionType,
    LifecyclePhase,
    Outcome,
    ReconstructionContent,
    TargetRef,
    create_interaction_id,
    get_interaction_context,
)
from taproot_common.activity.recorder import RAW_PAYLOAD_KEYS
from taproot_common.audit.models import AuditEvent


class ActivityAuditPublisher:
    """Publishes legacy audit events through the TAP-38 activity recorder."""

    def __init__(self, recorder: ActivityRecorder) -> None:
        self._recorder = recorder

    async def publish(self, event: AuditEvent) -> None:
        taxonomy = ActivityTaxonomy(
            domain_area=_domain_area_from_service(event.service),
            target_type=_target_type(event.entity_type),
            action_family=_action_family_from_audit_action(event.action),
            action=_action_name(event.action),
            lifecycle_phase=LifecyclePhase.COMPLETED,
            outcome=Outcome.SUCCEEDED,
            durability=Durability.ASYNC,
            event_label=_event_label(event.action, event.entity_type),
            evidence_class=EvidenceClass.VERSIONED_RESOURCE,
        )
        reconstruction = ReconstructionContent(
            primary_target=TargetRef(
                target_type=taxonomy.target_type,
                target_id=event.entity_id or "unknown",
            ),
            metadata=_legacy_metadata(event),
        )
        await self._recorder.record_activity(
            taxonomy=taxonomy,
            reconstruction=reconstruction,
            interaction=_interaction_context_for_event(event, taxonomy.domain_area),
            occurred_at=_parse_timestamp(event.timestamp),
        )

    async def publish_batch(self, events: list[AuditEvent]) -> None:
        for event in events:
            await self.publish(event)

    async def close(self) -> None:
        pass


def _domain_area_from_service(service: str) -> DomainArea:
    normalized = service.lower().replace("_", "-")
    if "retrieval" in normalized:
        return DomainArea.RETRIEVAL
    if "prompt" in normalized:
        return DomainArea.PROMPT
    if "guardrail" in normalized:
        return DomainArea.GUARDRAIL
    if "eval" in normalized:
        return DomainArea.EVALS
    if "toolbox" in normalized or "tool-box" in normalized:
        return DomainArea.TOOLBOX
    if "worker" in normalized:
        return DomainArea.WORKER
    if "front" in normalized:
        return DomainArea.FRONT
    if "sdk" in normalized:
        return DomainArea.SDK
    return DomainArea.COMMON


def _action_family_from_audit_action(action: str) -> ActionFamily:
    normalized = action.upper()
    action_map = {
        "CREATE": ActionFamily.CREATE,
        "UPDATE": ActionFamily.UPDATE,
        "DELETE": ActionFamily.DELETE,
        "APPROVE": ActionFamily.APPROVE,
        "REJECT": ActionFamily.REJECT,
        "ACCESS": ActionFamily.ACCESS,
        "INVOKE": ActionFamily.INVOKE,
        "ENABLE_SUPPORT": ActionFamily.ACCESS,
        "DISABLE_SUPPORT": ActionFamily.ACCESS,
        "ENABLE_DEBUG": ActionFamily.ACCESS,
        "DISABLE_DEBUG": ActionFamily.ACCESS,
    }
    return action_map.get(normalized, ActionFamily.UPDATE)


def _interaction_context_for_event(
    event: AuditEvent, domain_area: DomainArea
) -> InteractionContext:
    current = get_interaction_context()
    if current is not None:
        if current.project_id is None and event.tenant_id:
            return replace(
                current,
                project_id=event.tenant_id,
                domain_area=current.domain_area or domain_area,
            )
        return current

    return InteractionContext(
        interaction_id=create_interaction_id(),
        interaction_type=InteractionType.SERVICE_REQUEST,
        project_id=event.tenant_id,
        domain_area=domain_area,
        caller=ActorRef(actor_type="legacy_audit_actor", actor_id=event.performed_by),
        source_agent_id=event.agent_id,
        root_agent_id=event.agent_id,
        source_entry_point="legacy_audit.publish_audit_event",
        correlation_id=event.correlation_id,
        trace_id=event.trace_id,
    )


def _legacy_metadata(event: AuditEvent) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "compatibility_adapter": "legacy_audit",
        "legacy_service": event.service,
        "legacy_action": event.action,
        "legacy_entity_type": event.entity_type,
        "legacy_performed_by": event.performed_by,
    }
    _add_if_present(metadata, "legacy_changed_fields", event.changed_fields)
    _add_if_present(metadata, "legacy_source_ip", event.source_ip)
    _add_if_present(metadata, "legacy_transaction_id", event.transaction_id)
    _add_if_present(metadata, "legacy_old_value_hash", _json_hash(event.old_value))
    _add_if_present(metadata, "legacy_new_value_hash", _json_hash(event.new_value))
    safe_metadata = _safe_mapping(event.metadata or {})
    if safe_metadata:
        metadata["legacy_metadata"] = safe_metadata
    return metadata


def _safe_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    for key, item in value.items():
        if str(key).lower() in RAW_PAYLOAD_KEYS:
            continue
        safe[key] = _safe_value(item)
    return safe


def _safe_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return _safe_mapping(value)
    if isinstance(value, list):
        return [_safe_value(item) for item in value]
    return value


def _json_hash(value: Mapping[str, Any] | None) -> str | None:
    if value is None:
        return None
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return f"sha256:{hashlib.sha256(payload.encode()).hexdigest()}"


def _parse_timestamp(timestamp: str | None) -> datetime | None:
    if not timestamp:
        return None
    try:
        return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(UTC)


def _target_type(entity_type: str) -> str:
    return entity_type.strip().lower() or "unknown"


def _action_name(action: str) -> str:
    return action.strip().lower() or "legacy_audit_action"


def _event_label(action: str, entity_type: str) -> str:
    return f"{action.replace('_', ' ').title()} {entity_type.replace('_', ' ').title()}".strip()


def _add_if_present(target: dict[str, Any], key: str, value: Any) -> None:
    if value is not None:
        target[key] = value
