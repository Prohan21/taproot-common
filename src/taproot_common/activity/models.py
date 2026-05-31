"""Activity domain models for Taproot system-of-record activity.

These models intentionally have no storage dependency. Services use them to
describe interaction context, actor chains, activity taxonomy, targets, and
reconstruction references before later layers decide how to persist records.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Mapping, Sequence, TypeVar


ACTIVITY_SCHEMA_VERSION = 1
ACTIVITY_HEADER_VERSION = 1


class DomainArea(StrEnum):
    """Service ownership area for activity filtering and retention."""

    RETRIEVAL = "retrieval"
    PROMPT = "prompt"
    GUARDRAIL = "guardrail"
    EVALS = "evals"
    TOOLBOX = "toolbox"
    WORKER = "worker"
    FRONT = "front"
    SDK = "sdk"
    COMMON = "common"


class InteractionType(StrEnum):
    """Externally meaningful workflow type."""

    AGENT_RUN = "agent_run"
    ADMIN_ACTION = "admin_action"
    SDK_OPERATION = "sdk_operation"
    SERVICE_REQUEST = "service_request"
    WEBHOOK = "webhook"
    BACKGROUND_JOB = "background_job"
    SUPPORT_ACTION = "support_action"
    RETENTION_JOB = "retention_job"


class ActionFamily(StrEnum):
    """Shared broad action family used for cross-service filtering."""

    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    RESTORE = "restore"
    PURGE = "purge"
    APPROVE = "approve"
    REJECT = "reject"
    INVOKE = "invoke"
    QUERY = "query"
    RESOLVE = "resolve"
    BLOCK = "block"
    RETAIN = "retain"
    ACCESS = "access"
    EXECUTE = "execute"
    PUBLISH = "publish"
    IMPORT = "import"
    EXPORT = "export"


class LifecyclePhase(StrEnum):
    """Timeline phase for every activity record."""

    REQUESTED = "requested"
    ACCEPTED = "accepted"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELED = "canceled"
    EXPIRED = "expired"


class Outcome(StrEnum):
    """Result of the activity phase."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    BLOCKED = "blocked"
    REJECTED = "rejected"
    NO_OP = "no_op"
    PARTIAL = "partial"
    PENDING = "pending"


class Durability(StrEnum):
    """Activity publication durability tier."""

    CRITICAL = "critical"
    ASYNC = "async"


class RecordScope(StrEnum):
    """Project isolation scope for system-record rows."""

    PROJECT = "project"
    SYSTEM = "system"


class ProjectIsolationError(ValueError):
    """Raised when a system-record row has an invalid project scope."""


class EvidenceClass(StrEnum):
    """Broad evidence shape attached to activity."""

    SNAPSHOT = "snapshot"
    DIFF = "diff"
    VERSIONED_RESOURCE = "versioned_resource"
    DECISION = "decision"
    TRACE = "trace"
    INVOCATION = "invocation"
    QUERY_RESULT = "query_result"
    RETENTION_RECORD = "retention_record"
    PURGE_TOMBSTONE = "purge_tombstone"
    NONE = "none"


def validate_record_project_scope(
    *,
    record_type: str,
    project_id: str | None,
    record_scope: RecordScope | str,
) -> RecordScope:
    """Validate the TAP-38 tenant/project isolation contract.

    Customer-owned records are project-scoped and must carry ``project_id``.
    Global platform/system records are represented explicitly with
    ``record_scope=system`` and no ``project_id``; ``tenant_id`` is deliberately
    absent from this contract.
    """

    scope = _enum_from(RecordScope, record_scope) or RecordScope.PROJECT
    if scope is RecordScope.PROJECT and not (project_id or "").strip():
        raise ProjectIsolationError(
            f"{record_type} requires project_id for project-scoped records"
        )
    if scope is RecordScope.SYSTEM and project_id is not None:
        raise ProjectIsolationError(
            f"{record_type} system-scoped records must not set project_id"
        )
    return scope


EnumT = TypeVar("EnumT", bound=StrEnum)


def _drop_none(values: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in values.items() if value is not None}


def _enum_value(value: StrEnum | str | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, StrEnum):
        return value.value
    return value


def _enum_from(enum_type: type[EnumT], value: EnumT | str | None) -> EnumT | None:
    if value is None:
        return None
    if isinstance(value, enum_type):
        return value
    return enum_type(value)


@dataclass(frozen=True)
class ActorRef:
    """Reference to a user, process, API key, service principal, agent, or system."""

    actor_type: str
    actor_id: str
    display_name: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return _drop_none(
            {
                "actor_type": self.actor_type,
                "actor_id": self.actor_id,
                "display_name": self.display_name,
                "metadata": dict(self.metadata) if self.metadata else None,
            }
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ActorRef:
        return cls(
            actor_type=str(data["actor_type"]),
            actor_id=str(data["actor_id"]),
            display_name=data.get("display_name"),
            metadata=data.get("metadata") or {},
        )


@dataclass(frozen=True)
class ActorChain:
    """Default or activity-specific actor chain."""

    caller: ActorRef | None = None
    source_agent: ActorRef | None = None
    root_agent: ActorRef | None = None
    effective_actor: ActorRef | None = None
    credential: ActorRef | None = None
    trusted_proxy: ActorRef | None = None
    service_principal: ActorRef | None = None
    system_actor: ActorRef | None = None

    def to_dict(self) -> dict[str, Any]:
        return _drop_none(
            {
                "caller": self.caller.to_dict() if self.caller else None,
                "source_agent": self.source_agent.to_dict()
                if self.source_agent
                else None,
                "root_agent": self.root_agent.to_dict() if self.root_agent else None,
                "effective_actor": self.effective_actor.to_dict()
                if self.effective_actor
                else None,
                "credential": self.credential.to_dict() if self.credential else None,
                "trusted_proxy": self.trusted_proxy.to_dict()
                if self.trusted_proxy
                else None,
                "service_principal": self.service_principal.to_dict()
                if self.service_principal
                else None,
                "system_actor": self.system_actor.to_dict()
                if self.system_actor
                else None,
            }
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ActorChain:
        def actor(key: str) -> ActorRef | None:
            value = data.get(key)
            return ActorRef.from_dict(value) if value else None

        return cls(
            caller=actor("caller"),
            source_agent=actor("source_agent"),
            root_agent=actor("root_agent"),
            effective_actor=actor("effective_actor"),
            credential=actor("credential"),
            trusted_proxy=actor("trusted_proxy"),
            service_principal=actor("service_principal"),
            system_actor=actor("system_actor"),
        )


@dataclass(frozen=True)
class InteractionContext:
    """Context that groups activity for one externally meaningful workflow."""

    interaction_id: str
    interaction_type: InteractionType
    project_id: str | None = None
    domain_area: DomainArea | None = None
    caller: ActorRef | None = None
    source_agent_id: str | None = None
    root_agent_id: str | None = None
    source_entry_point: str | None = None
    correlation_id: str | None = None
    trace_id: str | None = None
    retention_policy_id: str | None = None
    parent_activity_id: str | None = None
    record_scope: RecordScope = RecordScope.PROJECT

    def to_dict(self) -> dict[str, Any]:
        return _drop_none(
            {
                "interaction_id": self.interaction_id,
                "interaction_type": self.interaction_type.value,
                "project_id": self.project_id,
                "record_scope": self.record_scope.value,
                "domain_area": _enum_value(self.domain_area),
                "caller": self.caller.to_dict() if self.caller else None,
                "source_agent_id": self.source_agent_id,
                "root_agent_id": self.root_agent_id,
                "source_entry_point": self.source_entry_point,
                "correlation_id": self.correlation_id,
                "trace_id": self.trace_id,
                "retention_policy_id": self.retention_policy_id,
                "parent_activity_id": self.parent_activity_id,
            }
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> InteractionContext:
        caller = data.get("caller")
        return cls(
            interaction_id=str(data["interaction_id"]),
            interaction_type=InteractionType(data["interaction_type"]),
            project_id=data.get("project_id"),
            record_scope=_enum_from(RecordScope, data.get("record_scope"))
            or RecordScope.PROJECT,
            domain_area=_enum_from(DomainArea, data.get("domain_area")),
            caller=ActorRef.from_dict(caller) if caller else None,
            source_agent_id=data.get("source_agent_id"),
            root_agent_id=data.get("root_agent_id"),
            source_entry_point=data.get("source_entry_point"),
            correlation_id=data.get("correlation_id"),
            trace_id=data.get("trace_id"),
            retention_policy_id=data.get("retention_policy_id"),
            parent_activity_id=data.get("parent_activity_id"),
        )


@dataclass(frozen=True)
class TargetRef:
    """Reference to the primary or related target of an activity."""

    target_type: str
    target_id: str
    display_name: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return _drop_none(
            {
                "target_type": self.target_type,
                "target_id": self.target_id,
                "display_name": self.display_name,
                "metadata": dict(self.metadata) if self.metadata else None,
            }
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> TargetRef:
        return cls(
            target_type=str(data["target_type"]),
            target_id=str(data["target_id"]),
            display_name=data.get("display_name"),
            metadata=data.get("metadata") or {},
        )


@dataclass(frozen=True)
class RelatedTargetRef:
    """Typed relationship to another target involved in an activity."""

    role: str
    target: TargetRef

    def to_dict(self) -> dict[str, Any]:
        return {"role": self.role, "target": self.target.to_dict()}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RelatedTargetRef:
        return cls(role=str(data["role"]), target=TargetRef.from_dict(data["target"]))


@dataclass(frozen=True)
class EvidenceRef:
    """Reference to service-owned evidence used for reconstruction."""

    evidence_type: str
    evidence_id: str
    domain_area: DomainArea
    content_hash: str | None = None
    metadata_hash: str | None = None
    ref: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return _drop_none(
            {
                "evidence_type": self.evidence_type,
                "evidence_id": self.evidence_id,
                "domain_area": self.domain_area.value,
                "content_hash": self.content_hash,
                "metadata_hash": self.metadata_hash,
                "ref": dict(self.ref) if self.ref else None,
            }
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> EvidenceRef:
        return cls(
            evidence_type=str(data["evidence_type"]),
            evidence_id=str(data["evidence_id"]),
            domain_area=DomainArea(data["domain_area"]),
            content_hash=data.get("content_hash"),
            metadata_hash=data.get("metadata_hash"),
            ref=data.get("ref") or {},
        )


@dataclass(frozen=True)
class ActivityTaxonomy:
    """Faceted taxonomy for filtering and timeline display."""

    domain_area: DomainArea
    target_type: str
    action_family: ActionFamily
    action: str
    lifecycle_phase: LifecyclePhase
    outcome: Outcome
    durability: Durability
    event_label: str
    evidence_class: EvidenceClass | None = None

    def to_dict(self) -> dict[str, Any]:
        return _drop_none(
            {
                "domain_area": self.domain_area.value,
                "target_type": self.target_type,
                "action_family": self.action_family.value,
                "action": self.action,
                "lifecycle_phase": self.lifecycle_phase.value,
                "outcome": self.outcome.value,
                "durability": self.durability.value,
                "evidence_class": _enum_value(self.evidence_class),
                "event_label": self.event_label,
            }
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ActivityTaxonomy:
        return cls(
            domain_area=DomainArea(data["domain_area"]),
            target_type=str(data["target_type"]),
            action_family=ActionFamily(data["action_family"]),
            action=str(data["action"]),
            lifecycle_phase=LifecyclePhase(data["lifecycle_phase"]),
            outcome=Outcome(data["outcome"]),
            durability=Durability(data["durability"]),
            evidence_class=_enum_from(EvidenceClass, data.get("evidence_class")),
            event_label=str(data["event_label"]),
        )


@dataclass(frozen=True)
class ReconstructionContent:
    """Structured reconstruction references for an activity."""

    primary_target: TargetRef
    related_targets: Sequence[RelatedTargetRef] = ()
    snapshot_ref: str | None = None
    diff_ref: str | None = None
    version_refs: Sequence[str] = ()
    evidence_refs: Sequence[EvidenceRef] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return _drop_none(
            {
                "primary_target": self.primary_target.to_dict(),
                "related_targets": [target.to_dict() for target in self.related_targets]
                or None,
                "snapshot_ref": self.snapshot_ref,
                "diff_ref": self.diff_ref,
                "version_refs": list(self.version_refs) or None,
                "evidence_refs": [evidence.to_dict() for evidence in self.evidence_refs]
                or None,
                "metadata": dict(self.metadata) if self.metadata else None,
            }
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ReconstructionContent:
        return cls(
            primary_target=TargetRef.from_dict(data["primary_target"]),
            related_targets=tuple(
                RelatedTargetRef.from_dict(item)
                for item in data.get("related_targets", ())
            ),
            snapshot_ref=data.get("snapshot_ref"),
            diff_ref=data.get("diff_ref"),
            version_refs=tuple(data.get("version_refs", ())),
            evidence_refs=tuple(
                EvidenceRef.from_dict(item) for item in data.get("evidence_refs", ())
            ),
            metadata=data.get("metadata") or {},
        )
