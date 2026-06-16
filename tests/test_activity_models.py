"""Tests for TAP-38 activity domain models."""

import json
from dataclasses import FrozenInstanceError

import pytest

from taproot_common.activity import (
    ACTIVITY_HEADER_VERSION,
    ACTIVITY_SCHEMA_VERSION,
    ActionFamily,
    ActivityTaxonomy,
    ActorChain,
    ActorRef,
    DomainArea,
    Durability,
    EvidenceClass,
    EvidenceRef,
    DELETE_FIELD_DELETED_AT,
    DELETE_FIELD_DELETED_BY,
    DELETE_FIELD_DELETE_REASON,
    DELETE_FIELD_RETENTION_EXPIRES_AT,
    GOVERNANCE_DELETE_FIELDS,
    GOVERNANCE_PURGE_TOMBSTONE_FIELDS,
    INCLUDE_DELETED_QUERY_PARAM,
    InteractionContext,
    InteractionType,
    LifecyclePhase,
    Outcome,
    ProjectIsolationError,
    PURGE_FIELD_PURGED_AT,
    ReconstructionContent,
    RecordScope,
    RelatedTargetRef,
    TargetRef,
    can_include_deleted,
    validate_record_project_scope,
)
from taproot_common.auth.models import AuthContext


def test_contract_versions_are_v1():
    assert ACTIVITY_SCHEMA_VERSION == 1
    assert ACTIVITY_HEADER_VERSION == 1


def test_shared_enum_values_match_v1_interface():
    assert {item.value for item in DomainArea} == {
        "retrieval",
        "prompt",
        "guardrail",
        "evals",
        "toolbox",
        "worker",
        "front",
        "sdk",
        "common",
    }
    assert InteractionType.AGENT_RUN.value == "agent_run"
    assert ActionFamily.RESOLVE.value == "resolve"
    assert LifecyclePhase.COMPLETED.value == "completed"
    assert Outcome.BLOCKED.value == "blocked"
    assert Durability.CRITICAL.value == "critical"
    assert RecordScope.SYSTEM.value == "system"
    assert EvidenceClass.PURGE_TOMBSTONE.value == "purge_tombstone"


def test_interaction_context_serializes_without_none_values():
    context = InteractionContext(
        interaction_id="int-123",
        interaction_type=InteractionType.AGENT_RUN,
        project_id="project-1",
        domain_area=DomainArea.FRONT,
        caller=ActorRef("user", "user-1", display_name="Ada"),
        source_agent_id="agent-1",
        correlation_id="corr-1",
        parent_interaction_id="parent-int-1",
    )

    data = context.to_dict()

    assert data == {
        "interaction_id": "int-123",
        "interaction_type": "agent_run",
        "project_id": "project-1",
        "record_scope": "project",
        "domain_area": "front",
        "caller": {
            "actor_type": "user",
            "actor_id": "user-1",
            "display_name": "Ada",
        },
        "source_agent_id": "agent-1",
        "correlation_id": "corr-1",
        "parent_interaction_id": "parent-int-1",
        "parent_activity_id": "parent-int-1",
    }
    assert "trace_id" not in data
    assert InteractionContext.from_dict(data) == context
    json.dumps(data)


def test_system_interaction_context_serializes_explicit_record_scope():
    context = InteractionContext(
        interaction_id="int-system",
        interaction_type=InteractionType.RETENTION_JOB,
        domain_area=DomainArea.COMMON,
        record_scope=RecordScope.SYSTEM,
    )

    data = context.to_dict()

    assert data["record_scope"] == "system"
    assert "project_id" not in data
    assert InteractionContext.from_dict(data) == context


def test_project_isolation_contract_requires_project_for_customer_records():
    assert (
        validate_record_project_scope(
            record_type="activity_record",
            project_id="project-1",
            record_scope=RecordScope.PROJECT,
        )
        is RecordScope.PROJECT
    )

    with pytest.raises(ProjectIsolationError, match="requires project_id"):
        validate_record_project_scope(
            record_type="activity_record",
            project_id=None,
            record_scope=RecordScope.PROJECT,
        )


def test_project_isolation_contract_represents_system_records_explicitly():
    assert (
        validate_record_project_scope(
            record_type="activity_record",
            project_id=None,
            record_scope=RecordScope.SYSTEM,
        )
        is RecordScope.SYSTEM
    )

    with pytest.raises(ProjectIsolationError, match="must not set project_id"):
        validate_record_project_scope(
            record_type="activity_record",
            project_id="project-1",
            record_scope=RecordScope.SYSTEM,
        )


def test_governance_delete_vocabulary_and_deleted_read_privilege_are_shared():
    assert GOVERNANCE_DELETE_FIELDS == (
        DELETE_FIELD_DELETED_AT,
        DELETE_FIELD_DELETED_BY,
        DELETE_FIELD_DELETE_REASON,
        DELETE_FIELD_RETENTION_EXPIRES_AT,
    )
    assert GOVERNANCE_PURGE_TOMBSTONE_FIELDS[-1] == PURGE_FIELD_PURGED_AT
    assert INCLUDE_DELETED_QUERY_PARAM == "include_deleted"
    assert can_include_deleted(AuthContext("admin", metadata={"is_admin": True}))
    assert not can_include_deleted(AuthContext("user", metadata={"is_admin": False}))
    assert not can_include_deleted(None)


def test_actor_chain_round_trips_nested_actor_refs():
    chain = ActorChain(
        caller=ActorRef("process", "ci", metadata={"workflow": "release"}),
        source_agent=ActorRef("agent", "agent-1"),
        service_principal=ActorRef("service_principal", "front-s"),
    )

    hydrated = ActorChain.from_dict(chain.to_dict())

    assert hydrated == chain


def test_activity_taxonomy_uses_shared_and_service_owned_values():
    taxonomy = ActivityTaxonomy(
        domain_area=DomainArea.RETRIEVAL,
        target_type="document",
        action_family=ActionFamily.UPDATE,
        action="replace_document",
        lifecycle_phase=LifecyclePhase.COMPLETED,
        outcome=Outcome.SUCCEEDED,
        durability=Durability.CRITICAL,
        evidence_class=EvidenceClass.VERSIONED_RESOURCE,
        event_label="Document Replaced",
    )

    data = taxonomy.to_dict()

    assert data["target_type"] == "document"
    assert data["action"] == "replace_document"
    assert data["event_label"] == "Document Replaced"
    assert ActivityTaxonomy.from_dict(data) == taxonomy


def test_reconstruction_content_serializes_targets_and_evidence_refs():
    content = ReconstructionContent(
        primary_target=TargetRef("document", "doc-1", display_name="guide.pdf"),
        related_targets=(
            RelatedTargetRef("new_version", TargetRef("document_version", "ver-2")),
        ),
        snapshot_ref="snapshot-1",
        version_refs=("ver-1", "ver-2"),
        evidence_refs=(
            EvidenceRef(
                evidence_type="chunk",
                evidence_id="chunk-1",
                domain_area=DomainArea.RETRIEVAL,
                content_hash="sha256:abc",
            ),
        ),
        metadata={"safe": True},
    )

    data = content.to_dict()

    assert data["primary_target"]["target_id"] == "doc-1"
    assert data["related_targets"][0]["role"] == "new_version"
    assert data["evidence_refs"][0]["domain_area"] == "retrieval"
    assert ReconstructionContent.from_dict(data) == content
    json.dumps(data)


def test_models_are_frozen():
    actor = ActorRef("system", "retention-job")

    with pytest.raises(FrozenInstanceError):
        actor.actor_id = "other"  # type: ignore[misc]
