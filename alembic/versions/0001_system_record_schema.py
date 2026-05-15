"""Create TAP-38 system record schema.

Revision ID: 0001_system_record_schema
Revises:
Create Date: 2026-05-15
"""

from __future__ import annotations

from typing import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0001_system_record_schema"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "retention_policies",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column("retention_policy_id", sa.Text(), nullable=False, unique=True),
        sa.Column("project_id", sa.Text(), nullable=True),
        sa.Column("domain_area", sa.Text(), nullable=False),
        sa.Column("policy_name", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("TRUE")),
        sa.Column("default_days", sa.Integer(), nullable=True),
        sa.Column("evidence_days", sa.Integer(), nullable=True),
        sa.Column("hard_purge_after_days", sa.Integer(), nullable=True),
        sa.Column("compliance_hold", sa.Boolean(), nullable=False, server_default=sa.text("FALSE")),
        sa.Column("config", postgresql.JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("idx_retention_policies_project_domain", "retention_policies", ["project_id", "domain_area"])
    op.create_index("idx_retention_policies_domain_policy", "retention_policies", ["domain_area", "policy_name"])

    op.create_table(
        "interaction_records",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column("interaction_id", sa.Text(), nullable=False, unique=True),
        sa.Column("interaction_type", sa.Text(), nullable=False),
        sa.Column("project_id", sa.Text(), nullable=True),
        sa.Column("domain_area", sa.Text(), nullable=True),
        sa.Column("caller_summary", postgresql.JSONB(), nullable=True),
        sa.Column("default_actor_chain", postgresql.JSONB(), nullable=True),
        sa.Column("root_agent_id", sa.Text(), nullable=True),
        sa.Column("source_entry_point", sa.Text(), nullable=True),
        sa.Column("retention_policy_id", sa.Text(), nullable=True),
        sa.Column("collapse_metadata", postgresql.JSONB(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("idx_interaction_records_project_started", "interaction_records", ["project_id", sa.text("started_at DESC")])
    op.create_index("idx_interaction_records_project_interaction_started", "interaction_records", ["project_id", "interaction_id", sa.text("started_at DESC")])
    op.create_index("idx_interaction_records_type_started", "interaction_records", ["interaction_type", sa.text("started_at DESC")])
    op.create_index("idx_interaction_records_root_agent_started", "interaction_records", ["root_agent_id", sa.text("started_at DESC")], postgresql_where=sa.text("root_agent_id IS NOT NULL"))

    op.create_table(
        "activity_records",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column("activity_id", sa.Text(), nullable=False, unique=True),
        sa.Column("interaction_id", sa.Text(), sa.ForeignKey("interaction_records.interaction_id"), nullable=True),
        sa.Column("parent_activity_id", sa.Text(), nullable=True),
        sa.Column("project_id", sa.Text(), nullable=True),
        sa.Column("domain_area", sa.Text(), nullable=False),
        sa.Column("target_type", sa.Text(), nullable=False),
        sa.Column("target_id", sa.Text(), nullable=False),
        sa.Column("action_family", sa.Text(), nullable=False),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("lifecycle_phase", sa.Text(), nullable=False),
        sa.Column("outcome", sa.Text(), nullable=False),
        sa.Column("durability", sa.Text(), nullable=False),
        sa.Column("evidence_class", sa.Text(), nullable=True),
        sa.Column("event_label", sa.Text(), nullable=False),
        sa.Column("primary_target", postgresql.JSONB(), nullable=False),
        sa.Column("related_targets", postgresql.JSONB(), nullable=True),
        sa.Column("actor_override", postgresql.JSONB(), nullable=True),
        sa.Column("reconstruction_refs", postgresql.JSONB(), nullable=True),
        sa.Column("metadata", postgresql.JSONB(), nullable=True),
        sa.Column("retention_policy_id", sa.Text(), nullable=True),
        sa.Column("retention_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("idx_activity_records_project_occurred", "activity_records", ["project_id", sa.text("occurred_at DESC")])
    op.create_index("idx_activity_records_project_interaction_occurred", "activity_records", ["project_id", "interaction_id", sa.text("occurred_at ASC")])
    op.create_index("idx_activity_records_interaction", "activity_records", ["interaction_id"], postgresql_where=sa.text("interaction_id IS NOT NULL"))
    op.create_index("idx_activity_records_project_domain_occurred", "activity_records", ["project_id", "domain_area", sa.text("occurred_at DESC")])
    op.create_index("idx_activity_records_project_target_occurred", "activity_records", ["project_id", "target_type", "target_id", sa.text("occurred_at DESC")])
    op.create_index("idx_activity_records_project_durability_occurred", "activity_records", ["project_id", "durability", sa.text("occurred_at DESC")])
    op.create_index("idx_activity_records_project_action_family_occurred", "activity_records", ["project_id", "action_family", sa.text("occurred_at DESC")])
    op.create_index("idx_activity_records_retention_expiry", "activity_records", ["retention_policy_id", "retention_expires_at"], postgresql_where=sa.text("retention_expires_at IS NOT NULL"))
    op.create_index("idx_activity_records_parent_occurred", "activity_records", ["parent_activity_id", sa.text("occurred_at ASC")], postgresql_where=sa.text("parent_activity_id IS NOT NULL"))

    op.create_table(
        "activity_snapshots",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column("snapshot_id", sa.Text(), nullable=False, unique=True),
        sa.Column("activity_id", sa.Text(), sa.ForeignKey("activity_records.activity_id"), nullable=False),
        sa.Column("project_id", sa.Text(), nullable=True),
        sa.Column("domain_area", sa.Text(), nullable=False),
        sa.Column("target_type", sa.Text(), nullable=False),
        sa.Column("target_id", sa.Text(), nullable=False),
        sa.Column("snapshot_kind", sa.Text(), nullable=False),
        sa.Column("snapshot_payload", postgresql.JSONB(), nullable=False),
        sa.Column("payload_hash", sa.Text(), nullable=False),
        sa.Column("retention_policy_id", sa.Text(), nullable=True),
        sa.Column("retention_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("idx_activity_snapshots_project_target_created", "activity_snapshots", ["project_id", "target_type", "target_id", sa.text("created_at DESC")])
    op.create_index("idx_activity_snapshots_activity", "activity_snapshots", ["activity_id"])
    op.create_index("idx_activity_snapshots_retention_expiry", "activity_snapshots", ["retention_policy_id", "retention_expires_at"], postgresql_where=sa.text("retention_expires_at IS NOT NULL"))

    op.create_table(
        "activity_diffs",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column("diff_id", sa.Text(), nullable=False, unique=True),
        sa.Column("activity_id", sa.Text(), sa.ForeignKey("activity_records.activity_id"), nullable=False),
        sa.Column("project_id", sa.Text(), nullable=True),
        sa.Column("domain_area", sa.Text(), nullable=False),
        sa.Column("target_type", sa.Text(), nullable=False),
        sa.Column("target_id", sa.Text(), nullable=False),
        sa.Column("diff_payload", postgresql.JSONB(), nullable=False),
        sa.Column("payload_hash", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("idx_activity_diffs_project_target_created", "activity_diffs", ["project_id", "target_type", "target_id", sa.text("created_at DESC")])
    op.create_index("idx_activity_diffs_activity", "activity_diffs", ["activity_id"])

    op.create_table(
        "activity_evidence_links",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column("activity_id", sa.Text(), sa.ForeignKey("activity_records.activity_id"), nullable=False),
        sa.Column("project_id", sa.Text(), nullable=True),
        sa.Column("domain_area", sa.Text(), nullable=False),
        sa.Column("evidence_type", sa.Text(), nullable=False),
        sa.Column("evidence_id", sa.Text(), nullable=False),
        sa.Column("evidence_ref", postgresql.JSONB(), nullable=False),
        sa.Column("content_hash", sa.Text(), nullable=True),
        sa.Column("metadata_hash", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("idx_activity_evidence_links_activity", "activity_evidence_links", ["activity_id"])
    op.create_index("uq_activity_evidence_links_activity_evidence", "activity_evidence_links", ["activity_id", "evidence_type", "evidence_id"], unique=True)
    op.create_index("idx_activity_evidence_links_project_evidence", "activity_evidence_links", ["project_id", "domain_area", "evidence_type", "evidence_id"])
    op.create_index("idx_activity_evidence_links_project_type_created", "activity_evidence_links", ["project_id", "evidence_type", sa.text("created_at DESC")])

    op.create_table(
        "retention_applications",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column("application_id", sa.Text(), nullable=False, unique=True),
        sa.Column("retention_policy_id", sa.Text(), nullable=False),
        sa.Column("activity_id", sa.Text(), sa.ForeignKey("activity_records.activity_id"), nullable=True),
        sa.Column("project_id", sa.Text(), nullable=True),
        sa.Column("domain_area", sa.Text(), nullable=False),
        sa.Column("target_type", sa.Text(), nullable=False),
        sa.Column("target_id", sa.Text(), nullable=False),
        sa.Column("action_taken", sa.Text(), nullable=False),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata", postgresql.JSONB(), nullable=True),
    )
    op.create_index("idx_retention_applications_policy_applied", "retention_applications", ["retention_policy_id", sa.text("applied_at DESC")])
    op.create_index("idx_retention_applications_activity", "retention_applications", ["activity_id"], postgresql_where=sa.text("activity_id IS NOT NULL"))
    op.create_index("idx_retention_applications_project_target_applied", "retention_applications", ["project_id", "target_type", "target_id", sa.text("applied_at DESC")])

    op.create_table(
        "purge_tombstones",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column("purge_tombstone_id", sa.Text(), nullable=False, unique=True),
        sa.Column("activity_id", sa.Text(), sa.ForeignKey("activity_records.activity_id"), nullable=False),
        sa.Column("project_id", sa.Text(), nullable=True),
        sa.Column("domain_area", sa.Text(), nullable=False),
        sa.Column("target_type", sa.Text(), nullable=False),
        sa.Column("target_id", sa.Text(), nullable=False),
        sa.Column("purge_reason", sa.Text(), nullable=False),
        sa.Column("purge_scope", sa.Text(), nullable=False),
        sa.Column("initiated_by", postgresql.JSONB(), nullable=True),
        sa.Column("retention_policy_id", sa.Text(), nullable=True),
        sa.Column("purged_evidence_classes", postgresql.ARRAY(sa.Text()), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("idx_purge_tombstones_project_target_created", "purge_tombstones", ["project_id", "target_type", "target_id", sa.text("created_at DESC")])
    op.create_index("idx_purge_tombstones_activity", "purge_tombstones", ["activity_id"])
    op.create_index("idx_purge_tombstones_retention_created", "purge_tombstones", ["retention_policy_id", sa.text("created_at DESC")])

    op.create_table(
        "activity_dead_letters",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column("dead_letter_id", sa.Text(), nullable=False, unique=True),
        sa.Column("project_id", sa.Text(), nullable=True),
        sa.Column("domain_area", sa.Text(), nullable=True),
        sa.Column("operation_type", sa.Text(), nullable=False),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column("error_type", sa.Text(), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("next_retry_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("idx_activity_dead_letters_status_retry", "activity_dead_letters", ["status", "next_retry_at"])
    op.create_index("idx_activity_dead_letters_project_created", "activity_dead_letters", ["project_id", sa.text("created_at DESC")])
    op.create_index("idx_activity_dead_letters_domain_created", "activity_dead_letters", ["domain_area", sa.text("created_at DESC")])


def downgrade() -> None:
    for table_name in (
        "activity_dead_letters",
        "purge_tombstones",
        "retention_applications",
        "activity_evidence_links",
        "activity_diffs",
        "activity_snapshots",
        "activity_records",
        "interaction_records",
        "retention_policies",
    ):
        op.drop_table(table_name)
