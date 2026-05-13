"""PostgreSQL schema DDL for the TAP-38 activity database."""

from __future__ import annotations

ACTIVITY_TABLES: tuple[str, ...] = (
    "retention_policies",
    "interaction_records",
    "activity_records",
    "activity_snapshots",
    "activity_diffs",
    "activity_evidence_links",
    "retention_applications",
    "purge_tombstones",
    "activity_dead_letters",
)

ACTIVITY_PARTITION_RECOMMENDATIONS: tuple[str, ...] = (
    "activity_records by occurred_at",
    "activity_evidence_links by created_at when evidence volume warrants it",
)

CREATE_ACTIVITY_TABLE_SQL: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS retention_policies (
        id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        retention_policy_id TEXT UNIQUE NOT NULL,
        project_id TEXT NULL,
        domain_area TEXT NOT NULL,
        policy_name TEXT NOT NULL,
        enabled BOOLEAN NOT NULL DEFAULT TRUE,
        default_days INTEGER NULL,
        evidence_days INTEGER NULL,
        hard_purge_after_days INTEGER NULL,
        compliance_hold BOOLEAN NOT NULL DEFAULT FALSE,
        config JSONB NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS interaction_records (
        id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        interaction_id TEXT UNIQUE NOT NULL,
        interaction_type TEXT NOT NULL,
        project_id TEXT NULL,
        domain_area TEXT NULL,
        caller_summary JSONB NULL,
        default_actor_chain JSONB NULL,
        root_agent_id TEXT NULL,
        source_entry_point TEXT NULL,
        retention_policy_id TEXT NULL,
        collapse_metadata JSONB NULL,
        started_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS activity_records (
        id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        activity_id TEXT UNIQUE NOT NULL,
        interaction_id TEXT NULL REFERENCES interaction_records(interaction_id),
        parent_activity_id TEXT NULL,
        project_id TEXT NULL,
        domain_area TEXT NOT NULL,
        target_type TEXT NOT NULL,
        target_id TEXT NOT NULL,
        action_family TEXT NOT NULL,
        action TEXT NOT NULL,
        lifecycle_phase TEXT NOT NULL,
        outcome TEXT NOT NULL,
        durability TEXT NOT NULL,
        evidence_class TEXT NULL,
        event_label TEXT NOT NULL,
        primary_target JSONB NOT NULL,
        related_targets JSONB NULL,
        actor_override JSONB NULL,
        reconstruction_refs JSONB NULL,
        metadata JSONB NULL,
        retention_policy_id TEXT NULL,
        retention_expires_at TIMESTAMPTZ NULL,
        occurred_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS activity_snapshots (
        id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        snapshot_id TEXT UNIQUE NOT NULL,
        activity_id TEXT NOT NULL REFERENCES activity_records(activity_id),
        project_id TEXT NULL,
        domain_area TEXT NOT NULL,
        target_type TEXT NOT NULL,
        target_id TEXT NOT NULL,
        snapshot_kind TEXT NOT NULL,
        snapshot_payload JSONB NOT NULL,
        payload_hash TEXT NOT NULL,
        retention_policy_id TEXT NULL,
        retention_expires_at TIMESTAMPTZ NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS activity_diffs (
        id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        diff_id TEXT UNIQUE NOT NULL,
        activity_id TEXT NOT NULL REFERENCES activity_records(activity_id),
        project_id TEXT NULL,
        domain_area TEXT NOT NULL,
        target_type TEXT NOT NULL,
        target_id TEXT NOT NULL,
        diff_payload JSONB NOT NULL,
        payload_hash TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS activity_evidence_links (
        id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        activity_id TEXT NOT NULL REFERENCES activity_records(activity_id),
        project_id TEXT NULL,
        domain_area TEXT NOT NULL,
        evidence_type TEXT NOT NULL,
        evidence_id TEXT NOT NULL,
        evidence_ref JSONB NOT NULL,
        content_hash TEXT NULL,
        metadata_hash TEXT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS retention_applications (
        id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        application_id TEXT UNIQUE NOT NULL,
        retention_policy_id TEXT NOT NULL,
        activity_id TEXT NULL REFERENCES activity_records(activity_id),
        project_id TEXT NULL,
        domain_area TEXT NOT NULL,
        target_type TEXT NOT NULL,
        target_id TEXT NOT NULL,
        action_taken TEXT NOT NULL,
        applied_at TIMESTAMPTZ NOT NULL,
        metadata JSONB NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS purge_tombstones (
        id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        purge_tombstone_id TEXT UNIQUE NOT NULL,
        activity_id TEXT NOT NULL REFERENCES activity_records(activity_id),
        project_id TEXT NULL,
        domain_area TEXT NOT NULL,
        target_type TEXT NOT NULL,
        target_id TEXT NOT NULL,
        purge_reason TEXT NOT NULL,
        purge_scope TEXT NOT NULL,
        initiated_by JSONB NULL,
        retention_policy_id TEXT NULL,
        purged_evidence_classes TEXT[] NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS activity_dead_letters (
        id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        dead_letter_id TEXT UNIQUE NOT NULL,
        project_id TEXT NULL,
        domain_area TEXT NULL,
        operation_type TEXT NOT NULL,
        payload JSONB NOT NULL,
        error_type TEXT NOT NULL,
        error_message TEXT NULL,
        attempt_count INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL,
        next_retry_at TIMESTAMPTZ NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    """,
)

CREATE_ACTIVITY_INDEX_SQL: tuple[str, ...] = (
    """
    CREATE INDEX IF NOT EXISTS idx_retention_policies_project_domain
        ON retention_policies(project_id, domain_area);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_retention_policies_domain_policy
        ON retention_policies(domain_area, policy_name);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_interaction_records_project_started
        ON interaction_records(project_id, started_at DESC);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_interaction_records_project_interaction_started
        ON interaction_records(project_id, interaction_id, started_at DESC);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_interaction_records_type_started
        ON interaction_records(interaction_type, started_at DESC);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_interaction_records_root_agent_started
        ON interaction_records(root_agent_id, started_at DESC)
        WHERE root_agent_id IS NOT NULL;
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_activity_records_project_occurred
        ON activity_records(project_id, occurred_at DESC);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_activity_records_project_interaction_occurred
        ON activity_records(project_id, interaction_id, occurred_at ASC);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_activity_records_interaction
        ON activity_records(interaction_id)
        WHERE interaction_id IS NOT NULL;
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_activity_records_project_domain_occurred
        ON activity_records(project_id, domain_area, occurred_at DESC);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_activity_records_project_target_occurred
        ON activity_records(project_id, target_type, target_id, occurred_at DESC);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_activity_records_project_durability_occurred
        ON activity_records(project_id, durability, occurred_at DESC);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_activity_records_project_action_family_occurred
        ON activity_records(project_id, action_family, occurred_at DESC);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_activity_records_retention_expiry
        ON activity_records(retention_policy_id, retention_expires_at)
        WHERE retention_expires_at IS NOT NULL;
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_activity_records_parent_occurred
        ON activity_records(parent_activity_id, occurred_at ASC)
        WHERE parent_activity_id IS NOT NULL;
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_activity_snapshots_project_target_created
        ON activity_snapshots(project_id, target_type, target_id, created_at DESC);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_activity_snapshots_activity
        ON activity_snapshots(activity_id);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_activity_snapshots_retention_expiry
        ON activity_snapshots(retention_policy_id, retention_expires_at)
        WHERE retention_expires_at IS NOT NULL;
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_activity_diffs_project_target_created
        ON activity_diffs(project_id, target_type, target_id, created_at DESC);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_activity_diffs_activity
        ON activity_diffs(activity_id);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_activity_evidence_links_activity
        ON activity_evidence_links(activity_id);
    """,
    """
    CREATE UNIQUE INDEX IF NOT EXISTS uq_activity_evidence_links_activity_evidence
        ON activity_evidence_links(activity_id, evidence_type, evidence_id);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_activity_evidence_links_project_evidence
        ON activity_evidence_links(project_id, domain_area, evidence_type, evidence_id);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_activity_evidence_links_project_type_created
        ON activity_evidence_links(project_id, evidence_type, created_at DESC);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_retention_applications_policy_applied
        ON retention_applications(retention_policy_id, applied_at DESC);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_retention_applications_activity
        ON retention_applications(activity_id)
        WHERE activity_id IS NOT NULL;
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_retention_applications_project_target_applied
        ON retention_applications(project_id, target_type, target_id, applied_at DESC);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_purge_tombstones_project_target_created
        ON purge_tombstones(project_id, target_type, target_id, created_at DESC);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_purge_tombstones_activity
        ON purge_tombstones(activity_id);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_purge_tombstones_retention_created
        ON purge_tombstones(retention_policy_id, created_at DESC);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_activity_dead_letters_status_retry
        ON activity_dead_letters(status, next_retry_at);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_activity_dead_letters_project_created
        ON activity_dead_letters(project_id, created_at DESC);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_activity_dead_letters_domain_created
        ON activity_dead_letters(domain_area, created_at DESC);
    """,
)

DROP_ACTIVITY_SCHEMA_SQL: tuple[str, ...] = tuple(
    f"DROP TABLE IF EXISTS {table_name} CASCADE;"
    for table_name in reversed(ACTIVITY_TABLES)
)


def iter_activity_schema_sql() -> tuple[str, ...]:
    """Return ordered DDL statements for creating the activity database schema."""

    return CREATE_ACTIVITY_TABLE_SQL + CREATE_ACTIVITY_INDEX_SQL
