"""Real-Postgres tamper-evidence tests for WO-018 T1 (hash chain) and
T2 (DB-enforced append-only).

Requires a real Postgres (not SQLite — REVOKE/trigger semantics and
concurrent chain writes cannot be proven against SQLite). Run:

    SYSTEM_RECORD_TEST_DATABASE_URL=postgresql://user:pass@host/db \
        uv run pytest tests/test_sor_tamper_evidence_postgres.py -v

Skipped when the URL is not provided, matching the convention in
Guardrail-S's tests/integrations/test_durable_audit_postgres.py.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

DB_URL = os.environ.get("SYSTEM_RECORD_TEST_DATABASE_URL")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not DB_URL,
        reason="SYSTEM_RECORD_TEST_DATABASE_URL not set (needs a real Postgres)",
    ),
]

ALEMBIC_DIR = Path(__file__).resolve().parents[1] / "alembic"


def _run_alembic(command: str) -> None:
    from alembic.config import Config
    from alembic import command as alembic_command

    os.environ["SYSTEM_RECORD_DATABASE_URL"] = DB_URL
    cfg = Config()
    cfg.set_main_option("script_location", str(ALEMBIC_DIR))
    cfg.set_main_option("prepend_sys_path", "src")
    getattr(alembic_command, command)(cfg, "head" if command == "upgrade" else "base")


@pytest.fixture
async def pg_pool():
    import asyncpg

    _run_alembic("upgrade")
    pool = await asyncpg.create_pool(_asyncpg_url(DB_URL), min_size=1, max_size=3)
    try:
        yield pool
    finally:
        await pool.close()
        _run_alembic("downgrade")


def _asyncpg_url(url: str) -> str:
    return url.replace("postgresql+asyncpg://", "postgresql://", 1)


async def _insert_activity_record(pool, storage, *, activity_id: str, project_id: str):
    from datetime import UTC, datetime

    from taproot_common.activity.chain import (
        chain_key_for_project,
        compute_activity_record_hash,
    )

    chain_key = chain_key_for_project(project_id)
    head = await storage.get_activity_chain_head(chain_key)
    prev_hash = head.record_hash if head else None
    chain_seq = (head.chain_seq if head else 0) + 1
    record = {
        "activity_id": activity_id,
        "interaction_id": None,
        "parent_activity_id": None,
        "project_id": project_id,
        "domain_area": "prompt",
        "target_type": "prompt",
        "target_id": "prompt-1",
        "action_family": "update",
        "action": "assign_label",
        "lifecycle_phase": "completed",
        "outcome": "succeeded",
        "durability": "critical",
        "evidence_class": None,
        "event_label": "Label Assigned",
        "primary_target": {"target_type": "prompt", "target_id": "prompt-1"},
        "related_targets": None,
        "actor_override": None,
        "reconstruction_refs": None,
        "metadata": None,
        "retention_policy_id": None,
        "retention_expires_at": None,
        "occurred_at": datetime(2026, 7, 10, tzinfo=UTC),
        "chain_key": chain_key,
        "chain_seq": chain_seq,
        "prev_record_hash": prev_hash,
        "record_hash": compute_activity_record_hash(
            {
                "activity_id": activity_id,
                "interaction_id": None,
                "parent_activity_id": None,
                "project_id": project_id,
                "domain_area": "prompt",
                "target_type": "prompt",
                "target_id": "prompt-1",
                "action_family": "update",
                "action": "assign_label",
                "lifecycle_phase": "completed",
                "outcome": "succeeded",
                "durability": "critical",
                "evidence_class": None,
                "event_label": "Label Assigned",
                "primary_target": {"target_type": "prompt", "target_id": "prompt-1"},
                "related_targets": None,
                "actor_override": None,
                "reconstruction_refs": None,
                "metadata": None,
                "retention_policy_id": None,
                "retention_expires_at": None,
                "occurred_at": datetime(2026, 7, 10, tzinfo=UTC),
            },
            chain_key=chain_key,
            chain_seq=chain_seq,
            prev_record_hash=prev_hash,
        ),
    }
    await storage.write_activity_record(record)
    return record


async def test_verify_chain_passes_for_untampered_records(pg_pool):
    from taproot_common.activity import PostgresActivityStorageAdapter

    storage = PostgresActivityStorageAdapter(pg_pool)
    project_id = "proj-chain-clean"
    await _insert_activity_record(
        pg_pool, storage, activity_id="act-1", project_id=project_id
    )
    await _insert_activity_record(
        pg_pool, storage, activity_id="act-2", project_id=project_id
    )

    result = await storage.verify_activity_chain(project_id)

    assert result.valid is True
    assert result.records_checked == 2


async def test_verify_chain_detects_a_tampered_row(pg_pool):
    from taproot_common.activity import PostgresActivityStorageAdapter
    from taproot_common.activity.schema import SYSTEM_RECORD_RETENTION_BYPASS_GUC

    storage = PostgresActivityStorageAdapter(pg_pool)
    project_id = "proj-chain-tampered"
    await _insert_activity_record(
        pg_pool, storage, activity_id="act-1", project_id=project_id
    )
    await _insert_activity_record(
        pg_pool, storage, activity_id="act-2", project_id=project_id
    )

    # The append-only trigger blocks ordinary UPDATE; only the retention-mode
    # escape hatch (a privileged, exceptional path — see 0004 migration
    # docstring) can perform this mutation at all, simulating a rogue
    # rewrite that a chain check must still catch.
    async with pg_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                f"SET LOCAL \"{SYSTEM_RECORD_RETENTION_BYPASS_GUC}\" = 'on'"
            )
            await conn.execute(
                "UPDATE activity_records SET action = 'revoke_label' WHERE activity_id = $1",
                "act-2",
            )

    result = await storage.verify_activity_chain(project_id)

    assert result.valid is False
    assert result.reason == "hash_mismatch"
    assert result.broken_at_seq == 2


async def test_verify_chain_detects_a_deleted_row(pg_pool):
    from taproot_common.activity import PostgresActivityStorageAdapter
    from taproot_common.activity.schema import SYSTEM_RECORD_RETENTION_BYPASS_GUC

    storage = PostgresActivityStorageAdapter(pg_pool)
    project_id = "proj-chain-deleted"
    await _insert_activity_record(
        pg_pool, storage, activity_id="act-1", project_id=project_id
    )
    await _insert_activity_record(
        pg_pool, storage, activity_id="act-2", project_id=project_id
    )
    await _insert_activity_record(
        pg_pool, storage, activity_id="act-3", project_id=project_id
    )

    async with pg_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                f"SET LOCAL \"{SYSTEM_RECORD_RETENTION_BYPASS_GUC}\" = 'on'"
            )
            await conn.execute(
                "DELETE FROM activity_records WHERE activity_id = $1", "act-2"
            )

    result = await storage.verify_activity_chain(project_id)

    assert result.valid is False
    assert result.reason == "sequence_gap"
    assert result.broken_at_seq == 3


async def test_app_role_cannot_update_or_delete_activity_records(pg_pool):
    from taproot_common.activity import PostgresActivityStorageAdapter

    storage = PostgresActivityStorageAdapter(pg_pool)
    await _insert_activity_record(
        pg_pool, storage, activity_id="act-append-only", project_id="proj-append-only"
    )

    import asyncpg

    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        async with pg_pool.acquire() as conn:
            await conn.execute(
                "UPDATE activity_records SET action = 'x' WHERE activity_id = $1",
                "act-append-only",
            )

    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        async with pg_pool.acquire() as conn:
            await conn.execute(
                "DELETE FROM activity_records WHERE activity_id = $1",
                "act-append-only",
            )


async def test_retention_application_insert_still_works_post_revoke(pg_pool):
    """INSERT-only retention/purge bookkeeping is unaffected by the
    UPDATE/DELETE lockdown — only mutation of existing rows is blocked."""

    async with pg_pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO retention_applications "
            "(application_id, retention_policy_id, domain_area, target_type, "
            "target_id, action_taken, applied_at) "
            "VALUES ($1, $2, $3, $4, $5, $6, now())",
            "app-post-revoke",
            "ret-90d",
            "prompt",
            "prompt",
            "prompt-1",
            "expired",
        )
        row = await conn.fetchrow(
            "SELECT application_id FROM retention_applications WHERE application_id = $1",
            "app-post-revoke",
        )

    assert row is not None
