"""Tests for WO-018 T1 hash-chain tamper-evidence helpers."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from taproot_common.activity.chain import (
    chain_key_for_project,
    compute_activity_record_hash,
    verify_activity_chain_rows,
)


def _record(**overrides: Any) -> dict[str, Any]:
    base = {
        "activity_id": "act-1",
        "interaction_id": None,
        "parent_activity_id": None,
        "project_id": "project-1",
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
        "metadata": {"safe_summary": "label prod"},
        "retention_policy_id": None,
        "retention_expires_at": None,
        "occurred_at": datetime(2026, 5, 12, tzinfo=timezone.utc),
    }
    base.update(overrides)
    return base


def _chained_row(
    record: dict[str, Any], *, chain_seq: int, prev_hash: str | None
) -> dict[str, Any]:
    record_hash = compute_activity_record_hash(
        record, chain_key="project-1", chain_seq=chain_seq, prev_record_hash=prev_hash
    )
    return {
        **record,
        "chain_key": "project-1",
        "chain_seq": chain_seq,
        "prev_record_hash": prev_hash,
        "record_hash": record_hash,
    }


def test_chain_key_for_project_uses_project_id_or_global():
    assert chain_key_for_project("project-1") == "project-1"
    assert chain_key_for_project(None) == "global"
    assert chain_key_for_project("") == "global"


def test_hash_is_deterministic_for_identical_input():
    record = _record()
    first = compute_activity_record_hash(
        record, chain_key="project-1", chain_seq=1, prev_record_hash=None
    )
    second = compute_activity_record_hash(
        record, chain_key="project-1", chain_seq=1, prev_record_hash=None
    )
    assert first == second
    assert first.startswith("sha256:")


def test_hash_changes_when_content_changes():
    unchanged = compute_activity_record_hash(
        _record(), chain_key="project-1", chain_seq=1, prev_record_hash=None
    )
    changed = compute_activity_record_hash(
        _record(action="revoke_label"),
        chain_key="project-1",
        chain_seq=1,
        prev_record_hash=None,
    )
    assert unchanged != changed


def test_hash_survives_jsonb_text_roundtrip():
    """Values fetched back from Postgres come as JSON text / native datetimes."""

    record = _record()
    written_hash = compute_activity_record_hash(
        record, chain_key="project-1", chain_seq=1, prev_record_hash=None
    )
    round_tripped = _record(
        primary_target='{"target_id": "prompt-1", "target_type": "prompt"}',
        metadata='{"safe_summary": "label prod"}',
    )
    read_back_hash = compute_activity_record_hash(
        round_tripped, chain_key="project-1", chain_seq=1, prev_record_hash=None
    )
    assert written_hash == read_back_hash


def test_verify_chain_accepts_an_intact_chain():
    row1 = _chained_row(_record(activity_id="act-1"), chain_seq=1, prev_hash=None)
    row2 = _chained_row(
        _record(activity_id="act-2", action="revoke_label"),
        chain_seq=2,
        prev_hash=row1["record_hash"],
    )

    result = verify_activity_chain_rows([row1, row2], chain_key="project-1")

    assert result.valid is True
    assert result.records_checked == 2
    assert result.broken_at_seq is None


def test_verify_chain_detects_modified_row():
    row1 = _chained_row(_record(activity_id="act-1"), chain_seq=1, prev_hash=None)
    row2 = _chained_row(
        _record(activity_id="act-2", action="revoke_label"),
        chain_seq=2,
        prev_hash=row1["record_hash"],
    )
    tampered_row2 = {**row2, "action": "delete_label"}

    result = verify_activity_chain_rows([row1, tampered_row2], chain_key="project-1")

    assert result.valid is False
    assert result.reason == "hash_mismatch"
    assert result.broken_at_seq == 2
    assert result.records_checked == 1


def test_verify_chain_detects_deleted_row_as_sequence_gap():
    row1 = _chained_row(_record(activity_id="act-1"), chain_seq=1, prev_hash=None)
    row2 = _chained_row(
        _record(activity_id="act-2"), chain_seq=2, prev_hash=row1["record_hash"]
    )
    row3 = _chained_row(
        _record(activity_id="act-3"), chain_seq=3, prev_hash=row2["record_hash"]
    )

    # row2 deleted: only row1 and row3 remain in the result set.
    result = verify_activity_chain_rows([row1, row3], chain_key="project-1")

    assert result.valid is False
    assert result.reason == "sequence_gap"
    assert result.broken_at_seq == 3
    assert result.records_checked == 1


def test_verify_chain_detects_reordered_rows():
    row1 = _chained_row(_record(activity_id="act-1"), chain_seq=1, prev_hash=None)
    row2 = _chained_row(
        _record(activity_id="act-2"), chain_seq=2, prev_hash=row1["record_hash"]
    )
    # Reorder: row2's prev_record_hash no longer matches what precedes it.
    swapped_row1 = {**row1, "chain_seq": 1}
    swapped_row2 = {
        **row2,
        "chain_seq": 2,
        "prev_record_hash": "sha256:not-a-real-hash",
    }

    result = verify_activity_chain_rows(
        [swapped_row1, swapped_row2], chain_key="project-1"
    )

    assert result.valid is False
    assert result.reason == "prev_hash_mismatch"
    assert result.broken_at_seq == 2


def test_verify_chain_empty_chain_is_valid():
    result = verify_activity_chain_rows([], chain_key="project-1")

    assert result.valid is True
    assert result.records_checked == 0
