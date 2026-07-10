"""Hash-chain tamper-evidence for ``activity_records`` (WO-018 T1).

Each activity record is chained to the prior record within the same
``chain_key`` (the project scope, or ``"global"`` for project-less records):
``record_hash = sha256(canonical_json(row-content, chain_key, chain_seq,
prev_record_hash))``. Rewriting, deleting, or reordering a record breaks the
chain at that point, which :func:`verify_activity_chain_rows` detects.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

GLOBAL_CHAIN_KEY = "global"

_CANONICAL_FIELDS: tuple[str, ...] = (
    "activity_id",
    "interaction_id",
    "parent_activity_id",
    "project_id",
    "domain_area",
    "target_type",
    "target_id",
    "action_family",
    "action",
    "lifecycle_phase",
    "outcome",
    "durability",
    "evidence_class",
    "event_label",
    "primary_target",
    "related_targets",
    "actor_override",
    "reconstruction_refs",
    "metadata",
    "retention_policy_id",
    "retention_expires_at",
    "occurred_at",
)


@dataclass(frozen=True)
class ActivityChainHead:
    """The most recently chained record for one ``chain_key``."""

    chain_seq: int
    record_hash: str


@dataclass(frozen=True)
class ActivityChainVerificationResult:
    """Outcome of walking one chain's records in ``chain_seq`` order."""

    chain_key: str
    valid: bool
    records_checked: int
    broken_at_seq: int | None = None
    reason: str | None = None


def chain_key_for_project(project_id: str | None) -> str:
    """Return the chain partition key for a record's project scope."""

    return project_id if project_id else GLOBAL_CHAIN_KEY


def compute_activity_record_hash(
    record: Mapping[str, Any],
    *,
    chain_key: str,
    chain_seq: int,
    prev_record_hash: str | None,
) -> str:
    """Compute the chained hash for one ``activity_records`` row.

    ``record`` may come from the write path (native Python values) or from a
    round-tripped DB read (JSONB text, native datetimes) — both are
    canonicalized identically via :func:`_canonical_payload` so the hash is
    stable across storage round-trips.
    """

    payload = _canonical_payload(record)
    payload["chain_key"] = chain_key
    payload["chain_seq"] = chain_seq
    payload["prev_record_hash"] = prev_record_hash
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return f"sha256:{hashlib.sha256(serialized.encode('utf-8')).hexdigest()}"


def verify_activity_chain_rows(
    rows: Sequence[Mapping[str, Any]],
    *,
    chain_key: str,
) -> ActivityChainVerificationResult:
    """Walk ``rows`` (already ordered by ``chain_seq`` ascending) and detect tamper.

    A modified record fails the ``hash_mismatch`` check; a deleted record
    produces a ``sequence_gap`` (the next surviving row's ``chain_seq`` skips
    over it); a reordered record breaks either the sequence or the
    ``prev_record_hash`` link.
    """

    expected_seq = 1
    prev_hash: str | None = None
    for row in rows:
        chain_seq = row["chain_seq"]
        if chain_seq != expected_seq:
            return ActivityChainVerificationResult(
                chain_key=chain_key,
                valid=False,
                records_checked=expected_seq - 1,
                broken_at_seq=chain_seq,
                reason="sequence_gap",
            )
        stored_prev_hash = row.get("prev_record_hash")
        if stored_prev_hash != prev_hash:
            return ActivityChainVerificationResult(
                chain_key=chain_key,
                valid=False,
                records_checked=expected_seq - 1,
                broken_at_seq=chain_seq,
                reason="prev_hash_mismatch",
            )
        recomputed = compute_activity_record_hash(
            row, chain_key=chain_key, chain_seq=chain_seq, prev_record_hash=prev_hash
        )
        if recomputed != row["record_hash"]:
            return ActivityChainVerificationResult(
                chain_key=chain_key,
                valid=False,
                records_checked=expected_seq - 1,
                broken_at_seq=chain_seq,
                reason="hash_mismatch",
            )
        prev_hash = row["record_hash"]
        expected_seq += 1

    return ActivityChainVerificationResult(
        chain_key=chain_key,
        valid=True,
        records_checked=expected_seq - 1,
    )


def _canonical_payload(record: Mapping[str, Any]) -> dict[str, Any]:
    return {field: _canonical_value(record.get(field)) for field in _CANONICAL_FIELDS}


def _canonical_value(value: Any) -> Any:
    if isinstance(value, str):
        stripped = value.strip()
        if stripped[:1] in "{[":
            try:
                return json.loads(value)
            except (ValueError, TypeError):
                return value
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    return value
