"""Tests for WO-018 T3 signed compliance exports."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Mapping, Sequence

import pytest

from taproot_common.activity import ExportSigningKey, SigningKeyUnavailableError
from taproot_common.activity.export import (
    build_signed_compliance_export,
    verify_signed_compliance_export,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _record(
    activity_id: str, *, chain_seq: int, prev_hash: str | None
) -> dict[str, Any]:
    from taproot_common.activity.chain import compute_activity_record_hash

    base = {
        "activity_id": activity_id,
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
        "metadata": None,
        "retention_policy_id": None,
        "retention_expires_at": None,
        "occurred_at": datetime(2026, 7, 10, tzinfo=UTC),
    }
    record_hash = compute_activity_record_hash(
        base, chain_key="project-1", chain_seq=chain_seq, prev_record_hash=prev_hash
    )
    return {
        **base,
        "chain_key": "project-1",
        "chain_seq": chain_seq,
        "prev_record_hash": prev_hash,
        "record_hash": record_hash,
    }


class FakeExportStorage:
    def __init__(
        self,
        records: Sequence[Mapping[str, Any]],
        *,
        dead_lettered_count: int = 0,
    ) -> None:
        self._records = list(records)
        self._dead_lettered_count = dead_lettered_count

    async def fetch_activity_records_for_export(
        self, chain_key, *, since=None, until=None
    ):
        return [r for r in self._records if r["chain_key"] == chain_key]

    async def verify_activity_chain(self, chain_key):
        from taproot_common.activity.chain import verify_activity_chain_rows

        chained = [r for r in self._records if r["chain_key"] == chain_key]
        return verify_activity_chain_rows(chained, chain_key=chain_key)

    async def count_system_record_write_failures(self, project_id):
        return self._dead_lettered_count


def _signing_key() -> ExportSigningKey:
    return ExportSigningKey(private_key=Ed25519PrivateKey.generate())


@pytest.mark.asyncio
async def test_build_signed_compliance_export_is_internally_consistent():
    row1 = _record("act-1", chain_seq=1, prev_hash=None)
    row2 = _record("act-2", chain_seq=2, prev_hash=row1["record_hash"])
    storage = FakeExportStorage([row1, row2], dead_lettered_count=1)
    key = _signing_key()

    export = await build_signed_compliance_export(
        storage, project_id="project-1", signing_key=key
    )

    assert export.project_id == "project-1"
    assert export.chain_key == "project-1"
    assert len(export.records) == 2
    assert export.chain_verification.valid is True
    assert export.completeness.exported_record_count == 2
    assert export.completeness.dead_lettered_count == 1
    assert export.signing_key_fingerprint == key.public_key_fingerprint
    assert export.public_key_hex == key.public_key_hex
    assert export.signature_hex

    report = verify_signed_compliance_export(
        export.to_dict(), trusted_public_key_hex=key.public_key_hex
    )
    assert report.signature_valid is True
    assert report.chain_valid is True
    assert report.used_embedded_public_key is False
    assert report.overall_pass is True


@pytest.mark.asyncio
async def test_build_signed_compliance_export_fails_closed_without_a_signing_key(
    monkeypatch,
):
    from taproot_common.activity import export as export_module

    monkeypatch.setattr(
        export_module,
        "resolve_export_signing_key",
        lambda environment=None: (_ for _ in ()).throw(
            SigningKeyUnavailableError("no key configured")
        ),
    )
    storage = FakeExportStorage([])

    with pytest.raises(SigningKeyUnavailableError):
        await build_signed_compliance_export(storage, project_id="project-1")


@pytest.mark.asyncio
async def test_verify_rejects_a_tampered_record_even_if_chain_block_is_edited_too():
    row1 = _record("act-1", chain_seq=1, prev_hash=None)
    storage = FakeExportStorage([row1])
    key = _signing_key()

    export = await build_signed_compliance_export(
        storage, project_id="project-1", signing_key=key
    )
    export_dict = export.to_dict()
    # Tamper the record AND lie in the embedded verification block.
    export_dict["records"][0] = {**export_dict["records"][0], "action": "revoke_label"}
    export_dict["chain_verification"] = {
        "chain_key": "project-1",
        "valid": True,
        "records_checked": 1,
        "broken_at_seq": None,
        "reason": None,
    }

    report = verify_signed_compliance_export(
        export_dict, trusted_public_key_hex=key.public_key_hex
    )

    assert report.chain_valid is False
    assert report.chain_reason == "hash_mismatch"
    assert report.overall_pass is False


@pytest.mark.asyncio
async def test_verify_rejects_signature_after_any_field_edit():
    row1 = _record("act-1", chain_seq=1, prev_hash=None)
    storage = FakeExportStorage([row1])
    key = _signing_key()

    export = await build_signed_compliance_export(
        storage, project_id="project-1", signing_key=key
    )
    export_dict = export.to_dict()
    export_dict["completeness"]["dead_lettered_count"] = 999  # edited post-signing

    report = verify_signed_compliance_export(
        export_dict, trusted_public_key_hex=key.public_key_hex
    )

    assert report.signature_valid is False
    assert report.overall_pass is False


@pytest.mark.asyncio
async def test_verify_using_embedded_key_only_never_passes_overall():
    """The embedded public key is informational, not an independent trust
    root — an attacker forging an export can embed their own key and pass
    signature verification against it. overall_pass must require an
    externally-supplied key."""

    row1 = _record("act-1", chain_seq=1, prev_hash=None)
    storage = FakeExportStorage([row1])
    key = _signing_key()

    export = await build_signed_compliance_export(
        storage, project_id="project-1", signing_key=key
    )

    report = verify_signed_compliance_export(export.to_dict())

    assert report.used_embedded_public_key is True
    assert report.signature_valid is True
    assert report.chain_valid is True
    assert report.overall_pass is False


@pytest.mark.asyncio
async def test_verify_rejects_wrong_trusted_public_key():
    row1 = _record("act-1", chain_seq=1, prev_hash=None)
    storage = FakeExportStorage([row1])
    key = _signing_key()
    wrong_key = _signing_key()

    export = await build_signed_compliance_export(
        storage, project_id="project-1", signing_key=key
    )

    report = verify_signed_compliance_export(
        export.to_dict(), trusted_public_key_hex=wrong_key.public_key_hex
    )

    assert report.signature_valid is False
    assert report.overall_pass is False


@pytest.mark.asyncio
async def test_export_uses_global_chain_key_for_system_scoped_project():
    storage = FakeExportStorage([])
    key = _signing_key()

    export = await build_signed_compliance_export(
        storage, project_id=None, signing_key=key
    )

    assert export.chain_key == "global"
    assert export.completeness.exported_record_count == 0


def test_verify_handles_malformed_embedded_public_key_hex():
    report = verify_signed_compliance_export(
        {
            "chain_key": "project-1",
            "records": (),
            "public_key_hex": "not-hex-at-all",
            "signature_hex": "deadbeef",
        }
    )

    assert report.signature_valid is False
    assert report.overall_pass is False
