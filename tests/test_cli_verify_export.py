"""Tests for the standalone ``taproot-verify-export`` CLI (WO-018 T3)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from taproot_common.activity import ExportSigningKey
from taproot_common.activity.chain import compute_activity_record_hash
from taproot_common.activity.export import build_signed_compliance_export
from taproot_common.cli.verify_export import main


class _FakeExportStorage:
    def __init__(self, records: list[dict[str, Any]]) -> None:
        self._records = records

    async def fetch_activity_records_for_export(
        self, chain_key, *, since=None, until=None
    ):
        return [r for r in self._records if r["chain_key"] == chain_key]

    async def verify_activity_chain(self, chain_key):
        from taproot_common.activity.chain import verify_activity_chain_rows

        return verify_activity_chain_rows(
            [r for r in self._records if r["chain_key"] == chain_key],
            chain_key=chain_key,
        )

    async def count_system_record_write_failures(self, project_id):
        return 0


def _record() -> dict[str, Any]:
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
        "metadata": None,
        "retention_policy_id": None,
        "retention_expires_at": None,
        "occurred_at": datetime(2026, 7, 10, tzinfo=UTC),
    }
    record_hash = compute_activity_record_hash(
        base, chain_key="project-1", chain_seq=1, prev_record_hash=None
    )
    return {
        **base,
        "chain_key": "project-1",
        "chain_seq": 1,
        "prev_record_hash": None,
        "record_hash": record_hash,
    }


async def _write_export_file(path: Path) -> ExportSigningKey:
    key = ExportSigningKey(private_key=Ed25519PrivateKey.generate())
    storage = _FakeExportStorage([_record()])
    export = await build_signed_compliance_export(
        storage, project_id="project-1", signing_key=key
    )
    path.write_text(json.dumps(export.to_dict(), default=str), encoding="utf-8")
    return key


@pytest.mark.asyncio
async def test_cli_passes_with_correct_trusted_public_key(tmp_path, capsys):
    export_file = tmp_path / "export.json"
    key = await _write_export_file(export_file)

    exit_code = main([str(export_file), "--public-key", key.public_key_hex])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "signature:      PASS" in captured.out
    assert "chain integrity: PASS" in captured.out
    assert "OVERALL:        PASS" in captured.out


@pytest.mark.asyncio
async def test_cli_fails_without_any_key_argument(tmp_path, capsys):
    export_file = tmp_path / "export.json"
    await _write_export_file(export_file)

    exit_code = main([str(export_file)])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "refusing to verify without --public-key" in captured.err


@pytest.mark.asyncio
async def test_cli_trust_embedded_key_flag_still_fails_overall(tmp_path, capsys):
    export_file = tmp_path / "export.json"
    await _write_export_file(export_file)

    exit_code = main([str(export_file), "--trust-embedded-key"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "embedded key only" in captured.out
    assert "OVERALL:        FAIL" in captured.out


@pytest.mark.asyncio
async def test_cli_prints_chain_reason_for_a_tampered_export(tmp_path, capsys):
    export_file = tmp_path / "export.json"
    key = await _write_export_file(export_file)
    export_dict = json.loads(export_file.read_text(encoding="utf-8"))
    export_dict["records"][0]["action"] = "revoke_label"
    export_file.write_text(json.dumps(export_dict), encoding="utf-8")

    exit_code = main([str(export_file), "--public-key", key.public_key_hex])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "chain integrity: FAIL" in captured.out
    assert "reason: hash_mismatch" in captured.out


@pytest.mark.asyncio
async def test_cli_fails_with_wrong_public_key(tmp_path, capsys):
    export_file = tmp_path / "export.json"
    await _write_export_file(export_file)
    wrong_key = ExportSigningKey(private_key=Ed25519PrivateKey.generate())

    exit_code = main([str(export_file), "--public-key", wrong_key.public_key_hex])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "signature:      FAIL" in captured.out


def test_cli_handles_missing_file(tmp_path, capsys):
    missing_file = tmp_path / "does-not-exist.json"

    exit_code = main([str(missing_file), "--trust-embedded-key"])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "could not read export file" in captured.err


def test_cli_handles_malformed_json(tmp_path, capsys):
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("{not valid json", encoding="utf-8")

    exit_code = main([str(bad_file), "--trust-embedded-key"])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "could not read export file" in captured.err
