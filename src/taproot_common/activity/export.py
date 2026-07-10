"""Signed compliance exports for WO-018 T3.

Builds an independently-verifiable evidence package for one project/chain:
the requested records, a whole-chain integrity verification (via
:func:`taproot_common.activity.chain.verify_activity_chain_rows`), and a
completeness attestation — all signed with the platform Ed25519 export
signing key (:mod:`taproot_common.activity.signing`).

External anchoring (Merkle/timestamp notarization, WO-018 §C1) is a
follow-on; this covers the export + verifier half only (§C2).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime
from typing import Any, Mapping, Protocol, Sequence

from taproot_common.activity.chain import (
    ActivityChainVerificationResult,
    chain_key_for_project,
    verify_activity_chain_rows,
)
from taproot_common.activity.signing import (
    ExportSigningKey,
    public_key_from_hex,
    resolve_export_signing_key,
    sign_payload,
    verify_payload_signature,
)


class ExportableActivityStorage(Protocol):
    """Storage capability required to build a compliance export."""

    async def fetch_activity_records_for_export(
        self,
        chain_key: str,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> Sequence[Mapping[str, Any]]: ...

    async def verify_activity_chain(
        self, chain_key: str
    ) -> ActivityChainVerificationResult: ...

    async def count_system_record_write_failures(
        self, project_id: str | None
    ) -> int: ...


@dataclass(frozen=True)
class CompletenessAttestation:
    """What this export can honestly claim about delivery completeness.

    ``attempted_count`` is intentionally absent: no service yet emits the
    attempted/committed/dead-lettered counters described in the SoR plan's
    Workstream B2 (completeness metrics), so this attestation only reports
    what the write-failure-visibility table actually proves today.
    """

    exported_record_count: int
    dead_lettered_count: int
    caveat: str = (
        "attempted-write counters are not tracked yet (SoR plan Workstream B2); "
        "this attestation reports committed (exported) records and visible "
        "dead-letters only, not a full attempted/committed/dead-lettered ratio."
    )


@dataclass(frozen=True)
class SignedComplianceExport:
    """A signed, independently-verifiable compliance evidence package."""

    project_id: str | None
    chain_key: str
    generated_at: str
    since: str | None
    until: str | None
    records: tuple[Mapping[str, Any], ...]
    chain_verification: ActivityChainVerificationResult
    completeness: CompletenessAttestation
    signing_key_fingerprint: str
    public_key_hex: str
    signature_hex: str = field(default="")

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_id": self.project_id,
            "chain_key": self.chain_key,
            "generated_at": self.generated_at,
            "since": self.since,
            "until": self.until,
            "records": [_json_safe_record(record) for record in self.records],
            "chain_verification": asdict(self.chain_verification),
            "completeness": asdict(self.completeness),
            "signing_key_fingerprint": self.signing_key_fingerprint,
            "public_key_hex": self.public_key_hex,
            "signature_hex": self.signature_hex,
        }


def _json_safe_record(record: Mapping[str, Any]) -> dict[str, Any]:
    """Eagerly normalize datetimes to ISO format.

    ``compute_activity_record_hash`` canonicalizes a native ``datetime`` via
    ``.isoformat()``. If the export dict still holds raw ``datetime``
    objects, a caller serializing it with a generic ``json.dumps(...,
    default=str)`` gets Python's ``str(datetime)`` instead (space separator,
    not ``T``) — a JSON round-trip through a file would then desync from the
    hash that was actually signed. Normalizing here means ``to_dict()`` is
    already fully JSON-native; any subsequent ``json.dumps`` round-trips
    losslessly.
    """

    return {
        key: value.isoformat() if isinstance(value, datetime) else value
        for key, value in record.items()
    }


@dataclass(frozen=True)
class ExportVerificationReport:
    """Result of independently re-verifying a signed compliance export."""

    signature_valid: bool
    chain_valid: bool
    chain_reason: str | None
    used_embedded_public_key: bool
    overall_pass: bool


def _signable_payload(export_dict: Mapping[str, Any]) -> bytes:
    unsigned = {
        key: value for key, value in export_dict.items() if key != "signature_hex"
    }
    serialized = json.dumps(
        unsigned, sort_keys=True, separators=(",", ":"), default=str
    )
    return serialized.encode("utf-8")


async def build_signed_compliance_export(
    storage: ExportableActivityStorage,
    *,
    project_id: str | None,
    since: datetime | None = None,
    until: datetime | None = None,
    environment: str | None = None,
    signing_key: ExportSigningKey | None = None,
) -> SignedComplianceExport:
    """Build and sign a compliance export for one project's activity chain.

    Fails closed (``SigningKeyUnavailableError``) if no export signing key is
    configured — an unsigned "export" would not be worth the compliance
    claim, so this never silently returns unsigned evidence.
    """

    chain_key = chain_key_for_project(project_id)
    resolved_key = signing_key or resolve_export_signing_key(environment)

    records = tuple(
        await storage.fetch_activity_records_for_export(
            chain_key, since=since, until=until
        )
    )
    chain_verification = await storage.verify_activity_chain(chain_key)
    dead_lettered_count = await storage.count_system_record_write_failures(project_id)

    export = SignedComplianceExport(
        project_id=project_id,
        chain_key=chain_key,
        generated_at=datetime.now(UTC).isoformat(),
        since=since.isoformat() if since else None,
        until=until.isoformat() if until else None,
        records=records,
        chain_verification=chain_verification,
        completeness=CompletenessAttestation(
            exported_record_count=len(records),
            dead_lettered_count=dead_lettered_count,
        ),
        signing_key_fingerprint=resolved_key.public_key_fingerprint,
        public_key_hex=resolved_key.public_key_hex,
    )

    signature_hex = sign_payload(
        resolved_key.private_key, _signable_payload(export.to_dict())
    )
    return replace(export, signature_hex=signature_hex)


def verify_signed_compliance_export(
    export_dict: Mapping[str, Any],
    *,
    trusted_public_key_hex: str | None = None,
) -> ExportVerificationReport:
    """Independently re-verify a compliance export: signature + chain integrity.

    Chain integrity is recomputed from the embedded records rather than
    trusting the embedded ``chain_verification`` block, so a tampered export
    (records edited *and* the embedded verification block edited to say
    "valid") is still caught. Signature verification defaults to the
    embedded public key only when the caller explicitly accepts that (no
    independent trust root — see ``used_embedded_public_key`` in the report);
    passing ``trusted_public_key_hex`` (obtained out-of-band) is the
    credible verification path for an external auditor.
    """

    used_embedded_public_key = trusted_public_key_hex is None
    public_key_hex = trusted_public_key_hex or str(
        export_dict.get("public_key_hex", "")
    )
    signature_hex = str(export_dict.get("signature_hex", ""))

    signature_valid = False
    if public_key_hex and signature_hex:
        try:
            public_key = public_key_from_hex(public_key_hex)
            signature_valid = verify_payload_signature(
                public_key, _signable_payload(export_dict), signature_hex
            )
        except ValueError:
            signature_valid = False

    records = export_dict.get("records", ())
    chain_key = str(export_dict.get("chain_key", ""))
    recomputed_chain = verify_activity_chain_rows(records, chain_key=chain_key)

    overall_pass = (
        signature_valid and recomputed_chain.valid and not used_embedded_public_key
    )

    return ExportVerificationReport(
        signature_valid=signature_valid,
        chain_valid=recomputed_chain.valid,
        chain_reason=recomputed_chain.reason,
        used_embedded_public_key=used_embedded_public_key,
        overall_pass=overall_pass,
    )
