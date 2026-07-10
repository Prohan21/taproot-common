"""``taproot-verify-export`` — standalone WO-018 T3 compliance export verifier.

Runs entirely offline against an export JSON file: no database connection,
no cloud credentials. An external auditor runs this with only the export
file and (ideally) an independently-obtained copy of the platform's public
key — see ``--public-key``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from taproot_common.activity.export import verify_signed_compliance_export


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="taproot-verify-export",
        description=(
            "Independently verify a Taproot signed compliance export: chain "
            "integrity and signature, without database access."
        ),
    )
    parser.add_argument("export_file", type=Path, help="Path to the export JSON file")
    parser.add_argument(
        "--public-key",
        dest="public_key_hex",
        default=None,
        help=(
            "Hex-encoded Ed25519 public key to verify against, obtained "
            "out-of-band from the export itself. Recommended: without this, "
            "verification trusts the key embedded in the export, which is "
            "not an independent guarantee."
        ),
    )
    parser.add_argument(
        "--trust-embedded-key",
        action="store_true",
        help=(
            "Explicitly accept verifying against the public key embedded in "
            "the export file itself. INSECURE for adversarial verification: "
            "an attacker who forges an export can embed their own key."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.public_key_hex and not args.trust_embedded_key:
        print(
            "ERROR: refusing to verify without --public-key. "
            "Pass --trust-embedded-key to explicitly accept the (insecure) "
            "embedded-key fallback instead.",
            file=sys.stderr,
        )
        return 2

    try:
        export_dict = json.loads(args.export_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: could not read export file: {exc}", file=sys.stderr)
        return 2

    report = verify_signed_compliance_export(
        export_dict, trusted_public_key_hex=args.public_key_hex
    )

    print(f"signature:      {'PASS' if report.signature_valid else 'FAIL'}")
    if report.used_embedded_public_key:
        print(
            "                (verified against the embedded key only — no independent trust root)"
        )
    print(f"chain integrity: {'PASS' if report.chain_valid else 'FAIL'}")
    if report.chain_reason:
        print(f"                reason: {report.chain_reason}")
    print(f"OVERALL:        {'PASS' if report.overall_pass else 'FAIL'}")

    return 0 if report.overall_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
