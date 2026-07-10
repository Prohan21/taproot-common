"""Ed25519 signing for WO-018 T3 signed compliance exports.

Asymmetric (not HMAC) so an external auditor can verify a compliance export
with only the public key — no shared secret with the signer is needed, which
is the point of an independently-runnable ``verify-export`` CLI.

One platform-level signing key, not per-service (the SoR plan's "signed with
a platform key" is singular; every SoR-consuming service signs exports with
the same key so an auditor needs exactly one public key, not seven).

# TODO(taproot-infra): provision the private key + a rotation module. This
# module only *resolves* the key from the cloud secret manager; it does not
# provision, generate, or rotate it. Until provisioned, export requests fail
# closed with SigningKeyUnavailableError.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from taproot_common.secrets import get_runtime_environment, load_secret

_SOR_EXPORT_SIGNING_KEY_NAME_TEMPLATE = "taproot-{environment}-sor-export-signing-key"


class SigningKeyUnavailableError(RuntimeError):
    """Raised when a compliance export is requested but no signing key is configured."""


@dataclass(frozen=True)
class ExportSigningKey:
    """A resolved Ed25519 keypair used to sign one compliance export."""

    private_key: Ed25519PrivateKey

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()

    @property
    def public_key_hex(self) -> str:
        return public_key_to_hex(self.public_key)

    @property
    def public_key_fingerprint(self) -> str:
        return public_key_fingerprint(self.public_key)


def sor_export_signing_key_secret_name(environment: str) -> str:
    """Return the canonical secret name for the platform export signing key."""

    if not environment.strip():
        raise ValueError(
            "environment is required to resolve the signing key secret name"
        )
    return _SOR_EXPORT_SIGNING_KEY_NAME_TEMPLATE.format(
        environment=environment.strip().lower()
    )


def resolve_export_signing_key(environment: str | None = None) -> ExportSigningKey:
    """Resolve the platform Ed25519 export signing key. Fails closed if absent.

    The secret payload must be the 32-byte Ed25519 private seed, base64-encoded
    (standard, with padding).
    """

    resolved_environment = environment or get_runtime_environment() or "dev"
    secret_name = sor_export_signing_key_secret_name(resolved_environment)
    payload = load_secret(secret_name)
    if not payload:
        raise SigningKeyUnavailableError(
            f"No compliance export signing key configured at secret '{secret_name}'. "
            "Compliance exports cannot be signed until this secret is provisioned."
        )
    try:
        seed = base64.b64decode(payload, validate=True)
    except Exception as exc:  # noqa: BLE001 - surfaced as a config error, not a crash
        raise SigningKeyUnavailableError(
            f"Signing key secret '{secret_name}' is not valid base64."
        ) from exc
    if len(seed) != 32:
        raise SigningKeyUnavailableError(
            f"Signing key secret '{secret_name}' must decode to 32 bytes "
            f"(Ed25519 seed); got {len(seed)}."
        )
    return ExportSigningKey(private_key=Ed25519PrivateKey.from_private_bytes(seed))


def sign_payload(private_key: Ed25519PrivateKey, payload_bytes: bytes) -> str:
    """Return a hex-encoded detached Ed25519 signature over ``payload_bytes``."""

    return private_key.sign(payload_bytes).hex()


def verify_payload_signature(
    public_key: Ed25519PublicKey, payload_bytes: bytes, signature_hex: str
) -> bool:
    """Return whether ``signature_hex`` is a valid Ed25519 signature over the payload."""

    try:
        public_key.verify(bytes.fromhex(signature_hex), payload_bytes)
    except (InvalidSignature, ValueError):
        return False
    return True


def public_key_to_hex(public_key: Ed25519PublicKey) -> str:
    from cryptography.hazmat.primitives import serialization

    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


def public_key_from_hex(public_key_hex: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))


def public_key_fingerprint(public_key: Ed25519PublicKey) -> str:
    """Return a short sha256 fingerprint of the raw public key bytes."""

    from cryptography.hazmat.primitives import serialization

    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"
