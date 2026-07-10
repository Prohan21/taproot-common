"""Tests for WO-018 T3 Ed25519 export signing primitives."""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from taproot_common.activity import signing


def _base64_seed(seed: bytes = b"\x01" * 32) -> str:
    return base64.b64encode(seed).decode("ascii")


def test_sor_export_signing_key_secret_name_format():
    assert (
        signing.sor_export_signing_key_secret_name("prod")
        == "taproot-prod-sor-export-signing-key"
    )
    assert (
        signing.sor_export_signing_key_secret_name("  DEV  ")
        == "taproot-dev-sor-export-signing-key"
    )


def test_sor_export_signing_key_secret_name_requires_environment():
    with pytest.raises(ValueError, match="environment is required"):
        signing.sor_export_signing_key_secret_name("   ")


def test_resolve_export_signing_key_fails_closed_when_secret_missing(monkeypatch):
    monkeypatch.setattr(signing, "load_secret", lambda name: None)

    with pytest.raises(
        signing.SigningKeyUnavailableError, match="No compliance export"
    ):
        signing.resolve_export_signing_key(environment="dev")


def test_resolve_export_signing_key_rejects_invalid_base64(monkeypatch):
    monkeypatch.setattr(signing, "load_secret", lambda name: "not-valid-base64!!!")

    with pytest.raises(signing.SigningKeyUnavailableError, match="not valid base64"):
        signing.resolve_export_signing_key(environment="dev")


def test_resolve_export_signing_key_rejects_wrong_length_seed(monkeypatch):
    monkeypatch.setattr(
        signing, "load_secret", lambda name: base64.b64encode(b"short").decode()
    )

    with pytest.raises(
        signing.SigningKeyUnavailableError, match="must decode to 32 bytes"
    ):
        signing.resolve_export_signing_key(environment="dev")


def test_resolve_export_signing_key_succeeds_with_valid_seed(monkeypatch):
    captured_names: list[str] = []

    def fake_load_secret(name: str) -> str:
        captured_names.append(name)
        return _base64_seed()

    monkeypatch.setattr(signing, "load_secret", fake_load_secret)

    key = signing.resolve_export_signing_key(environment="prod")

    assert isinstance(key, signing.ExportSigningKey)
    assert captured_names == ["taproot-prod-sor-export-signing-key"]
    assert len(key.public_key_hex) == 64
    assert key.public_key_fingerprint.startswith("sha256:")


def test_resolve_export_signing_key_falls_back_to_runtime_environment(monkeypatch):
    monkeypatch.setattr(signing, "load_secret", lambda name: _base64_seed())
    monkeypatch.setattr(signing, "get_runtime_environment", lambda: "staging")

    signing.resolve_export_signing_key()  # no explicit environment


def test_sign_and_verify_payload_round_trip():
    private_key = Ed25519PrivateKey.generate()
    signature_hex = signing.sign_payload(private_key, b"hello world")

    assert signing.verify_payload_signature(
        private_key.public_key(), b"hello world", signature_hex
    )


def test_verify_payload_signature_rejects_tampered_payload():
    private_key = Ed25519PrivateKey.generate()
    signature_hex = signing.sign_payload(private_key, b"original")

    assert not signing.verify_payload_signature(
        private_key.public_key(), b"tampered", signature_hex
    )


def test_verify_payload_signature_rejects_wrong_key():
    signer_key = Ed25519PrivateKey.generate()
    other_key = Ed25519PrivateKey.generate()
    signature_hex = signing.sign_payload(signer_key, b"hello world")

    assert not signing.verify_payload_signature(
        other_key.public_key(), b"hello world", signature_hex
    )


def test_verify_payload_signature_rejects_malformed_signature_hex():
    private_key = Ed25519PrivateKey.generate()

    assert not signing.verify_payload_signature(
        private_key.public_key(), b"hello world", "not-hex"
    )


def test_public_key_hex_round_trip():
    private_key = Ed25519PrivateKey.generate()
    public_key_hex = signing.public_key_to_hex(private_key.public_key())

    restored = signing.public_key_from_hex(public_key_hex)

    assert signing.public_key_to_hex(restored) == public_key_hex


def test_public_key_fingerprint_is_stable_and_content_derived():
    key_a = Ed25519PrivateKey.generate()
    key_b = Ed25519PrivateKey.generate()

    fingerprint_a1 = signing.public_key_fingerprint(key_a.public_key())
    fingerprint_a2 = signing.public_key_fingerprint(key_a.public_key())
    fingerprint_b = signing.public_key_fingerprint(key_b.public_key())

    assert fingerprint_a1 == fingerprint_a2
    assert fingerprint_a1 != fingerprint_b
    assert fingerprint_a1.startswith("sha256:")
