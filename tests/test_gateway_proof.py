"""Tests for the gateway shared-secret proof check (WO-012 T1b)."""

import logging

import pytest
from fastapi import HTTPException

from taproot_common.auth import gateway_proof
from taproot_common.auth.gateway_proof import (
    GATEWAY_SECRET_HEADER,
    verify_gateway_proof,
)


@pytest.fixture(autouse=True)
def _reset_state(monkeypatch):
    gateway_proof.reset_gateway_proof_state()
    monkeypatch.setenv("TAPROOT_ENVIRONMENT", "dev")
    yield
    gateway_proof.reset_gateway_proof_state()


def _configure(monkeypatch, *, mode: str, secret: str | None):
    monkeypatch.setenv("TAPROOT_GATEWAY_PROOF_MODE", mode)
    monkeypatch.setattr(
        gateway_proof,
        "_load_expected_secret",
        lambda settings: secret,
    )


class TestOffMode:
    def test_skips_check_entirely(self, monkeypatch):
        _configure(monkeypatch, mode="off", secret="right")
        verify_gateway_proof({GATEWAY_SECRET_HEADER: "wrong"})
        verify_gateway_proof({})


class TestObserveMode:
    def test_match_passes_silently(self, monkeypatch, caplog):
        _configure(monkeypatch, mode="observe", secret="s3cret")
        with caplog.at_level(logging.WARNING):
            verify_gateway_proof({GATEWAY_SECRET_HEADER: "s3cret"})
        assert "auth.gateway_proof.mismatch" not in caplog.text

    def test_mismatch_logs_but_allows(self, monkeypatch, caplog):
        _configure(monkeypatch, mode="observe", secret="s3cret")
        with caplog.at_level(logging.WARNING):
            verify_gateway_proof({GATEWAY_SECRET_HEADER: "forged"})
        assert "auth.gateway_proof.mismatch" in caplog.text

    def test_missing_header_logs_but_allows(self, monkeypatch, caplog):
        _configure(monkeypatch, mode="observe", secret="s3cret")
        with caplog.at_level(logging.WARNING):
            verify_gateway_proof({})
        assert "auth.gateway_proof.mismatch" in caplog.text

    def test_unconfigured_secret_skips_check(self, monkeypatch, caplog):
        _configure(monkeypatch, mode="observe", secret=None)
        with caplog.at_level(logging.WARNING):
            verify_gateway_proof({GATEWAY_SECRET_HEADER: "anything"})
        assert "auth.gateway_proof.mismatch" not in caplog.text
        assert "auth.gateway_proof.unconfigured" in caplog.text

    def test_unconfigured_logs_only_once(self, monkeypatch, caplog):
        _configure(monkeypatch, mode="observe", secret=None)
        with caplog.at_level(logging.WARNING):
            verify_gateway_proof({})
            verify_gateway_proof({})
        assert caplog.text.count("auth.gateway_proof.unconfigured") == 1


class TestEnforceMode:
    def test_match_passes(self, monkeypatch):
        _configure(monkeypatch, mode="enforce", secret="s3cret")
        verify_gateway_proof({GATEWAY_SECRET_HEADER: "s3cret"})

    def test_mismatch_rejected_401(self, monkeypatch):
        _configure(monkeypatch, mode="enforce", secret="s3cret")
        with pytest.raises(HTTPException) as exc_info:
            verify_gateway_proof({GATEWAY_SECRET_HEADER: "forged"})
        assert exc_info.value.status_code == 401

    def test_missing_header_rejected_401(self, monkeypatch):
        _configure(monkeypatch, mode="enforce", secret="s3cret")
        with pytest.raises(HTTPException) as exc_info:
            verify_gateway_proof({})
        assert exc_info.value.status_code == 401

    def test_unconfigured_fails_closed_503(self, monkeypatch):
        _configure(monkeypatch, mode="enforce", secret=None)
        with pytest.raises(HTTPException) as exc_info:
            verify_gateway_proof({GATEWAY_SECRET_HEADER: "anything"})
        assert exc_info.value.status_code == 503

    def test_error_detail_does_not_echo_secret(self, monkeypatch):
        _configure(monkeypatch, mode="enforce", secret="s3cret")
        with pytest.raises(HTTPException) as exc_info:
            verify_gateway_proof({GATEWAY_SECRET_HEADER: "forged"})
        assert "s3cret" not in str(exc_info.value.detail)
        assert "forged" not in str(exc_info.value.detail)


class TestSecretResolution:
    def test_secret_loaded_once_and_cached(self, monkeypatch):
        calls = []

        def fake_loader(settings):
            calls.append(1)
            return "s3cret"

        monkeypatch.setenv("TAPROOT_GATEWAY_PROOF_MODE", "observe")
        monkeypatch.setattr(gateway_proof, "_load_expected_secret", fake_loader)
        verify_gateway_proof({GATEWAY_SECRET_HEADER: "s3cret"})
        verify_gateway_proof({GATEWAY_SECRET_HEADER: "s3cret"})
        assert len(calls) == 1

    def test_canonical_secret_name_derived_from_environment(self, monkeypatch):
        monkeypatch.setenv("TAPROOT_ENVIRONMENT", "staging")
        assert (
            gateway_proof.gateway_secret_name(environment="staging")
            == "taproot-staging-gateway-shared-secret"
        )

    def test_invalid_mode_treated_as_observe(self, monkeypatch, caplog):
        _configure(monkeypatch, mode="bogus", secret="s3cret")
        with caplog.at_level(logging.WARNING):
            verify_gateway_proof({GATEWAY_SECRET_HEADER: "forged"})
        assert "auth.gateway_proof.mismatch" in caplog.text


class TestMiddlewareIntegration:
    async def test_enforce_blocks_forged_request_via_apim_auth(self, monkeypatch):
        from fastapi import FastAPI
        from httpx import ASGITransport, AsyncClient

        from taproot_common import ApimAuth
        from taproot_common.auth.middleware import reset_metadata_store

        monkeypatch.setenv("TAPROOT_CLOUD_PROVIDER", "local")
        monkeypatch.setenv("TAPROOT_METADATA_BACKEND", "memory")
        monkeypatch.setenv("TAPROOT_GATEWAY_PROOF_MODE", "enforce")
        monkeypatch.setattr(
            gateway_proof, "_load_expected_secret", lambda settings: "s3cret"
        )
        reset_metadata_store()
        gateway_proof.reset_gateway_proof_state()

        app = FastAPI()

        @app.get("/protected")
        async def protected(auth: ApimAuth):
            return {"api_key_id": auth.api_key_id}

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            ok = await client.get(
                "/protected", headers={"X-Taproot-Gateway-Secret": "s3cret"}
            )
            forged = await client.get("/protected")

        assert ok.status_code == 200
        assert forged.status_code == 401

        reset_metadata_store()
