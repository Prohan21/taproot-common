"""Tests for the shared internal trust contract."""

import base64
import hashlib
import hmac
import json
import time
from datetime import datetime, timedelta, timezone

import pytest

from taproot_common.trust import (
    DELEGATED_ACTOR_SCOPE,
    DelegatedPrincipal,
    DelegatedActorTokenInvalidError,
    DelegatedActorTokenMissingSecretError,
    DelegatedActorTokenProjectMismatchError,
    HeaderTrustClass,
    InternalTokenError,
    PrincipalType,
    SAFE_OBSERVED_HEADERS,
    ServicePrincipal,
    classify_header,
    extract_bearer_token,
    internal_principal_from_headers,
    is_audit_sensitive_header,
    is_credential_header,
    is_reserved_header,
    is_safe_observed_header,
    mint_delegated_actor_token,
    mint_internal_token,
    principal_from_claims,
    public_ignored_header_names,
    strip_public_ingress_headers,
    verify_delegated_actor_token_from_headers,
    verify_internal_token,
    verify_internal_token_policy,
)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _mint_test_token(
    *,
    secret: str,
    header: dict[str, object],
    payload: dict[str, object],
) -> str:
    encoded_header = _b64url_encode(
        json.dumps(header, separators=(",", ":")).encode("utf-8")
    )
    encoded_payload = _b64url_encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    )
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    signature = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{encoded_header}.{encoded_payload}.{_b64url_encode(signature)}"


def test_extract_bearer_token_returns_token():
    token = extract_bearer_token({"Authorization": "Bearer abc.def.ghi"})
    assert token == "abc.def.ghi"


def test_extract_bearer_token_rejects_non_bearer_values():
    assert extract_bearer_token({"authorization": "Basic xyz"}) is None
    assert extract_bearer_token({"authorization": "Bearer   "}) is None


def test_service_principal_round_trips_through_claims():
    principal = ServicePrincipal(
        service_name="front-s",
        audience="retrieval-s",
        issued_at=datetime(2026, 4, 4, 12, 0, tzinfo=timezone.utc),
        expires_at=datetime(2026, 4, 4, 12, 5, tzinfo=timezone.utc),
        correlation_id="corr-123",
        scopes=("service.read",),
        metadata={"env": "staging"},
    )

    hydrated = principal_from_claims(principal.to_claims())

    assert isinstance(hydrated, ServicePrincipal)
    assert not isinstance(hydrated, DelegatedPrincipal)
    assert hydrated.principal_type is PrincipalType.SERVICE
    assert hydrated.service_name == "front-s"
    assert hydrated.audience == "retrieval-s"
    assert hydrated.scopes == ("service.read",)
    assert hydrated.metadata == {"env": "staging"}


def test_delegated_principal_round_trips_through_claims():
    principal = DelegatedPrincipal(
        service_name="front-s",
        audience="prompt-s",
        issued_at=datetime(2026, 4, 4, 12, 0, tzinfo=timezone.utc),
        expires_at=datetime(2026, 4, 4, 12, 5, tzinfo=timezone.utc),
        actor_user_id="user-123",
        actor_email="user@example.com",
        project_id="project-abc",
        entitlements={"is_admin": True},
    )

    hydrated = principal_from_claims(principal.to_claims())

    assert isinstance(hydrated, DelegatedPrincipal)
    assert hydrated.principal_type is PrincipalType.DELEGATED
    assert hydrated.actor_email == "user@example.com"
    assert hydrated.project_id == "project-abc"
    assert hydrated.entitlements == {"is_admin": True}


def test_service_principal_reports_expiry():
    principal = ServicePrincipal(
        service_name="evals-s",
        audience="front-s",
        issued_at=datetime.now(timezone.utc) - timedelta(minutes=2),
        expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
    )

    assert principal.is_expired is True


def test_internal_token_round_trips_claims():
    token = mint_internal_token(
        secret="shared-secret",
        audience="prompt-s",
        subject="front-s",
        actor_email="actor@example.com",
        additional_claims={"project_id": "project-123"},
        ttl_seconds=300,
    )

    claims = verify_internal_token(
        token,
        secret="shared-secret",
        audience="prompt-s",
    )

    assert claims["sub"] == "front-s"
    assert claims["aud"] == "prompt-s"
    assert isinstance(claims["iat"], int)
    assert isinstance(claims["exp"], int)
    assert claims["exp"] > claims["iat"]
    assert claims["actor_email"] == "actor@example.com"
    assert claims["project_id"] == "project-123"


def test_internal_token_rejects_invalid_signature():
    token = mint_internal_token(
        secret="shared-secret",
        audience="prompt-s",
        subject="front-s",
    )

    with pytest.raises(InternalTokenError, match="signature"):
        verify_internal_token(
            token,
            secret="different-secret",
            audience="prompt-s",
        )


def test_internal_token_rejects_malformed_token():
    with pytest.raises(InternalTokenError, match="Malformed"):
        verify_internal_token(
            "not-a-compact-token",
            secret="shared-secret",
            audience="prompt-s",
        )


def test_internal_token_rejects_audience_mismatch():
    token = mint_internal_token(
        secret="shared-secret",
        audience="prompt-s",
        subject="front-s",
    )

    with pytest.raises(InternalTokenError, match="audience"):
        verify_internal_token(
            token,
            secret="shared-secret",
            audience="worker-s",
        )


def test_internal_token_rejects_unsupported_algorithm():
    token = _mint_test_token(
        secret="shared-secret",
        header={"alg": "HS512", "typ": "JWT"},
        payload={
            "sub": "front-s",
            "aud": "prompt-s",
            "iat": int(time.time()),
            "exp": int(time.time()) + 300,
        },
    )

    with pytest.raises(InternalTokenError, match="algorithm"):
        verify_internal_token(
            token,
            secret="shared-secret",
            audience="prompt-s",
        )


def test_internal_token_rejects_expired_token():
    token = mint_internal_token(
        secret="shared-secret",
        audience="prompt-s",
        subject="front-s",
        ttl_seconds=-1,
    )

    with pytest.raises(InternalTokenError, match="expired"):
        verify_internal_token(
            token,
            secret="shared-secret",
            audience="prompt-s",
        )


def test_internal_token_rejects_reserved_additional_claims():
    with pytest.raises(InternalTokenError, match="Reserved"):
        mint_internal_token(
            secret="shared-secret",
            audience="prompt-s",
            subject="front-s",
            additional_claims={"aud": "worker-s"},
        )


def test_internal_token_policy_accepts_allowed_subject_and_required_scope():
    token = mint_internal_token(
        secret="shared-secret",
        audience="prompt-s",
        subject="front-s",
        additional_claims={"scopes": ["system-record.write", "prompt.manage"]},
    )

    claims = verify_internal_token_policy(
        token,
        secret="shared-secret",
        audience="prompt-s",
        allowed_subjects={"front-s"},
        required_scopes={"system-record.write"},
    )

    assert claims["sub"] == "front-s"


def test_internal_token_policy_accepts_string_subject_and_scope_claim():
    token = mint_internal_token(
        secret="shared-secret",
        audience="front-s",
        subject="evals-s",
        additional_claims={"scope": "agents:execute traces:write"},
    )

    claims = verify_internal_token_policy(
        token,
        secret="shared-secret",
        audience="front-s",
        allowed_subjects="evals-s",
        required_scopes={"agents:execute"},
    )

    assert claims["sub"] == "evals-s"


def test_internal_token_policy_requires_non_empty_subject_policy():
    token = mint_internal_token(
        secret="shared-secret",
        audience="prompt-s",
        subject="front-s",
        additional_claims={"scopes": ["system-record.write"]},
    )

    with pytest.raises(InternalTokenError, match="allowed subjects"):
        verify_internal_token_policy(
            token,
            secret="shared-secret",
            audience="prompt-s",
            allowed_subjects=set(),
            required_scopes={"system-record.write"},
        )


def test_internal_token_policy_requires_non_empty_scope_policy():
    token = mint_internal_token(
        secret="shared-secret",
        audience="prompt-s",
        subject="front-s",
        additional_claims={"scopes": ["system-record.write"]},
    )

    with pytest.raises(InternalTokenError, match="required scopes"):
        verify_internal_token_policy(
            token,
            secret="shared-secret",
            audience="prompt-s",
            allowed_subjects={"front-s"},
            required_scopes=set(),
        )


def test_internal_token_policy_rejects_audience_mismatch():
    token = mint_internal_token(
        secret="shared-secret",
        audience="prompt-s",
        subject="front-s",
        additional_claims={"scope": "system-record.write"},
    )

    with pytest.raises(InternalTokenError, match="audience"):
        verify_internal_token_policy(
            token,
            secret="shared-secret",
            audience="worker-s",
            allowed_subjects={"front-s"},
            required_scopes={"system-record.write"},
        )


def test_internal_token_policy_rejects_disallowed_subject():
    token = mint_internal_token(
        secret="shared-secret",
        audience="prompt-s",
        subject="worker-s",
        additional_claims={"scopes": ["system-record.write"]},
    )

    with pytest.raises(InternalTokenError, match="subject"):
        verify_internal_token_policy(
            token,
            secret="shared-secret",
            audience="prompt-s",
            allowed_subjects={"front-s"},
            required_scopes={"system-record.write"},
        )


def test_internal_token_policy_rejects_missing_required_scope():
    token = mint_internal_token(
        secret="shared-secret",
        audience="prompt-s",
        subject="front-s",
        additional_claims={"scopes": ["prompt.manage"]},
    )

    with pytest.raises(InternalTokenError, match="scope"):
        verify_internal_token_policy(
            token,
            secret="shared-secret",
            audience="prompt-s",
            allowed_subjects={"front-s"},
            required_scopes={"system-record.write"},
        )


def test_internal_token_policy_rejects_invalid_scope_claim_type():
    token = mint_internal_token(
        secret="shared-secret",
        audience="prompt-s",
        subject="front-s",
        additional_claims={"scopes": {"system-record.write": True}},
    )

    with pytest.raises(InternalTokenError, match="Invalid internal token scopes"):
        verify_internal_token_policy(
            token,
            secret="shared-secret",
            audience="prompt-s",
            allowed_subjects={"front-s"},
            required_scopes={"system-record.write"},
        )


def test_delegated_actor_token_round_trips_from_authorization_header():
    token = mint_delegated_actor_token(
        secret="shared-secret",
        audience="guardrail-s",
        subject="front-s",
        actor_email="user@example.com",
        actor_user_id="user-123",
        scopes={"guardrail.scan"},
        project_id="project-123",
        correlation_id="corr-123",
        additional_claims={"metadata": {"route": "scan"}},
    )

    principal = verify_delegated_actor_token_from_headers(
        {
            "Authorization": f"Bearer {token}",
            "X-Actor-Identity": "spoofed@example.com",
        },
        secret="shared-secret",
        audience="guardrail-s",
        allowed_subjects={"front-s"},
        required_scopes={DELEGATED_ACTOR_SCOPE, "guardrail.scan"},
        expected_project_id="project-123",
    )

    assert principal.principal_type is PrincipalType.DELEGATED
    assert principal.service_name == "front-s"
    assert principal.audience == "guardrail-s"
    assert principal.actor_email == "user@example.com"
    assert principal.actor_user_id == "user-123"
    assert principal.project_id == "project-123"
    assert principal.correlation_id == "corr-123"
    assert principal.metadata == {"route": "scan"}
    assert DELEGATED_ACTOR_SCOPE in principal.scopes
    assert "guardrail.scan" in principal.scopes


def test_mint_delegated_actor_token_rejects_missing_actor_and_long_ttl():
    with pytest.raises(DelegatedActorTokenInvalidError, match="actor_email"):
        mint_delegated_actor_token(
            secret="shared-secret",
            audience="guardrail-s",
            subject="front-s",
        )

    with pytest.raises(DelegatedActorTokenInvalidError, match="ttl_seconds"):
        mint_delegated_actor_token(
            secret="shared-secret",
            audience="guardrail-s",
            subject="front-s",
            actor_email="user@example.com",
            ttl_seconds=301,
        )


def test_delegated_actor_token_verification_distinguishes_missing_secret():
    with pytest.raises(DelegatedActorTokenMissingSecretError, match="secret"):
        verify_delegated_actor_token_from_headers(
            {"Authorization": "Bearer anything"},
            secret=None,
            audience="guardrail-s",
        )


def test_delegated_actor_token_verification_rejects_wrong_audience():
    token = mint_delegated_actor_token(
        secret="shared-secret",
        audience="prompt-s",
        subject="front-s",
        actor_email="user@example.com",
    )

    with pytest.raises(DelegatedActorTokenInvalidError, match="audience"):
        verify_delegated_actor_token_from_headers(
            {"Authorization": f"Bearer {token}"},
            secret="shared-secret",
            audience="guardrail-s",
        )


def test_delegated_actor_token_verification_rejects_disallowed_subject():
    token = mint_delegated_actor_token(
        secret="shared-secret",
        audience="guardrail-s",
        subject="worker-s",
        actor_email="user@example.com",
    )

    with pytest.raises(DelegatedActorTokenInvalidError, match="subject"):
        verify_delegated_actor_token_from_headers(
            {"Authorization": f"Bearer {token}"},
            secret="shared-secret",
            audience="guardrail-s",
            allowed_subjects={"front-s"},
        )


def test_delegated_actor_token_verification_rejects_missing_scope():
    token = mint_delegated_actor_token(
        secret="shared-secret",
        audience="guardrail-s",
        subject="front-s",
        actor_email="user@example.com",
    )

    with pytest.raises(DelegatedActorTokenInvalidError, match="scope"):
        verify_delegated_actor_token_from_headers(
            {"Authorization": f"Bearer {token}"},
            secret="shared-secret",
            audience="guardrail-s",
            required_scopes={DELEGATED_ACTOR_SCOPE, "guardrail.scan"},
        )


def test_delegated_actor_token_verification_rejects_wrong_principal_type():
    token = mint_internal_token(
        secret="shared-secret",
        audience="guardrail-s",
        subject="front-s",
        additional_claims={
            "principal_type": "service",
            "actor_email": "user@example.com",
            "scopes": [DELEGATED_ACTOR_SCOPE],
        },
    )

    with pytest.raises(DelegatedActorTokenInvalidError, match="principal_type"):
        verify_delegated_actor_token_from_headers(
            {"Authorization": f"Bearer {token}"},
            secret="shared-secret",
            audience="guardrail-s",
        )


def test_delegated_actor_token_verification_rejects_missing_actor_claim():
    token = mint_internal_token(
        secret="shared-secret",
        audience="guardrail-s",
        subject="front-s",
        additional_claims={
            "principal_type": "delegated",
            "scopes": [DELEGATED_ACTOR_SCOPE],
        },
    )

    with pytest.raises(DelegatedActorTokenInvalidError, match="actor_email"):
        verify_delegated_actor_token_from_headers(
            {"Authorization": f"Bearer {token}"},
            secret="shared-secret",
            audience="guardrail-s",
        )


def test_delegated_actor_token_verification_rejects_expired_token():
    token = mint_internal_token(
        secret="shared-secret",
        audience="guardrail-s",
        subject="front-s",
        additional_claims={
            "principal_type": "delegated",
            "actor_email": "user@example.com",
            "scopes": [DELEGATED_ACTOR_SCOPE],
        },
        ttl_seconds=-1,
    )

    with pytest.raises(DelegatedActorTokenInvalidError, match="expired"):
        verify_delegated_actor_token_from_headers(
            {"Authorization": f"Bearer {token}"},
            secret="shared-secret",
            audience="guardrail-s",
        )


def test_delegated_actor_token_verification_distinguishes_project_mismatch():
    token = mint_delegated_actor_token(
        secret="shared-secret",
        audience="guardrail-s",
        subject="front-s",
        actor_email="user@example.com",
        project_id="project-123",
    )

    with pytest.raises(DelegatedActorTokenProjectMismatchError, match="project"):
        verify_delegated_actor_token_from_headers(
            {"Authorization": f"Bearer {token}"},
            secret="shared-secret",
            audience="guardrail-s",
            expected_project_id="project-456",
        )


def test_header_taxonomy_classifies_safe_and_reserved_headers():
    assert "x-correlation-id" in SAFE_OBSERVED_HEADERS
    assert classify_header("X-Correlation-ID") is HeaderTrustClass.SAFE_OBSERVED
    assert classify_header("traceparent") is HeaderTrustClass.SAFE_OBSERVED
    assert classify_header("X-Taproot-Caller-Id") is HeaderTrustClass.AUDIT_SENSITIVE
    assert classify_header("X-Api-Key-Id") is HeaderTrustClass.CREDENTIAL
    assert classify_header("baggage") is HeaderTrustClass.UNSAFE_BAGGAGE
    assert is_safe_observed_header("X-Request-ID") is True
    assert is_audit_sensitive_header("X-Actor-Identity") is True
    assert is_credential_header("x-api-key") is True
    assert is_reserved_header("X-Taproot-Parent-Activity-Id") is True
    assert is_reserved_header("X-Correlation-ID") is False


def test_public_ingress_strips_reserved_headers_case_insensitively():
    sanitized = strip_public_ingress_headers(
        {
            "X-Correlation-ID": "corr-1",
            "X-Taproot-Interaction-Id": "public-hint",
            "X-Taproot-Caller-Id": "spoof-user",
            "x-api-key-id": "spoof-key",
            "Baggage": "actor=spoof",
            "X-Custom": "kept",
        }
    )

    assert sanitized == {"X-Correlation-ID": "corr-1", "X-Custom": "kept"}


def test_public_ignored_headers_exclude_accepted_interaction_hint():
    ignored = public_ignored_header_names(
        {
            "X-Taproot-Interaction-Id": "public-hint",
            "X-Taproot-Caller-Id": "spoof-user",
            "X-Taproot-Parent-Activity-Id": "spoof-parent",
            "X-Api-Key-Id": "spoof-key",
        }
    )

    assert "x-taproot-interaction-id" not in ignored
    assert "x-taproot-caller-id" in ignored
    assert "x-taproot-parent-activity-id" in ignored
    assert "x-api-key-id" in ignored


def test_internal_principal_from_headers_verifies_token():
    token = mint_internal_token(
        secret="shared-secret",
        audience="prompt-s",
        subject="front-s",
        additional_claims={"principal_type": "service"},
    )

    principal = internal_principal_from_headers(
        {"Authorization": f"Bearer {token}"},
        secret="shared-secret",
        audience="prompt-s",
    )

    assert principal.service_name == "front-s"
    assert principal.audience == "prompt-s"


def test_internal_principal_from_headers_fails_closed_without_valid_token():
    with pytest.raises(InternalTokenError, match="Missing"):
        internal_principal_from_headers({}, secret="shared-secret", audience="prompt-s")

    token = mint_internal_token(
        secret="shared-secret",
        audience="prompt-s",
        subject="front-s",
    )
    with pytest.raises(InternalTokenError, match="signature"):
        internal_principal_from_headers(
            {"Authorization": f"Bearer {token}"},
            secret="wrong-secret",
            audience="prompt-s",
        )
