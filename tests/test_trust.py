"""Tests for the shared internal trust contract."""

from datetime import datetime, timedelta, timezone

from taproot_common.trust import (
    DelegatedPrincipal,
    PrincipalType,
    ServicePrincipal,
    extract_bearer_token,
    principal_from_claims,
)


def test_extract_bearer_token_returns_token():
    token = extract_bearer_token({"authorization": "Bearer abc.def.ghi"})
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
