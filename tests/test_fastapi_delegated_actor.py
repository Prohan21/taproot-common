"""Tests for shared FastAPI delegated actor helpers."""

from fastapi import HTTPException, status
from starlette.requests import Request

from taproot_common.fastapi import verify_delegated_actor_from_request
from taproot_common.trust import mint_delegated_actor_token


def _request(token: str | None) -> Request:
    headers: list[tuple[bytes, bytes]] = []
    if token is not None:
        headers.append((b"authorization", f"Bearer {token}".encode("ascii")))
    headers.append((b"x-actor-identity", b"spoofed@example.com"))
    return Request({"type": "http", "method": "GET", "path": "/", "headers": headers})


def test_verify_delegated_actor_from_request_returns_signed_principal() -> None:
    token = mint_delegated_actor_token(
        secret="shared-secret",
        audience="worker-s",
        subject="front-s",
        actor_email="user@example.com",
        scopes={"worker-s:session:create"},
        project_id="project-123",
    )

    principal = verify_delegated_actor_from_request(
        _request(token),
        secret="shared-secret",
        audience="worker-s",
        allowed_subjects={"front-s"},
        required_scopes={"actor.delegate", "worker-s:session:create"},
        expected_project_id="project-123",
    )

    assert principal.service_name == "front-s"
    assert principal.actor_email == "user@example.com"
    assert principal.project_id == "project-123"


def test_verify_delegated_actor_from_request_maps_missing_secret_to_503() -> None:
    try:
        verify_delegated_actor_from_request(
            _request("anything"),
            secret="",
            audience="worker-s",
        )
    except HTTPException as exc:
        assert exc.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        assert exc.detail == "Internal service auth secret is not configured"
    else:  # pragma: no cover - defensive
        raise AssertionError("missing secret should fail closed")


def test_verify_delegated_actor_from_request_maps_project_mismatch_to_403() -> None:
    token = mint_delegated_actor_token(
        secret="shared-secret",
        audience="worker-s",
        subject="front-s",
        actor_email="user@example.com",
        project_id="project-123",
    )

    try:
        verify_delegated_actor_from_request(
            _request(token),
            secret="shared-secret",
            audience="worker-s",
            expected_project_id="project-456",
        )
    except HTTPException as exc:
        assert exc.status_code == status.HTTP_403_FORBIDDEN
        assert "project" in str(exc.detail)
    else:  # pragma: no cover - defensive
        raise AssertionError("project mismatch should fail closed")


def test_verify_delegated_actor_from_request_maps_invalid_token_to_401() -> None:
    try:
        verify_delegated_actor_from_request(
            _request(None),
            secret="shared-secret",
            audience="worker-s",
        )
    except HTTPException as exc:
        assert exc.status_code == status.HTTP_401_UNAUTHORIZED
        assert "bearer" in str(exc.detail)
    else:  # pragma: no cover - defensive
        raise AssertionError("missing bearer should fail closed")
