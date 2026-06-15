"""FastAPI helpers for signed delegated actor bearer tokens.

Services should use these helpers instead of hand-rolling inconsistent
``DelegatedActorToken*`` to ``HTTPException`` mappings. The helper keeps the
platform-wide contract stable:

- invalid/missing bearer token -> 401
- missing internal service auth secret -> 503
- project mismatch -> 403
"""

from __future__ import annotations

from collections.abc import Iterable

from fastapi import HTTPException, Request, status

from taproot_common.trust import (
    DelegatedActorTokenError,
    DelegatedActorTokenInvalidError,
    DelegatedActorTokenMissingSecretError,
    DelegatedActorTokenProjectMismatchError,
    DelegatedPrincipal,
    verify_delegated_actor_token_from_headers,
)


def delegated_actor_token_http_exception(
    exc: DelegatedActorTokenError,
    *,
    missing_secret_detail: str = "Internal service auth secret is not configured",
) -> HTTPException:
    """Map delegated actor token contract errors to HTTP responses.

    This is intentionally small and boring. The important part is that every
    Taproot FastAPI service fails closed using the same status semantics.
    """

    if isinstance(exc, DelegatedActorTokenProjectMismatchError):
        return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    if isinstance(exc, DelegatedActorTokenMissingSecretError):
        return HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=missing_secret_detail,
        )
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))


def verify_delegated_actor_from_request(
    request: Request,
    *,
    secret: str | None,
    audience: str,
    allowed_subjects: Iterable[str] | str | None = None,
    required_scopes: Iterable[str] | str = ("actor.delegate",),
    expected_project_id: str | None = None,
    missing_secret_detail: str = "Internal service auth secret is not configured",
) -> DelegatedPrincipal:
    """Verify a delegated actor bearer from a FastAPI request.

    Raises ``HTTPException`` with Taproot-standard status mapping. Public actor
    headers remain ignored; only the signed bearer token is trusted.
    """

    try:
        return verify_delegated_actor_token_from_headers(
            request.headers,
            secret=secret,
            audience=audience,
            allowed_subjects=allowed_subjects,
            required_scopes=required_scopes,
            expected_project_id=expected_project_id,
        )
    except (
        DelegatedActorTokenInvalidError,
        DelegatedActorTokenMissingSecretError,
        DelegatedActorTokenProjectMismatchError,
    ) as exc:
        raise delegated_actor_token_http_exception(
            exc,
            missing_secret_detail=missing_secret_detail,
        ) from exc
