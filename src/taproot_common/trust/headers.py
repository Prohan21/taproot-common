"""Helpers for internal trust headers and context header policy.

The policy helpers intentionally distinguish values that are safe to observe
from values that are reserved for Taproot-controlled boundaries. Public callers
may send correlation and trace metadata, but they are never authoritative for
actor, project, API-key, parent interaction/activity, service-principal, or
audit context.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from enum import StrEnum
from typing import Any

from taproot_common.trust.models import (
    DelegatedPrincipal,
    PrincipalType,
    ServicePrincipal,
    principal_from_claims,
)
from taproot_common.trust.tokens import (
    DELEGATED_ACTOR_SCOPE,
    DelegatedActorTokenInvalidError,
    DelegatedActorTokenMissingSecretError,
    DelegatedActorTokenProjectMismatchError,
    InternalTokenError,
    verify_internal_token,
)


INTERNAL_AUTHORIZATION_HEADER = "authorization"
CORRELATION_ID_HEADER = "x-correlation-id"
REQUEST_ID_HEADER = "x-request-id"
TRACEPARENT_HEADER = "traceparent"
TRACESTATE_HEADER = "tracestate"
BAGGAGE_HEADER = "baggage"


class HeaderTrustClass(StrEnum):
    """Trust classification for inbound/outbound propagation headers."""

    SAFE_OBSERVED = "safe_observed"
    RESERVED_CONTEXT = "reserved_context"
    AUDIT_SENSITIVE = "audit_sensitive"
    CREDENTIAL = "credential"
    UNSAFE_BAGGAGE = "unsafe_baggage"


SAFE_OBSERVED_HEADERS: frozenset[str] = frozenset(
    {
        CORRELATION_ID_HEADER,
        REQUEST_ID_HEADER,
        TRACEPARENT_HEADER,
        TRACESTATE_HEADER,
    }
)

RESERVED_CONTEXT_HEADERS: frozenset[str] = frozenset(
    {
        "x-taproot-activity-version",
        "x-taproot-interaction-id",
        "x-taproot-interaction-type",
        "x-taproot-source-agent-id",
        "x-taproot-root-agent-id",
    }
)

PUBLIC_INTERACTION_HINT_HEADERS: frozenset[str] = frozenset(
    {
        "x-taproot-interaction-id",
    }
)

AUDIT_SENSITIVE_HEADERS: frozenset[str] = frozenset(
    {
        "x-actor-identity",
        "x-trusted-proxy-secret",
        "x-taproot-caller-id",
        "x-taproot-caller-type",
        "x-taproot-parent-interaction-id",
        "x-taproot-parent-activity-id",
    }
)

CREDENTIAL_HEADERS: frozenset[str] = frozenset(
    {
        "x-api-key-id",
        "x-api-key",
        "x-endpoint-api-userinfo",
        INTERNAL_AUTHORIZATION_HEADER,
    }
)

UNSAFE_BAGGAGE_HEADERS: frozenset[str] = frozenset({BAGGAGE_HEADER})

RESERVED_HEADERS: frozenset[str] = frozenset(
    RESERVED_CONTEXT_HEADERS
    | AUDIT_SENSITIVE_HEADERS
    | CREDENTIAL_HEADERS
    | UNSAFE_BAGGAGE_HEADERS
)

PUBLIC_STRIP_HEADERS: frozenset[str] = frozenset(
    RESERVED_CONTEXT_HEADERS
    | AUDIT_SENSITIVE_HEADERS
    | CREDENTIAL_HEADERS
    | UNSAFE_BAGGAGE_HEADERS
)


def extract_bearer_token(headers: Mapping[str, str]) -> str | None:
    """Extract a bearer token from a case-insensitive header mapping."""

    raw = header_value(headers, INTERNAL_AUTHORIZATION_HEADER) or ""
    if not raw:
        return None
    scheme, _, token = raw.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


def normalize_header_name(name: str) -> str:
    """Normalize a header name for case-insensitive policy checks."""

    return name.strip().lower()


def header_value(headers: Mapping[str, str], name: str) -> str | None:
    """Return a header value with case-insensitive matching."""

    lower_name = normalize_header_name(name)
    for key, value in headers.items():
        if normalize_header_name(key) == lower_name and value:
            return value
    return None


def classify_header(name: str) -> HeaderTrustClass | None:
    """Classify a header according to the Taproot context trust contract."""

    normalized = normalize_header_name(name)
    if normalized in SAFE_OBSERVED_HEADERS:
        return HeaderTrustClass.SAFE_OBSERVED
    if normalized in AUDIT_SENSITIVE_HEADERS:
        return HeaderTrustClass.AUDIT_SENSITIVE
    if normalized in CREDENTIAL_HEADERS:
        return HeaderTrustClass.CREDENTIAL
    if normalized in UNSAFE_BAGGAGE_HEADERS:
        return HeaderTrustClass.UNSAFE_BAGGAGE
    if normalized in RESERVED_CONTEXT_HEADERS:
        return HeaderTrustClass.RESERVED_CONTEXT
    return None


def is_safe_observed_header(name: str) -> bool:
    """Return true when a public caller may provide this observability value."""

    return classify_header(name) is HeaderTrustClass.SAFE_OBSERVED


def is_audit_sensitive_header(name: str) -> bool:
    """Return true for actor/caller/parent headers that need verification."""

    return classify_header(name) is HeaderTrustClass.AUDIT_SENSITIVE


def is_credential_header(name: str) -> bool:
    """Return true for headers carrying API keys or internal bearer tokens."""

    return classify_header(name) is HeaderTrustClass.CREDENTIAL


def is_reserved_header(name: str) -> bool:
    """Return true for headers controlled by Taproot trust boundaries."""

    header_class = classify_header(name)
    return (
        header_class is not None and header_class is not HeaderTrustClass.SAFE_OBSERVED
    )


def strip_reserved_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Return headers with Taproot-reserved values removed case-insensitively."""

    return {key: value for key, value in headers.items() if not is_reserved_header(key)}


def strip_public_ingress_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Remove values public ingress must not treat as trusted context."""

    return {
        key: value
        for key, value in headers.items()
        if normalize_header_name(key) not in PUBLIC_STRIP_HEADERS
    }


def public_ignored_header_names(headers: Mapping[str, str]) -> tuple[str, ...]:
    """Return normalized trust-sensitive header names ignored at public ingress.

    Public interaction IDs are excluded here because they may be recorded as
    untrusted grouping hints on ``ObservedRequestContext``. They remain reserved
    context headers and must still be stripped before forwarding or trusting.
    """

    ignored_public_headers = PUBLIC_STRIP_HEADERS - PUBLIC_INTERACTION_HINT_HEADERS

    ignored = {
        normalize_header_name(key)
        for key in headers
        if normalize_header_name(key) in ignored_public_headers
    }
    return tuple(sorted(ignored))


def internal_principal_from_headers(
    headers: Mapping[str, str],
    *,
    secret: str,
    audience: str,
) -> ServicePrincipal:
    """Verify an internal bearer token and hydrate its principal.

    Missing, malformed, expired, wrong-audience, and bad-signature inputs all
    raise :class:`InternalTokenError`; callers must treat that as fail-closed.
    """

    token = extract_bearer_token(headers)
    if token is None:
        raise InternalTokenError("Missing internal bearer token")
    claims = verify_internal_token(token, secret=secret, audience=audience)
    return principal_from_claims(claims)


def verify_delegated_actor_token_from_headers(
    headers: Mapping[str, str],
    *,
    secret: str | None,
    audience: str,
    allowed_subjects: Iterable[str] | str | None = None,
    required_scopes: Iterable[str] | str = (DELEGATED_ACTOR_SCOPE,),
    expected_project_id: str | None = None,
) -> DelegatedPrincipal:
    """Verify a signed delegated actor bearer token from Authorization headers.

    The only trusted carrier is ``Authorization: Bearer <taproot internal
    token>``. Public actor headers are deliberately ignored by this helper; the
    returned actor identity must come from signed token claims.

    Error subclasses are intentionally specific so service layers can map them:

    - :class:`DelegatedActorTokenInvalidError` -> 401
    - :class:`DelegatedActorTokenMissingSecretError` -> 503
    - :class:`DelegatedActorTokenProjectMismatchError` -> 403
    """

    if not isinstance(secret, str) or not secret.strip():
        raise DelegatedActorTokenMissingSecretError(
            "Delegated actor token verification requires internal auth secret"
        )

    token = extract_bearer_token(headers)
    if token is None:
        raise DelegatedActorTokenInvalidError("Missing delegated actor bearer token")

    try:
        claims = verify_internal_token(token, secret=secret, audience=audience)
    except InternalTokenError as exc:
        raise DelegatedActorTokenInvalidError(str(exc)) from exc

    _verify_delegated_actor_claims(
        claims,
        allowed_subjects=allowed_subjects,
        required_scopes=required_scopes,
        expected_project_id=expected_project_id,
    )

    principal = principal_from_claims(dict(claims))
    if not isinstance(principal, DelegatedPrincipal):
        raise DelegatedActorTokenInvalidError(
            "Delegated actor token principal_type must be delegated"
        )

    return DelegatedPrincipal(
        service_name=str(claims["sub"]),
        audience=str(claims["aud"]),
        issued_at=principal.issued_at,
        expires_at=principal.expires_at,
        correlation_id=str(claims["correlation_id"])
        if claims.get("correlation_id")
        else None,
        scopes=tuple(sorted(_scopes_from_claims(claims))),
        metadata=dict(claims.get("metadata", {})),
        actor_user_id=str(claims["actor_user_id"])
        if claims.get("actor_user_id")
        else None,
        actor_email=str(claims["actor_email"]) if claims.get("actor_email") else None,
        project_id=str(claims["project_id"]) if claims.get("project_id") else None,
        entitlements=dict(claims.get("entitlements", {})),
    )


def _verify_delegated_actor_claims(
    claims: Mapping[str, Any],
    *,
    allowed_subjects: Iterable[str] | str | None,
    required_scopes: Iterable[str] | str,
    expected_project_id: str | None,
) -> None:
    subject = _required_string_claim(claims, "sub")
    _required_string_claim(claims, "aud")
    _required_int_claim(claims, "iat")
    _required_int_claim(claims, "exp")

    if claims.get("principal_type") != PrincipalType.DELEGATED.value:
        raise DelegatedActorTokenInvalidError(
            "Delegated actor token principal_type must be delegated"
        )

    actor_email = _optional_string_claim(claims, "actor_email")
    actor_user_id = _optional_string_claim(claims, "actor_user_id")
    if not actor_email and not actor_user_id:
        raise DelegatedActorTokenInvalidError(
            "Delegated actor token requires actor_email or actor_user_id"
        )

    subject_policy = _normalize_policy_values(
        allowed_subjects, policy_name="allowed subjects", required=False
    )
    if subject_policy and subject not in subject_policy:
        raise DelegatedActorTokenInvalidError(
            "Delegated actor token subject not allowed"
        )

    scope_policy = _normalize_policy_values(
        required_scopes, policy_name="required scopes", required=True
    )
    token_scopes = _scopes_from_claims(claims)
    if scope_policy - token_scopes:
        raise DelegatedActorTokenInvalidError(
            "Delegated actor token missing required scope"
        )

    token_project_id = _optional_string_claim(claims, "project_id")
    expected_project_id = expected_project_id.strip() if expected_project_id else None
    if (
        token_project_id
        and expected_project_id
        and token_project_id != expected_project_id
    ):
        raise DelegatedActorTokenProjectMismatchError(
            "Delegated actor token project mismatch"
        )


def _required_string_claim(claims: Mapping[str, Any], claim_name: str) -> str:
    value = claims.get(claim_name)
    if not isinstance(value, str) or not value.strip():
        raise DelegatedActorTokenInvalidError(
            f"Delegated actor token requires {claim_name}"
        )
    return value.strip()


def _required_int_claim(claims: Mapping[str, Any], claim_name: str) -> int:
    value = claims.get(claim_name)
    if not isinstance(value, int):
        raise DelegatedActorTokenInvalidError(
            f"Delegated actor token requires {claim_name}"
        )
    return value


def _optional_string_claim(claims: Mapping[str, Any], claim_name: str) -> str | None:
    value = claims.get(claim_name)
    if value is None:
        return None
    if not isinstance(value, str):
        raise DelegatedActorTokenInvalidError(
            f"Delegated actor token {claim_name} must be a string"
        )
    stripped = value.strip()
    return stripped or None


def _normalize_policy_values(
    values: Iterable[str] | str | None,
    *,
    policy_name: str,
    required: bool,
) -> frozenset[str]:
    if values is None:
        if required:
            raise DelegatedActorTokenInvalidError(
                f"Delegated actor token policy requires {policy_name}"
            )
        return frozenset()
    if isinstance(values, str):
        values = (values,)

    normalized = set()
    for value in values:
        if not isinstance(value, str) or not value.strip():
            raise DelegatedActorTokenInvalidError(
                f"Delegated actor token policy requires non-empty {policy_name}"
            )
        normalized.add(value.strip())

    if required and not normalized:
        raise DelegatedActorTokenInvalidError(
            f"Delegated actor token policy requires {policy_name}"
        )
    return frozenset(normalized)


def _scopes_from_claims(claims: Mapping[str, Any]) -> frozenset[str]:
    scopes = claims.get("scopes")
    if scopes is None:
        scopes = claims.get("scope", ())
    if isinstance(scopes, str):
        return frozenset(scope for scope in scopes.split() if scope)
    if isinstance(scopes, Mapping):
        raise DelegatedActorTokenInvalidError("Invalid delegated actor token scopes")
    try:
        token_scopes = set()
        for scope in scopes:
            if not isinstance(scope, str):
                raise DelegatedActorTokenInvalidError(
                    "Invalid delegated actor token scopes"
                )
            if scope:
                token_scopes.add(scope)
        return frozenset(token_scopes)
    except TypeError as exc:
        raise DelegatedActorTokenInvalidError(
            "Invalid delegated actor token scopes"
        ) from exc
