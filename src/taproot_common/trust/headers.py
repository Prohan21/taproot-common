"""Helpers for internal trust headers and context header policy.

The policy helpers intentionally distinguish values that are safe to observe
from values that are reserved for Taproot-controlled boundaries. Public callers
may send correlation and trace metadata, but they are never authoritative for
actor, project, API-key, parent-activity, service-principal, or audit context.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum

from taproot_common.trust.models import ServicePrincipal, principal_from_claims
from taproot_common.trust.tokens import InternalTokenError, verify_internal_token


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
