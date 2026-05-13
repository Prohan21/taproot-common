"""Shared internal trust contract exports."""

from taproot_common.trust.headers import (
    CORRELATION_ID_HEADER,
    INTERNAL_AUTHORIZATION_HEADER,
    extract_bearer_token,
)
from taproot_common.trust.models import (
    DelegatedPrincipal,
    PrincipalType,
    ServicePrincipal,
    principal_from_claims,
)

__all__ = [
    "CORRELATION_ID_HEADER",
    "DelegatedPrincipal",
    "INTERNAL_AUTHORIZATION_HEADER",
    "PrincipalType",
    "ServicePrincipal",
    "extract_bearer_token",
    "principal_from_claims",
]
