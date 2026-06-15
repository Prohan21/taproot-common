"""Compact HMAC-signed internal bearer token helpers.

The token format intentionally mirrors the existing Prompt-S Phase 1 internal
token behavior: a compact ``header.payload.signature`` value with HS256-style
HMAC signing, JSON claims, and base64url encoding without padding. Service
configuration owns secret loading and audience choices; this module stays
provider-neutral and dependency-free.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import time
from collections.abc import Iterable, Mapping
from typing import Any

from taproot_common.trust.models import PrincipalType


class InternalTokenError(ValueError):
    """Raised when an internal bearer token cannot be minted or verified."""


class DelegatedActorTokenError(InternalTokenError):
    """Base error for delegated actor token contract failures."""


class DelegatedActorTokenInvalidError(DelegatedActorTokenError):
    """Raised when a delegated actor token should be mapped to authentication failure."""


class DelegatedActorTokenMissingSecretError(DelegatedActorTokenError):
    """Raised when verification is required but no internal auth secret is configured."""


class DelegatedActorTokenProjectMismatchError(DelegatedActorTokenError):
    """Raised when delegated token project metadata conflicts with route context."""


_ALGORITHM = "HS256"
_HEADER = {"alg": _ALGORITHM, "typ": "JWT"}
_RESERVED_CLAIMS = frozenset({"sub", "aud", "iat", "exp"})
DELEGATED_ACTOR_SCOPE = "actor.delegate"
MAX_DELEGATED_ACTOR_TTL_SECONDS = 300
_DELEGATED_ACTOR_RESERVED_CLAIMS = frozenset(
    {
        "principal_type",
        "actor_email",
        "actor_user_id",
        "scopes",
        "scope",
        "project_id",
        "correlation_id",
    }
)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(f"{data}{padding}")


def _json_b64url(data: Mapping[str, Any]) -> str:
    try:
        serialized = json.dumps(data, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise InternalTokenError("Invalid internal token claims") from exc
    return _b64url_encode(serialized)


def mint_internal_token(
    *,
    secret: str,
    audience: str,
    subject: str,
    actor_email: str | None = None,
    additional_claims: Mapping[str, Any] | None = None,
    ttl_seconds: int = 300,
) -> str:
    """Create a compact HMAC-signed bearer token for internal use.

    ``additional_claims`` supports service-local migration needs such as
    delegated actor or project metadata. Core token claims are reserved so
    callers cannot accidentally override the subject, audience, issue time, or
    expiry that verification depends on.
    """

    now = int(time.time())
    payload: dict[str, Any] = {
        "sub": subject,
        "aud": audience,
        "iat": now,
        "exp": now + ttl_seconds,
    }
    if actor_email:
        payload["actor_email"] = actor_email

    if additional_claims:
        reserved = _RESERVED_CLAIMS.intersection(additional_claims)
        if reserved:
            names = ", ".join(sorted(reserved))
            raise InternalTokenError(f"Reserved internal token claims: {names}")
        payload.update(additional_claims)

    encoded_header = _json_b64url(_HEADER)
    encoded_payload = _json_b64url(payload)
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    signature = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    encoded_signature = _b64url_encode(signature)
    return f"{encoded_header}.{encoded_payload}.{encoded_signature}"


def mint_delegated_actor_token(
    *,
    secret: str,
    audience: str,
    subject: str,
    actor_email: str | None = None,
    actor_user_id: str | None = None,
    scopes: Iterable[str] | None = None,
    project_id: str | None = None,
    correlation_id: str | None = None,
    additional_claims: Mapping[str, Any] | None = None,
    ttl_seconds: int = MAX_DELEGATED_ACTOR_TTL_SECONDS,
) -> str:
    """Mint a short-lived signed delegated actor token.

    Delegated actor tokens are the Taproot-internal, cloud-neutral carrier for
    user-on-behalf-of provenance. They intentionally use the same compact HMAC
    primitive as other internal tokens while enforcing the delegated claim shape
    services need to fail closed: ``principal_type=delegated``, at least one
    actor identity claim, and ``actor.delegate`` in ``scopes``.

    Secret loading and storage remains a service concern. Callers should pass an
    internal service auth secret, not ``TRUSTED_PROXY_SECRET``.
    """

    if not isinstance(secret, str) or not secret.strip():
        raise DelegatedActorTokenMissingSecretError(
            "Delegated actor token minting requires internal auth secret"
        )
    if not isinstance(audience, str) or not audience.strip():
        raise DelegatedActorTokenInvalidError(
            "Delegated actor token requires non-empty audience"
        )
    if not isinstance(subject, str) or not subject.strip():
        raise DelegatedActorTokenInvalidError(
            "Delegated actor token requires non-empty subject"
        )
    actor_email = _optional_non_empty_claim(actor_email, claim_name="actor_email")
    actor_user_id = _optional_non_empty_claim(
        actor_user_id, claim_name="actor_user_id"
    )
    if not actor_email and not actor_user_id:
        raise DelegatedActorTokenInvalidError(
            "Delegated actor token requires actor_email or actor_user_id"
        )
    project_id = _optional_non_empty_claim(project_id, claim_name="project_id")
    correlation_id = _optional_non_empty_claim(
        correlation_id, claim_name="correlation_id"
    )

    if ttl_seconds <= 0 or ttl_seconds > MAX_DELEGATED_ACTOR_TTL_SECONDS:
        raise DelegatedActorTokenInvalidError(
            "Delegated actor token ttl_seconds must be between 1 and 300"
        )

    try:
        delegated_scopes = set(_claim_scopes({"scopes": scopes or ()}))
    except InternalTokenError as exc:
        raise DelegatedActorTokenInvalidError(str(exc)) from exc
    delegated_scopes.add(DELEGATED_ACTOR_SCOPE)

    claims: dict[str, Any] = {
        "principal_type": PrincipalType.DELEGATED.value,
        "scopes": sorted(delegated_scopes),
    }
    if actor_email:
        claims["actor_email"] = actor_email
    if actor_user_id:
        claims["actor_user_id"] = actor_user_id
    if project_id:
        claims["project_id"] = project_id
    if correlation_id:
        claims["correlation_id"] = correlation_id

    if additional_claims:
        reserved = (_RESERVED_CLAIMS | _DELEGATED_ACTOR_RESERVED_CLAIMS).intersection(
            additional_claims
        )
        if reserved:
            names = ", ".join(sorted(reserved))
            raise DelegatedActorTokenInvalidError(
                f"Reserved delegated actor token claims: {names}"
            )
        claims.update(additional_claims)

    return mint_internal_token(
        secret=secret,
        audience=audience,
        subject=subject,
        additional_claims=claims,
        ttl_seconds=ttl_seconds,
    )


def verify_internal_token(token: str, *, secret: str, audience: str) -> dict[str, Any]:
    """Verify a compact HMAC-signed internal bearer token."""

    parts = token.split(".")
    if len(parts) != 3:
        raise InternalTokenError("Malformed internal token")

    encoded_header, encoded_payload, encoded_signature = parts
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    expected_signature = _b64url_encode(
        hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    )
    if not hmac.compare_digest(encoded_signature, expected_signature):
        raise InternalTokenError("Invalid internal token signature")

    try:
        header = json.loads(_b64url_decode(encoded_header))
        payload = json.loads(_b64url_decode(encoded_payload))
    except (
        binascii.Error,
        json.JSONDecodeError,
        TypeError,
        UnicodeDecodeError,
        ValueError,
    ) as exc:
        raise InternalTokenError("Invalid internal token encoding") from exc

    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise InternalTokenError("Invalid internal token payload")
    if header.get("alg") != _ALGORITHM:
        raise InternalTokenError("Unsupported internal token algorithm")
    if payload.get("aud") != audience:
        raise InternalTokenError("Internal token audience mismatch")

    exp = payload.get("exp")
    if not isinstance(exp, int) or exp <= int(time.time()):
        raise InternalTokenError("Internal token expired")
    return payload


def _policy_values(values: Iterable[str], *, policy_name: str) -> frozenset[str]:
    if values is None:
        raise InternalTokenError(f"Internal token policy requires {policy_name}")
    if isinstance(values, str):
        values = (values,)

    normalized: set[str] = set()
    for value in values:
        if not isinstance(value, str) or not value.strip():
            raise InternalTokenError(
                f"Internal token policy requires non-empty {policy_name}"
            )
        normalized.add(value)

    if not normalized:
        raise InternalTokenError(f"Internal token policy requires {policy_name}")
    return frozenset(normalized)


def _claim_scopes(claims: Mapping[str, Any]) -> frozenset[str]:
    scopes = claims.get("scopes")
    if scopes is None:
        scopes = claims.get("scope", ())
    if isinstance(scopes, str):
        return frozenset(scope for scope in scopes.split() if scope)
    if isinstance(scopes, Mapping):
        raise InternalTokenError("Invalid internal token scopes")
    try:
        token_scopes = set()
        for scope in scopes:
            if not isinstance(scope, str):
                raise InternalTokenError("Invalid internal token scopes")
            if scope:
                token_scopes.add(scope)
        return frozenset(token_scopes)
    except TypeError as exc:
        raise InternalTokenError("Invalid internal token scopes") from exc


def _optional_non_empty_claim(value: str | None, *, claim_name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise DelegatedActorTokenInvalidError(
            f"Delegated actor token {claim_name} must be a string"
        )
    stripped = value.strip()
    if not stripped:
        return None
    return stripped


def verify_internal_token_policy(
    token: str,
    *,
    secret: str,
    audience: str,
    allowed_subjects: Iterable[str],
    required_scopes: Iterable[str],
) -> dict[str, Any]:
    """Verify an internal token and enforce route-local policy constraints.

    This wraps ``verify_internal_token`` so existing audience/signature/expiry
    behavior is preserved. Callers must restrict valid service subjects and
    require route capability scopes because global shared HMAC material is a v1
    blast-radius tradeoff. Scope extraction accepts the existing Taproot
    ``scopes`` list claim and JWT-style space-delimited ``scope`` strings.
    """

    claims = verify_internal_token(token, secret=secret, audience=audience)

    subject_policy = _policy_values(allowed_subjects, policy_name="allowed subjects")
    if claims.get("sub") not in subject_policy:
        raise InternalTokenError("Internal token subject not allowed")

    scope_policy = _policy_values(required_scopes, policy_name="required scopes")
    token_scopes = _claim_scopes(claims)
    missing_scopes = scope_policy - token_scopes
    if missing_scopes:
        raise InternalTokenError("Internal token missing required scope")

    return claims
