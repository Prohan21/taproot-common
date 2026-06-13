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


class InternalTokenError(ValueError):
    """Raised when an internal bearer token cannot be minted or verified."""


_ALGORITHM = "HS256"
_HEADER = {"alg": _ALGORITHM, "typ": "JWT"}
_RESERVED_CLAIMS = frozenset({"sub", "aud", "iat", "exp"})


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
