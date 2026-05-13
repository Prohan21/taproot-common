"""Helpers for internal trust headers.

These helpers are intentionally small and additive so services can begin to
standardize around one internal bearer-token contract before full token
verification is rolled out.
"""

from __future__ import annotations

from collections.abc import Mapping


INTERNAL_AUTHORIZATION_HEADER = "authorization"
CORRELATION_ID_HEADER = "x-correlation-id"


def extract_bearer_token(headers: Mapping[str, str]) -> str | None:
    """Extract a bearer token from a case-normalized header mapping."""

    raw = headers.get(INTERNAL_AUTHORIZATION_HEADER, "")
    if not raw:
        return None
    scheme, _, token = raw.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()
