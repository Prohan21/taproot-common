"""Shared internal trust contract models.

These models define the signed-claims shape Taproot services will use for
service-to-service identity and delegated on-behalf-of calls. This file is the
Phase 1 contract scaffold only; verification and issuance can be layered on top
without changing downstream claim names.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class PrincipalType(str, Enum):
    """Top-level principal type carried in internal trust claims."""

    SERVICE = "service"
    DELEGATED = "delegated"


@dataclass(frozen=True)
class ServicePrincipal:
    """Identity for a Taproot runtime calling another internal service."""

    service_name: str
    audience: str
    issued_at: datetime
    expires_at: datetime
    correlation_id: str | None = None
    scopes: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def principal_type(self) -> PrincipalType:
        return PrincipalType.SERVICE

    @property
    def is_expired(self) -> bool:
        return self.expires_at <= datetime.now(timezone.utc)

    def to_claims(self) -> dict[str, Any]:
        claims: dict[str, Any] = {
            "principal_type": self.principal_type.value,
            "sub": self.service_name,
            "aud": self.audience,
            "iat": int(self.issued_at.timestamp()),
            "exp": int(self.expires_at.timestamp()),
        }
        if self.correlation_id:
            claims["correlation_id"] = self.correlation_id
        if self.scopes:
            claims["scopes"] = list(self.scopes)
        if self.metadata:
            claims["metadata"] = self.metadata
        return claims


@dataclass(frozen=True)
class DelegatedPrincipal(ServicePrincipal):
    """Internal service identity carrying delegated end-user scope."""

    actor_user_id: str | None = None
    actor_email: str | None = None
    project_id: str | None = None
    entitlements: dict[str, Any] = field(default_factory=dict)

    @property
    def principal_type(self) -> PrincipalType:
        return PrincipalType.DELEGATED

    def to_claims(self) -> dict[str, Any]:
        claims = super().to_claims()
        if self.actor_user_id:
            claims["actor_user_id"] = self.actor_user_id
        if self.actor_email:
            claims["actor_email"] = self.actor_email
        if self.project_id:
            claims["project_id"] = self.project_id
        if self.entitlements:
            claims["entitlements"] = self.entitlements
        return claims


def principal_from_claims(claims: dict[str, Any]) -> ServicePrincipal:
    """Hydrate a service or delegated principal from token claims."""

    principal_type = PrincipalType(
        claims.get("principal_type", PrincipalType.SERVICE.value)
    )
    service_name = str(claims["sub"])
    audience = str(claims["aud"])
    issued_at = datetime.fromtimestamp(int(claims["iat"]), tz=timezone.utc)
    expires_at = datetime.fromtimestamp(int(claims["exp"]), tz=timezone.utc)
    correlation_id = claims.get("correlation_id")
    scopes = tuple(str(scope) for scope in claims.get("scopes", []))
    metadata = dict(claims.get("metadata", {}))
    if principal_type is PrincipalType.DELEGATED:
        return DelegatedPrincipal(
            service_name=service_name,
            audience=audience,
            issued_at=issued_at,
            expires_at=expires_at,
            correlation_id=str(correlation_id) if correlation_id else None,
            scopes=scopes,
            metadata=metadata,
            actor_user_id=claims.get("actor_user_id"),
            actor_email=claims.get("actor_email"),
            project_id=claims.get("project_id"),
            entitlements=dict(claims.get("entitlements", {})),
        )
    return ServicePrincipal(
        service_name=service_name,
        audience=audience,
        issued_at=issued_at,
        expires_at=expires_at,
        correlation_id=str(correlation_id) if correlation_id else None,
        scopes=scopes,
        metadata=metadata,
    )
