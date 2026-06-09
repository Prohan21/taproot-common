"""Shared internal trust contract models.

These models define the signed-claims shape Taproot services will use for
service-to-service identity and delegated on-behalf-of calls. This file is the
Phase 1 contract scaffold only; verification and issuance can be layered on top
without changing downstream claim names.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, StrEnum
from typing import Any, Mapping


class ContextTrustLevel(StrEnum):
    """Trust level attached to propagated context values."""

    OBSERVED = "observed"
    VERIFIED = "verified"
    INTERNAL = "internal"
    SYSTEM = "system"


@dataclass(frozen=True)
class ContextProvenance:
    """Where a context value came from and whether Taproot verified it."""

    source: str
    trust_level: ContextTrustLevel = ContextTrustLevel.OBSERVED
    verified: bool = False
    carrier: str | None = None
    accepted_headers: tuple[str, ...] = ()
    ignored_headers: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "source": self.source,
            "trust_level": self.trust_level.value,
            "verified": self.verified,
        }
        if self.carrier:
            data["carrier"] = self.carrier
        if self.accepted_headers:
            data["accepted_headers"] = list(self.accepted_headers)
        if self.ignored_headers:
            data["ignored_headers"] = list(self.ignored_headers)
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ContextProvenance:
        return cls(
            source=str(data["source"]),
            trust_level=ContextTrustLevel(data.get("trust_level", "observed")),
            verified=bool(data.get("verified", False)),
            carrier=data.get("carrier"),
            accepted_headers=tuple(
                str(item) for item in data.get("accepted_headers", ())
            ),
            ignored_headers=tuple(
                str(item) for item in data.get("ignored_headers", ())
            ),
        )


@dataclass(frozen=True)
class ObservedRequestContext:
    """Public, untrusted request metadata used only for observability/grouping."""

    correlation_id: str | None = None
    request_id: str | None = None
    traceparent: str | None = None
    tracestate: str | None = None
    public_interaction_id: str | None = None
    provenance: ContextProvenance = field(
        default_factory=lambda: ContextProvenance(source="public_headers")
    )

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {}
        if self.correlation_id:
            data["correlation_id"] = self.correlation_id
        if self.request_id:
            data["request_id"] = self.request_id
        if self.traceparent:
            data["traceparent"] = self.traceparent
        if self.tracestate:
            data["tracestate"] = self.tracestate
        if self.public_interaction_id:
            data["public_interaction_id"] = self.public_interaction_id
        data["provenance"] = self.provenance.to_dict()
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ObservedRequestContext:
        provenance_data = data.get("provenance") or {"source": "public_headers"}
        return cls(
            correlation_id=data.get("correlation_id"),
            request_id=data.get("request_id"),
            traceparent=data.get("traceparent"),
            tracestate=data.get("tracestate"),
            public_interaction_id=data.get("public_interaction_id"),
            provenance=ContextProvenance.from_dict(provenance_data),
        )


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
