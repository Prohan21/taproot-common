"""Audit event data model for the Taproot platform.

All audit events are immutable frozen dataclasses. Services publish events via
the ``IAuditPublisher`` port (see ``publisher.py``). The ``publish_audit_event``
helper is the primary entry-point for fire-and-forget publishing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _utcnow_iso() -> str:
    """Return the current UTC time as an ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class AuditEvent:
    """Immutable record of a single auditable action in the platform.

    Required fields must be supplied by the caller. Optional fields are either
    auto-populated (``timestamp``) or left as ``None`` when not applicable.

    Attributes:
        service: Name of the originating service (e.g. "prompt-s", "toolbox-s").
        action: The action that was performed. One of the AUDIT_ACTIONS constants.
        entity_type: The type of resource affected (e.g. "prompt", "tool", "credential").
        performed_by: Identity of the actor — user ID, API key ID, or system principal.
        tenant_id: Project or tenant identifier scoping the event.
        entity_id: Optional ID of the specific entity that was affected.
        old_value: Previous state of the entity (for UPDATE/DELETE actions).
        new_value: New state of the entity (for CREATE/UPDATE actions).
        changed_fields: Tuple of field names that differ between old_value and new_value.
            Auto-computed via ``compute_changed_fields()`` when not provided.
        agent_id: Optional agent identifier if the action was performed by an agent.
        trace_id: Optional OpenTelemetry trace ID for correlation with spans.
        source_ip: Optional source IP address of the request.
        correlation_id: Optional cross-service request correlation ID.
        transaction_id: Optional database transaction sequence number.
        metadata: Optional extra key-value pairs specific to the action or entity.
        timestamp: ISO 8601 UTC timestamp. Auto-set to the current time in
            ``__post_init__`` if not supplied by the caller.
    """

    # --- Required fields ---
    service: str
    action: str
    entity_type: str
    performed_by: str
    tenant_id: str

    # --- Optional identity/scope ---
    entity_id: str | None = None

    # --- Optional before/after state ---
    old_value: dict[str, Any] | None = None
    new_value: dict[str, Any] | None = None
    changed_fields: tuple[str, ...] | None = None

    # --- Optional context ---
    agent_id: str | None = None
    trace_id: str | None = None
    source_ip: str | None = None
    correlation_id: str | None = None
    transaction_id: int | None = None
    metadata: dict[str, Any] | None = None

    # --- Auto-populated ---
    timestamp: str | None = field(default=None)

    def __post_init__(self) -> None:
        # frozen=True prevents direct attribute assignment; use object.__setattr__
        if self.timestamp is None:
            object.__setattr__(self, "timestamp", _utcnow_iso())

    # ------------------------------------------------------------------
    # Business helpers
    # ------------------------------------------------------------------

    def compute_changed_fields(self) -> tuple[str, ...]:
        """Return the set of field names whose values differ between old and new.

        Compares ``old_value`` and ``new_value`` shallowly. Keys present in one
        dict but absent from the other are also considered changed.

        Returns:
            A sorted tuple of changed field name strings (empty if both are None
            or the dicts are equal).
        """
        old = self.old_value or {}
        new = self.new_value or {}
        all_keys = set(old) | set(new)
        changed = sorted(k for k in all_keys if old.get(k) != new.get(k))
        return tuple(changed)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the event to a plain dict suitable for JSON persistence.

        ``None`` values are omitted to keep payloads compact. ``changed_fields``
        is serialized as a list for JSON compatibility.

        Returns:
            A dict containing all non-None fields of the event.
        """
        result: dict[str, Any] = {
            "service": self.service,
            "action": self.action,
            "entity_type": self.entity_type,
            "performed_by": self.performed_by,
            "tenant_id": self.tenant_id,
            "timestamp": self.timestamp,
        }

        if self.entity_id is not None:
            result["entity_id"] = self.entity_id
        if self.old_value is not None:
            result["old_value"] = self.old_value
        if self.new_value is not None:
            result["new_value"] = self.new_value
        if self.changed_fields is not None:
            result["changed_fields"] = list(self.changed_fields)
        if self.agent_id is not None:
            result["agent_id"] = self.agent_id
        if self.trace_id is not None:
            result["trace_id"] = self.trace_id
        if self.source_ip is not None:
            result["source_ip"] = self.source_ip
        if self.correlation_id is not None:
            result["correlation_id"] = self.correlation_id
        if self.transaction_id is not None:
            result["transaction_id"] = self.transaction_id
        if self.metadata is not None:
            result["metadata"] = self.metadata

        return result


# ---------------------------------------------------------------------------
# Valid action constants
# ---------------------------------------------------------------------------

class AuditAction:
    """String constants for the ``action`` field of ``AuditEvent``.

    Using string constants (rather than an enum) keeps the model JSON-friendly
    and allows consuming services to extend the set without subclassing.
    """

    CREATE = "CREATE"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    APPROVE = "APPROVE"
    REJECT = "REJECT"
    ACCESS = "ACCESS"
    INVOKE = "INVOKE"
    ENABLE_SUPPORT = "ENABLE_SUPPORT"
    DISABLE_SUPPORT = "DISABLE_SUPPORT"
    ENABLE_DEBUG = "ENABLE_DEBUG"
    DISABLE_DEBUG = "DISABLE_DEBUG"
