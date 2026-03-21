"""Audit publisher port and implementations.

Provides:
- ``IAuditPublisher`` — Protocol interface that all publisher adapters must satisfy.
- ``InMemoryAuditPublisher`` — In-memory implementation for development and testing.
- ``publish_audit_event()`` — Fire-and-forget helper used by service code.
- ``set_audit_publisher()`` / ``get_audit_publisher()`` — Module-level singleton
  management, following the same pattern as ``get_metadata_store()`` in
  ``taproot_common.auth.middleware``.

Usage in a service::

    from taproot_common.audit.publisher import publish_audit_event, set_audit_publisher
    from taproot_common.audit.models import AuditAction

    # At startup, wire in a real publisher:
    set_audit_publisher(my_sqs_publisher)

    # In a route handler:
    await publish_audit_event(
        service="prompt-s",
        action=AuditAction.CREATE,
        entity_type="prompt",
        entity_id=str(new_prompt.id),
        performed_by=auth.api_key_id,
        tenant_id=auth.project_id,
        new_value=new_prompt_dict,
    )

Audit failures are always swallowed with a warning log; they must never propagate
to callers or interrupt the primary request flow.
"""

from __future__ import annotations

import logging
from typing import Any, Protocol, runtime_checkable

from taproot_common.audit.models import AuditEvent

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Port interface
# ---------------------------------------------------------------------------


@runtime_checkable
class IAuditPublisher(Protocol):
    """Port interface for audit event publishing.

    Implementations are responsible for durably delivering events to an
    audit store (e.g. SQS, Service Bus, Pub/Sub, database table).

    All methods are async to support non-blocking I/O. Callers should prefer
    ``publish_audit_event()`` (the module-level helper) rather than calling
    this interface directly.
    """

    async def publish(self, event: AuditEvent) -> None:
        """Publish a single audit event.

        Args:
            event: The audit event to publish.
        """
        ...

    async def publish_batch(self, events: list[AuditEvent]) -> None:
        """Publish multiple audit events in a single operation.

        Implementations should deliver all events or raise on partial failure.

        Args:
            events: The list of audit events to publish.
        """
        ...

    async def close(self) -> None:
        """Release any underlying connections or resources."""
        ...


# ---------------------------------------------------------------------------
# In-memory implementation (dev / test)
# ---------------------------------------------------------------------------


class InMemoryAuditPublisher:
    """In-memory audit publisher for local development and testing.

    Stores events in an in-process list. Not suitable for production use.

    Example::

        publisher = InMemoryAuditPublisher()
        set_audit_publisher(publisher)

        await publish_audit_event(...)

        assert len(publisher.events) == 1
        publisher.clear()
    """

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    @property
    def events(self) -> list[AuditEvent]:
        """Read-only view of all published events (ordered by publish time)."""
        return list(self._events)

    def clear(self) -> None:
        """Remove all stored events (useful between test cases)."""
        self._events.clear()

    async def publish(self, event: AuditEvent) -> None:
        """Append the event to the in-memory store."""
        self._events.append(event)

    async def publish_batch(self, events: list[AuditEvent]) -> None:
        """Append all events to the in-memory store."""
        self._events.extend(events)

    async def close(self) -> None:
        """No-op — nothing to close for an in-memory store."""


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_audit_publisher: IAuditPublisher | None = None


def set_audit_publisher(publisher: IAuditPublisher) -> None:
    """Set the process-wide audit publisher singleton.

    Should be called once at application startup (e.g. in the FastAPI lifespan
    handler) before any audit events are emitted.

    Args:
        publisher: The publisher instance to use for all subsequent
            ``publish_audit_event()`` calls.
    """
    global _audit_publisher
    _audit_publisher = publisher
    logger.info("audit.publisher.set", extra={"publisher_type": type(publisher).__name__})


def get_audit_publisher() -> IAuditPublisher | None:
    """Return the current audit publisher singleton, or ``None`` if not set.

    Returns:
        The configured publisher, or ``None`` when no publisher has been
        registered (e.g. during tests that do not configure one).
    """
    return _audit_publisher


def reset_audit_publisher() -> None:
    """Reset the audit publisher singleton to ``None``.

    Intended for use in tests to restore a clean state between test cases.
    """
    global _audit_publisher
    _audit_publisher = None


# ---------------------------------------------------------------------------
# Fire-and-forget helper
# ---------------------------------------------------------------------------


def _get_structlog_context() -> dict[str, Any]:
    """Attempt to read bound context values from structlog contextvars.

    Returns an empty dict if structlog is not installed or no context is bound.
    Never raises.
    """
    try:
        import structlog.contextvars  # type: ignore[import-untyped]

        return dict(structlog.contextvars.get_contextvars())
    except Exception:  # noqa: BLE001 — structlog absent or context unavailable
        return {}


async def publish_audit_event(
    *,
    action: str,
    entity_type: str,
    performed_by: str,
    tenant_id: str,
    service: str | None = None,
    entity_id: str | None = None,
    old_value: dict[str, Any] | None = None,
    new_value: dict[str, Any] | None = None,
    changed_fields: tuple[str, ...] | None = None,
    agent_id: str | None = None,
    trace_id: str | None = None,
    source_ip: str | None = None,
    correlation_id: str | None = None,
    transaction_id: int | None = None,
    metadata: dict[str, Any] | None = None,
    timestamp: str | None = None,
) -> None:
    """Build and publish an ``AuditEvent`` in a fire-and-forget manner.

    This is the primary entry-point for service code. It:

    1. Attempts to read ``service`` and ``correlation_id`` from structlog
       contextvars when not explicitly provided, enabling automatic propagation
       from request middleware that binds these values.
    2. Auto-computes ``changed_fields`` from ``old_value`` / ``new_value`` when
       ``changed_fields`` is not supplied.
    3. Publishes via the module-level singleton publisher.
    4. Swallows all errors with a ``WARNING`` log — audit failures must never
       interrupt the primary request flow.

    All arguments are keyword-only to prevent accidental positional mismatches.

    Args:
        action: The action being audited (use ``AuditAction`` constants).
        entity_type: The type of resource affected (e.g. "prompt", "tool").
        performed_by: Identity of the actor (user/API key ID, or system principal).
        tenant_id: Project or tenant identifier.
        service: Originating service name. Falls back to ``structlog`` context
            key ``"service"`` when omitted, then ``"unknown"``.
        entity_id: ID of the specific resource affected.
        old_value: Previous state (for UPDATE/DELETE).
        new_value: New state (for CREATE/UPDATE).
        changed_fields: Explicit list of changed field names. When ``None``,
            auto-computed from ``old_value`` vs ``new_value``.
        agent_id: Agent identifier (when action performed by an AI agent).
        trace_id: OpenTelemetry trace ID.
        source_ip: Source IP address.
        correlation_id: Cross-service correlation ID. Falls back to structlog
            context key ``"correlation_id"`` when omitted.
        transaction_id: Database transaction sequence number.
        metadata: Extra context key-value pairs.
        timestamp: ISO 8601 UTC timestamp. Auto-set to now when omitted.
    """
    publisher = _audit_publisher
    if publisher is None:
        logger.debug(
            "audit.publisher.not_configured",
            extra={"action": action, "entity_type": entity_type},
        )
        return

    try:
        # --- Enrich from structlog contextvars when fields are absent ---
        ctx = _get_structlog_context()

        resolved_service: str = service or ctx.get("service") or "unknown"
        resolved_correlation_id: str | None = correlation_id or ctx.get("correlation_id")

        # --- Auto-compute changed_fields when not provided ---
        event = AuditEvent(
            service=resolved_service,
            action=action,
            entity_type=entity_type,
            performed_by=performed_by,
            tenant_id=tenant_id,
            entity_id=entity_id,
            old_value=old_value,
            new_value=new_value,
            changed_fields=changed_fields,
            agent_id=agent_id,
            trace_id=trace_id,
            source_ip=source_ip,
            correlation_id=resolved_correlation_id,
            transaction_id=transaction_id,
            metadata=metadata,
            timestamp=timestamp,
        )

        # If changed_fields was not supplied, derive it now and replace the event.
        # We construct a new frozen instance because AuditEvent is immutable.
        if changed_fields is None and (old_value is not None or new_value is not None):
            computed = event.compute_changed_fields()
            event = AuditEvent(
                service=event.service,
                action=event.action,
                entity_type=event.entity_type,
                performed_by=event.performed_by,
                tenant_id=event.tenant_id,
                entity_id=event.entity_id,
                old_value=event.old_value,
                new_value=event.new_value,
                changed_fields=computed,
                agent_id=event.agent_id,
                trace_id=event.trace_id,
                source_ip=event.source_ip,
                correlation_id=event.correlation_id,
                transaction_id=event.transaction_id,
                metadata=event.metadata,
                timestamp=event.timestamp,
            )

        await publisher.publish(event)

    except Exception as exc:  # noqa: BLE001 — fire-and-forget; never break the caller
        logger.warning(
            "audit.publish.failed",
            extra={
                "action": action,
                "entity_type": entity_type,
                "error": str(exc),
            },
        )
