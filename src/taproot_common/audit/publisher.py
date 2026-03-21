"""Audit event persistence — fire-and-forget via asyncio.create_task.

Each service writes audit events directly to the shared ``audit.audit_log``
PostgreSQL table using an asyncpg connection pool.  The INSERT is scheduled
as a background task (``asyncio.create_task``) so the calling request is
never blocked.

Setup (in each service's lifespan)::

    from taproot_common.audit.publisher import init_audit_pool, close_audit_pool

    @asynccontextmanager
    async def lifespan(app):
        await init_audit_pool(os.getenv("AUDIT_DB_URL", DATABASE_URL))
        yield
        await close_audit_pool()

Publishing (in route handlers / services)::

    from taproot_common.audit import publish_audit_event

    await publish_audit_event(
        action="CREATE",
        entity_type="TOOL",
        entity_id=tool_id,
        performed_by=auth.api_key_id,
        tenant_id=auth.project_id,
        new_value={"name": tool.name},
    )

Audit failures are always swallowed with a warning log; they must never
propagate to callers or interrupt the primary request flow.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import Any, Protocol, runtime_checkable

from taproot_common.audit.models import AuditEvent

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Connection pool (module-level singleton)
# ---------------------------------------------------------------------------

_pool: Any = None  # asyncpg.Pool | None — typed as Any to avoid hard dep


async def init_audit_pool(
    db_url: str,
    *,
    min_size: int = 1,
    max_size: int = 3,
) -> None:
    """Create the asyncpg connection pool for audit writes.

    Call once at application startup (e.g. in FastAPI lifespan).
    Uses a small pool (1-3 connections) since audit volume is low.
    """
    global _pool
    if _pool is not None:
        return  # already initialized

    try:
        import asyncpg  # type: ignore[import-untyped]

        _pool = await asyncpg.create_pool(db_url, min_size=min_size, max_size=max_size)
        # OWASP: never log connection strings with credentials — mask everything before @
        safe_url = db_url.split("@")[-1] if "@" in db_url else "(local)"
        logger.info("audit.pool.initialized", extra={"db_host": safe_url})
    except Exception as exc:  # noqa: BLE001
        # OWASP: do not include db_url in error log — may contain credentials
        logger.warning("audit.pool.init_failed", extra={"error_type": type(exc).__name__})


async def close_audit_pool() -> None:
    """Close the audit connection pool. Call at shutdown."""
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None
        logger.info("audit.pool.closed")


def _get_pool() -> Any:
    """Return the current pool or None."""
    return _pool


# ---------------------------------------------------------------------------
# Port interface (retained for testing / InMemory)
# ---------------------------------------------------------------------------


@runtime_checkable
class IAuditPublisher(Protocol):
    """Port interface for audit event publishing.

    The default implementation writes directly to PostgreSQL via
    ``asyncio.create_task``.  This protocol exists so tests can swap
    in ``InMemoryAuditPublisher`` without a database.
    """

    async def publish(self, event: AuditEvent) -> None: ...
    async def publish_batch(self, events: list[AuditEvent]) -> None: ...
    async def close(self) -> None: ...


class InMemoryAuditPublisher:
    """In-memory audit publisher for local development and testing."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    @property
    def events(self) -> list[AuditEvent]:
        return list(self._events)

    def clear(self) -> None:
        self._events.clear()

    async def publish(self, event: AuditEvent) -> None:
        self._events.append(event)

    async def publish_batch(self, events: list[AuditEvent]) -> None:
        self._events.extend(events)

    async def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Module-level publisher override (for tests)
# ---------------------------------------------------------------------------

_audit_publisher: IAuditPublisher | None = None


def set_audit_publisher(publisher: IAuditPublisher) -> None:
    """Override the default DB-write behavior with a custom publisher (tests)."""
    global _audit_publisher
    _audit_publisher = publisher


def get_audit_publisher() -> IAuditPublisher | None:
    return _audit_publisher


def reset_audit_publisher() -> None:
    """Reset to default (DB-write) behavior. For test teardown."""
    global _audit_publisher
    _audit_publisher = None


# ---------------------------------------------------------------------------
# Direct DB insert
# ---------------------------------------------------------------------------

_INSERT_SQL = """
INSERT INTO audit.audit_log (
    id, trace_id, service, action, entity_type, entity_id,
    old_value, new_value, changed_fields, performed_by,
    performed_at, tenant_id, agent_id, source_ip,
    correlation_id, transaction_id, metadata
) VALUES (
    $1, $2, $3, $4, $5, $6,
    $7, $8, $9, $10,
    $11::timestamptz, $12, $13, $14::inet,
    $15, $16, $17
)
"""


async def _persist_event(event: AuditEvent) -> None:
    """Write a single audit event to PostgreSQL. Never raises."""
    pool = _get_pool()
    if pool is None:
        logger.debug("audit.persist.no_pool", extra={"action": event.action})
        return

    try:
        event_dict = event.to_dict()
        await pool.execute(
            _INSERT_SQL,
            str(uuid.uuid4()),                                      # id
            uuid.UUID(event.trace_id) if event.trace_id else None,  # trace_id
            event.service,                                          # service
            event.action,                                           # action
            event.entity_type,                                      # entity_type
            event.entity_id,                                        # entity_id
            json.dumps(event.old_value) if event.old_value else None,
            json.dumps(event.new_value) if event.new_value else None,
            list(event.changed_fields) if event.changed_fields else None,
            event.performed_by,                                     # performed_by
            event.timestamp,                                        # performed_at
            event.tenant_id,                                        # tenant_id
            event.agent_id,                                         # agent_id
            event.source_ip,                                        # source_ip
            event.correlation_id,                                   # correlation_id
            event.transaction_id,                                   # transaction_id
            json.dumps(event.metadata) if event.metadata else None,
        )
        logger.debug(
            "audit.event.persisted",
            extra={"service": event.service, "action": event.action,
                   "entity_type": event.entity_type, "entity_id": event.entity_id},
        )
    except Exception as exc:  # noqa: BLE001 — never break the caller
        logger.warning(
            "audit.persist.failed",
            extra={"action": event.action, "entity_type": event.entity_type,
                   "error": str(exc)},
        )


# ---------------------------------------------------------------------------
# Fire-and-forget helper
# ---------------------------------------------------------------------------


def _get_structlog_context() -> dict[str, Any]:
    """Read bound context from structlog contextvars. Never raises."""
    try:
        import structlog.contextvars  # type: ignore[import-untyped]
        return dict(structlog.contextvars.get_contextvars())
    except Exception:  # noqa: BLE001
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
    """Build an AuditEvent and persist it via fire-and-forget ``asyncio.create_task``.

    The INSERT runs as a background task on the event loop — the calling
    coroutine returns immediately with zero latency impact.

    If a custom ``IAuditPublisher`` has been set (via ``set_audit_publisher``),
    it is used instead of the direct DB write. This enables in-memory
    publishers for testing.
    """
    try:
        # Enrich from structlog context when fields are absent
        ctx = _get_structlog_context()
        resolved_service = service or ctx.get("service") or "unknown"
        resolved_cid = correlation_id or ctx.get("correlation_id")
        resolved_agent = agent_id or ctx.get("agent_id")
        # Prefer actor_identity (real user email from X-Actor-Identity) over api_key_id
        resolved_performed_by = ctx.get("actor_identity") or performed_by

        event = AuditEvent(
            service=resolved_service,
            action=action,
            entity_type=entity_type,
            performed_by=resolved_performed_by,
            tenant_id=tenant_id,
            entity_id=entity_id,
            old_value=old_value,
            new_value=new_value,
            changed_fields=changed_fields,
            agent_id=resolved_agent,
            trace_id=trace_id,
            source_ip=source_ip,
            correlation_id=resolved_cid,
            transaction_id=transaction_id,
            metadata=metadata,
            timestamp=timestamp,
        )

        # Auto-compute changed_fields for UPDATE actions
        if changed_fields is None and old_value is not None and new_value is not None:
            computed = event.compute_changed_fields()
            # Reconstruct frozen dataclass with computed fields
            event = AuditEvent(
                **{**event.to_dict(), "changed_fields": computed, "timestamp": event.timestamp}
            )

        # Route to custom publisher (tests) or direct DB write (production)
        publisher = _audit_publisher
        if publisher is not None:
            asyncio.create_task(publisher.publish(event))
        else:
            asyncio.create_task(_persist_event(event))

    except Exception as exc:  # noqa: BLE001 — fire-and-forget
        logger.warning(
            "audit.publish.failed",
            extra={"action": action, "entity_type": entity_type, "error": str(exc)},
        )
