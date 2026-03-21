"""Taproot audit module.

Provides the ``AuditEvent`` frozen dataclass, the ``IAuditPublisher`` Protocol,
the ``InMemoryAuditPublisher`` for development and testing, and the
``publish_audit_event`` fire-and-forget helper.

Typical usage::

    from taproot_common.audit import (
        AuditAction,
        AuditEvent,
        IAuditPublisher,
        InMemoryAuditPublisher,
        publish_audit_event,
        set_audit_publisher,
        get_audit_publisher,
        reset_audit_publisher,
    )
"""

from taproot_common.audit.models import AuditAction, AuditEvent
from taproot_common.audit.publisher import (
    IAuditPublisher,
    InMemoryAuditPublisher,
    close_audit_pool,
    get_audit_publisher,
    init_audit_pool,
    publish_audit_event,
    reset_audit_publisher,
    set_audit_publisher,
)

__all__ = [
    # Models
    "AuditEvent",
    "AuditAction",
    # Port interface
    "IAuditPublisher",
    # Implementations
    "InMemoryAuditPublisher",
    # Pool management (call in service lifespan)
    "init_audit_pool",
    "close_audit_pool",
    # Singleton management (for tests)
    "set_audit_publisher",
    "get_audit_publisher",
    "reset_audit_publisher",
    # Fire-and-forget helper
    "publish_audit_event",
]
