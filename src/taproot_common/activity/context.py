"""Interaction context creation and propagation helpers for TAP-38."""

from __future__ import annotations

from contextvars import ContextVar, Token
from typing import TYPE_CHECKING, Mapping
from uuid import uuid4

from taproot_common.activity.models import (
    ACTIVITY_HEADER_VERSION,
    ActorRef,
    DomainArea,
    InteractionContext,
    InteractionType,
    RecordScope,
)

if TYPE_CHECKING:
    from taproot_common.activity.recorder import ActivityRecorder

HEADER_ACTIVITY_VERSION = "X-Taproot-Activity-Version"
HEADER_INTERACTION_ID = "X-Taproot-Interaction-Id"
HEADER_INTERACTION_TYPE = "X-Taproot-Interaction-Type"
HEADER_CALLER_ID = "X-Taproot-Caller-Id"
HEADER_CALLER_TYPE = "X-Taproot-Caller-Type"
HEADER_SOURCE_AGENT_ID = "X-Taproot-Source-Agent-Id"
HEADER_ROOT_AGENT_ID = "X-Taproot-Root-Agent-Id"
HEADER_PARENT_ACTIVITY_ID = "X-Taproot-Parent-Activity-Id"
HEADER_CORRELATION_ID = "X-Correlation-ID"
HEADER_TRACEPARENT = "traceparent"


interaction_context_var: ContextVar[InteractionContext | None] = ContextVar(
    "taproot_activity_interaction_context",
    default=None,
)


def create_interaction_id() -> str:
    """Create a platform interaction identity."""

    return str(uuid4())


def get_interaction_context() -> InteractionContext | None:
    """Return the current interaction context, if one is bound."""

    return interaction_context_var.get()


def set_interaction_context(
    context: InteractionContext,
) -> Token[InteractionContext | None]:
    """Bind an interaction context to the current execution context."""

    return interaction_context_var.set(context)


def reset_interaction_context(token: Token[InteractionContext | None]) -> None:
    """Reset a previously bound interaction context token."""

    interaction_context_var.reset(token)


def clear_interaction_context() -> None:
    """Clear the current interaction context."""

    interaction_context_var.set(None)


async def ensure_interaction_context(
    *,
    interaction_type: InteractionType,
    interaction_id: str | None = None,
    project_id: str | None = None,
    domain_area: DomainArea | None = None,
    caller: ActorRef | None = None,
    source_agent_id: str | None = None,
    root_agent_id: str | None = None,
    source_entry_point: str | None = None,
    correlation_id: str | None = None,
    trace_id: str | None = None,
    retention_policy_id: str | None = None,
    parent_activity_id: str | None = None,
    record_scope: RecordScope = RecordScope.PROJECT,
    recorder: ActivityRecorder | None = None,
) -> InteractionContext:
    """Return the current context or create and bind a new one.

    When an activity recorder is supplied or configured as the process default,
    newly created contexts also create an interaction record. Storage failures
    are non-critical and are handled by bounded retry plus safe failure visibility.
    """

    current = get_interaction_context()
    if current is not None:
        return current

    context = InteractionContext(
        interaction_id=interaction_id or create_interaction_id(),
        interaction_type=interaction_type,
        project_id=project_id,
        domain_area=domain_area,
        caller=caller,
        source_agent_id=source_agent_id,
        root_agent_id=root_agent_id,
        source_entry_point=source_entry_point,
        correlation_id=correlation_id,
        trace_id=trace_id,
        retention_policy_id=retention_policy_id,
        parent_activity_id=parent_activity_id,
        record_scope=record_scope,
    )
    set_interaction_context(context)
    resolved_recorder = recorder or _get_default_activity_recorder()
    if resolved_recorder is not None:
        await resolved_recorder.record_interaction(context)
    return context


def _get_default_activity_recorder() -> ActivityRecorder | None:
    from taproot_common.activity.recorder import get_activity_recorder

    return get_activity_recorder()


def interaction_context_from_headers(
    headers: Mapping[str, str],
    *,
    default_interaction_type: InteractionType = InteractionType.SERVICE_REQUEST,
    project_id: str | None = None,
    domain_area: DomainArea | None = None,
    source_entry_point: str | None = None,
    retention_policy_id: str | None = None,
    record_scope: RecordScope = RecordScope.PROJECT,
) -> InteractionContext:
    """Create an interaction context from inbound request headers.

    Missing interaction IDs are generated at the first Taproot-controlled entry
    point. Header versions are advisory in v1: missing, malformed, or future
    values must not break mixed-version rolling deploys.
    """

    _parse_header_version(_header(headers, HEADER_ACTIVITY_VERSION))
    caller = _caller_from_headers(headers)
    traceparent = _header(headers, HEADER_TRACEPARENT)
    interaction_type = _header(headers, HEADER_INTERACTION_TYPE)

    return InteractionContext(
        interaction_id=_header(headers, HEADER_INTERACTION_ID)
        or create_interaction_id(),
        interaction_type=_interaction_type_from_header(
            interaction_type,
            default_interaction_type,
        ),
        project_id=project_id,
        domain_area=domain_area,
        caller=caller,
        source_agent_id=_header(headers, HEADER_SOURCE_AGENT_ID),
        root_agent_id=_header(headers, HEADER_ROOT_AGENT_ID),
        source_entry_point=source_entry_point,
        correlation_id=_header(headers, HEADER_CORRELATION_ID),
        trace_id=traceparent,
        retention_policy_id=retention_policy_id,
        parent_activity_id=_header(headers, HEADER_PARENT_ACTIVITY_ID),
        record_scope=record_scope,
    )


def bind_interaction_context_from_headers(
    headers: Mapping[str, str],
    *,
    default_interaction_type: InteractionType = InteractionType.SERVICE_REQUEST,
    project_id: str | None = None,
    domain_area: DomainArea | None = None,
    source_entry_point: str | None = None,
    retention_policy_id: str | None = None,
    record_scope: RecordScope = RecordScope.PROJECT,
) -> tuple[InteractionContext, Token[InteractionContext | None]]:
    """Extract and bind interaction context from inbound headers."""

    context = interaction_context_from_headers(
        headers,
        default_interaction_type=default_interaction_type,
        project_id=project_id,
        domain_area=domain_area,
        source_entry_point=source_entry_point,
        retention_policy_id=retention_policy_id,
        record_scope=record_scope,
    )
    token = set_interaction_context(context)
    return context, token


def propagation_headers(
    context: InteractionContext | None = None,
) -> dict[str, str]:
    """Build outbound TAP-38 propagation headers for a context."""

    current = context or get_interaction_context()
    if current is None:
        return {}

    headers = {
        HEADER_ACTIVITY_VERSION: str(ACTIVITY_HEADER_VERSION),
        HEADER_INTERACTION_ID: current.interaction_id,
        HEADER_INTERACTION_TYPE: current.interaction_type.value,
    }
    if current.caller:
        headers[HEADER_CALLER_ID] = current.caller.actor_id
        headers[HEADER_CALLER_TYPE] = current.caller.actor_type
    if current.source_agent_id:
        headers[HEADER_SOURCE_AGENT_ID] = current.source_agent_id
    if current.root_agent_id:
        headers[HEADER_ROOT_AGENT_ID] = current.root_agent_id
    if current.parent_activity_id:
        headers[HEADER_PARENT_ACTIVITY_ID] = current.parent_activity_id
    if current.correlation_id:
        headers[HEADER_CORRELATION_ID] = current.correlation_id
    if current.trace_id:
        headers[HEADER_TRACEPARENT] = current.trace_id

    return headers


def merge_propagation_headers(
    headers: Mapping[str, str] | None = None,
    *,
    context: InteractionContext | None = None,
    overwrite: bool = False,
) -> dict[str, str]:
    """Merge TAP-38 propagation headers into an existing header mapping.

    By default, explicit caller-provided header values are preserved. This lets
    service-specific auth, idempotency, and request headers remain untouched.
    """

    merged = dict(headers or {})
    existing = {key.lower() for key in merged}
    for key, value in propagation_headers(context).items():
        if overwrite or key.lower() not in existing:
            merged[key] = value
            existing.add(key.lower())
    return merged


def _caller_from_headers(headers: Mapping[str, str]) -> ActorRef | None:
    caller_id = _header(headers, HEADER_CALLER_ID)
    caller_type = _header(headers, HEADER_CALLER_TYPE)
    if not caller_id or not caller_type:
        return None
    return ActorRef(actor_type=caller_type, actor_id=caller_id)


def _parse_header_version(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        parsed = int(value)
    except ValueError:
        return None
    if parsed < 1:
        return None
    return parsed


def _interaction_type_from_header(
    value: str | None,
    default_interaction_type: InteractionType,
) -> InteractionType:
    if not value:
        return default_interaction_type
    try:
        return InteractionType(value)
    except ValueError:
        return default_interaction_type


def _header(headers: Mapping[str, str], name: str) -> str | None:
    lower_name = name.lower()
    for key, value in headers.items():
        if key.lower() == lower_name and value:
            return value
    return None
