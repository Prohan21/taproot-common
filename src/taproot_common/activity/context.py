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
from taproot_common.trust.headers import (
    header_value,
    internal_principal_from_headers,
    public_ignored_header_names,
    strip_reserved_headers,
)
from taproot_common.trust.models import (
    ContextProvenance,
    ContextTrustLevel,
    DelegatedPrincipal,
    ObservedRequestContext,
    ServicePrincipal,
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
HEADER_PARENT_INTERACTION_ID = HEADER_PARENT_ACTIVITY_ID
HEADER_CORRELATION_ID = "X-Correlation-ID"
HEADER_REQUEST_ID = "X-Request-ID"
HEADER_TRACEPARENT = "traceparent"
HEADER_TRACESTATE = "tracestate"


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

    This legacy helper preserves caller-provided TAP identity headers for
    backward compatibility. Public ingress should use
    :func:`public_interaction_context_from_headers`; internal service ingress
    should use :func:`internal_interaction_context_from_headers`.
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


def observed_context_from_public_headers(
    headers: Mapping[str, str],
) -> ObservedRequestContext:
    """Extract public, untrusted observability context from inbound headers.

    The returned values are not identity, authorization, project, or audit
    evidence. A public ``X-Taproot-Interaction-Id`` value is retained only as a
    grouping hint; Taproot-controlled boundaries must mint or bind the trusted
    interaction identity. Spoofed actor/caller/parent/API-key headers are
    recorded as ignored provenance only.
    """

    accepted = []
    values: dict[str, str | None] = {
        "correlation_id": header_value(headers, HEADER_CORRELATION_ID),
        "request_id": header_value(headers, HEADER_REQUEST_ID),
        "traceparent": header_value(headers, HEADER_TRACEPARENT),
        "tracestate": header_value(headers, HEADER_TRACESTATE),
        "public_interaction_id": header_value(headers, HEADER_INTERACTION_ID),
    }
    for header_name, value in (
        (HEADER_CORRELATION_ID, values["correlation_id"]),
        (HEADER_REQUEST_ID, values["request_id"]),
        (HEADER_TRACEPARENT, values["traceparent"]),
        (HEADER_TRACESTATE, values["tracestate"]),
        (HEADER_INTERACTION_ID, values["public_interaction_id"]),
    ):
        if value:
            accepted.append(header_name.lower())

    return ObservedRequestContext(
        correlation_id=values["correlation_id"],
        request_id=values["request_id"],
        traceparent=values["traceparent"],
        tracestate=values["tracestate"],
        public_interaction_id=values["public_interaction_id"],
        provenance=ContextProvenance(
            source="public_headers",
            trust_level=ContextTrustLevel.OBSERVED,
            verified=False,
            carrier="http_headers",
            accepted_headers=tuple(sorted(accepted)),
            ignored_headers=public_ignored_header_names(headers),
        ),
    )


def public_interaction_context_from_headers(
    headers: Mapping[str, str],
    *,
    default_interaction_type: InteractionType = InteractionType.SERVICE_REQUEST,
    interaction_id: str | None = None,
    project_id: str | None = None,
    domain_area: DomainArea | None = None,
    source_entry_point: str | None = None,
    retention_policy_id: str | None = None,
) -> InteractionContext:
    """Create a public-ingress context without trusting public identity headers.

    Public interaction IDs are copied only into ``observed_context`` as
    untrusted hints. The returned ``interaction_id`` is the supplied
    Taproot-boundary value or a freshly minted platform ID.
    """

    observed = observed_context_from_public_headers(headers)
    return InteractionContext(
        interaction_id=interaction_id or create_interaction_id(),
        interaction_type=default_interaction_type,
        project_id=project_id,
        domain_area=domain_area,
        caller=None,
        source_agent_id=None,
        root_agent_id=None,
        source_entry_point=source_entry_point,
        correlation_id=observed.correlation_id,
        trace_id=observed.traceparent,
        retention_policy_id=retention_policy_id,
        parent_activity_id=None,
        provenance=ContextProvenance(
            source="public_boundary",
            trust_level=ContextTrustLevel.OBSERVED,
            verified=False,
            carrier="http_headers",
            accepted_headers=observed.provenance.accepted_headers,
            ignored_headers=observed.provenance.ignored_headers,
        ),
        observed_context=observed,
    )


def internal_interaction_context_from_headers(
    headers: Mapping[str, str],
    *,
    secret: str,
    audience: str,
    default_interaction_type: InteractionType = InteractionType.SERVICE_REQUEST,
    project_id: str | None = None,
    domain_area: DomainArea | None = None,
    source_entry_point: str | None = None,
    retention_policy_id: str | None = None,
) -> InteractionContext:
    """Create a trusted internal context only after bearer-token verification."""

    principal = internal_principal_from_headers(
        headers, secret=secret, audience=audience
    )
    observed = observed_context_from_public_headers(headers)
    interaction_type = _header(headers, HEADER_INTERACTION_TYPE)
    return InteractionContext(
        interaction_id=_header(headers, HEADER_INTERACTION_ID)
        or create_interaction_id(),
        interaction_type=InteractionType(interaction_type)
        if interaction_type
        else default_interaction_type,
        project_id=project_id or _principal_project_id(principal),
        domain_area=domain_area,
        caller=_actor_from_principal(principal),
        source_agent_id=_header(headers, HEADER_SOURCE_AGENT_ID),
        root_agent_id=_header(headers, HEADER_ROOT_AGENT_ID),
        source_entry_point=source_entry_point,
        correlation_id=observed.correlation_id or principal.correlation_id,
        trace_id=observed.traceparent,
        retention_policy_id=retention_policy_id,
        parent_activity_id=_header(headers, HEADER_PARENT_ACTIVITY_ID),
        provenance=ContextProvenance(
            source="internal_bearer_token",
            trust_level=ContextTrustLevel.INTERNAL,
            verified=True,
            carrier="authorization_bearer",
            accepted_headers=tuple(
                sorted(
                    name.lower()
                    for name in (
                        HEADER_INTERACTION_ID,
                        HEADER_INTERACTION_TYPE,
                        HEADER_SOURCE_AGENT_ID,
                        HEADER_ROOT_AGENT_ID,
                        HEADER_PARENT_ACTIVITY_ID,
                    )
                    if _header(headers, name)
                )
            ),
            ignored_headers=(),
        ),
        observed_context=observed,
    )


def bind_public_interaction_context_from_headers(
    headers: Mapping[str, str],
    *,
    default_interaction_type: InteractionType = InteractionType.SERVICE_REQUEST,
    interaction_id: str | None = None,
    project_id: str | None = None,
    domain_area: DomainArea | None = None,
    source_entry_point: str | None = None,
    retention_policy_id: str | None = None,
) -> tuple[InteractionContext, Token[InteractionContext | None]]:
    """Extract and bind safe public-ingress interaction context."""

    context = public_interaction_context_from_headers(
        headers,
        default_interaction_type=default_interaction_type,
        interaction_id=interaction_id,
        project_id=project_id,
        domain_area=domain_area,
        source_entry_point=source_entry_point,
        retention_policy_id=retention_policy_id,
    )
    token = set_interaction_context(context)
    return context, token


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
    """Build outbound TAP-38 propagation headers for a context.

    ``HEADER_PARENT_ACTIVITY_ID`` carries parent-interaction semantics in the
    v1 wire contract; keep the old name until a schema/header rename is approved.
    """

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


def parent_interaction_id(
    context: InteractionContext | None = None,
) -> str | None:
    """Return the upstream parent interaction ID from the v1-compatible field."""

    current = context or get_interaction_context()
    return current.parent_activity_id if current else None


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


def merge_safe_propagation_headers(
    headers: Mapping[str, str] | None = None,
    *,
    context: InteractionContext | None = None,
) -> dict[str, str]:
    """Safely merge outbound context, removing spoofable reserved headers first.

    Unlike :func:`merge_propagation_headers`, existing Taproot-reserved,
    actor, parent, credential, and baggage headers cannot win by casing or
    explicit caller input. Canonical propagation values are rebuilt from the
    supplied/current context.
    """

    generated = propagation_headers(context)
    generated_names = {name.lower() for name in generated}
    cleaned = {
        key: value
        for key, value in strip_reserved_headers(headers or {}).items()
        if key.lower() not in generated_names
    }
    cleaned.update(generated)
    return cleaned


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
    return header_value(headers, name)


def _actor_from_principal(principal: ServicePrincipal) -> ActorRef:
    if isinstance(principal, DelegatedPrincipal):
        actor_id = principal.actor_email or principal.actor_user_id
        if actor_id:
            return ActorRef(
                actor_type="user",
                actor_id=actor_id,
                metadata={"delegated_by_service": principal.service_name},
            )
    return ActorRef(actor_type="service", actor_id=principal.service_name)


def _principal_project_id(principal: ServicePrincipal) -> str | None:
    if isinstance(principal, DelegatedPrincipal):
        return principal.project_id
    value = principal.metadata.get("project_id")
    return str(value) if value else None
