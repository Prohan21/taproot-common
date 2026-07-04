"""Shared FastAPI ingress binding for the TAP-38 interaction context.

Services install one middleware that mints/binds the request-scoped
interaction context at the outermost Taproot-controlled boundary, so every
activity record and log line inside the request inherits one
``interaction_id``. Public inbound ``X-Taproot-Interaction-Id`` values are
kept only as observed hints; a verified internal bearer token upgrades the
binding to a trusted child context with parent lineage.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Mapping, Protocol
from uuid import uuid4

import structlog

from taproot_common.activity.context import (
    HEADER_CORRELATION_ID,
    internal_interaction_context_from_headers,
    public_interaction_context_from_headers,
    reset_interaction_context,
    set_interaction_context,
)
from taproot_common.activity.models import (
    DomainArea,
    InteractionContext,
    InteractionType,
)
from taproot_common.trust.headers import extract_bearer_token

if TYPE_CHECKING:
    from fastapi import FastAPI, Request, Response

logger = logging.getLogger(__name__)

ProjectIdResolver = Callable[["Request"], "str | None"]


class InteractionRecorderLike(Protocol):
    """Minimal recorder surface the ingress middleware depends on."""

    def record_interaction(self, context: InteractionContext) -> Awaitable[Any]: ...


RecorderProvider = Callable[[], "InteractionRecorderLike | None"]


def _default_recorder_provider() -> InteractionRecorderLike | None:
    from taproot_common.activity.recorder import get_activity_recorder

    return get_activity_recorder()


def _build_context(
    headers: Mapping[str, str],
    *,
    default_interaction_type: InteractionType,
    domain_area: DomainArea | None,
    project_id: str | None,
    source_entry_point: str,
    internal_secret: str | None,
    internal_audience: str | None,
) -> InteractionContext:
    if internal_secret and internal_audience and extract_bearer_token(headers):
        try:
            return internal_interaction_context_from_headers(
                headers,
                secret=internal_secret,
                audience=internal_audience,
                default_interaction_type=default_interaction_type,
                project_id=project_id,
                domain_area=domain_area,
                source_entry_point=source_entry_point,
            )
        except Exception:
            # Accept-then-enforce: an unverifiable bearer token downgrades to
            # the public/observed binding instead of failing the request.
            logger.warning(
                "activity.ingress.internal_token_rejected",
                extra={"source_entry_point": source_entry_point},
            )
    return public_interaction_context_from_headers(
        headers,
        default_interaction_type=default_interaction_type,
        project_id=project_id,
        domain_area=domain_area,
        source_entry_point=source_entry_point,
    )


def install_interaction_context_middleware(
    app: FastAPI,
    *,
    service_name: str,
    default_interaction_type: InteractionType = InteractionType.SERVICE_REQUEST,
    domain_area: DomainArea | None = None,
    project_id_resolver: ProjectIdResolver | None = None,
    internal_secret: str | None = None,
    internal_audience: str | None = None,
    recorder_provider: RecorderProvider | None = _default_recorder_provider,
) -> None:
    """Install the shared TAP-38 interaction bind middleware on a FastAPI app.

    Binding is additive and best-effort: any failure to build, bind, or record
    the interaction context is logged and the request proceeds unchanged.

    Args:
        app: FastAPI application to install the middleware on.
        service_name: Service identifier used in log events.
        default_interaction_type: Interaction type when headers carry none.
        domain_area: Service domain recorded on the interaction.
        project_id_resolver: Optional callable deriving a project id from the
            request (e.g. from the path).
        internal_secret: HMAC secret for verifying internal bearer tokens.
            When set together with ``internal_audience``, a valid token yields
            a verified child context with ``parent_interaction_id`` lineage.
        internal_audience: Expected audience for internal bearer tokens.
        recorder_provider: Returns the activity recorder used to persist an
            interaction record for each bound context. Defaults to the
            process-configured recorder; pass ``None`` to disable recording.
    """

    @app.middleware("http")
    async def taproot_interaction_context_middleware(  # type: ignore[misc]
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        token = None
        bound_structlog = False
        try:
            correlation_id = request.headers.get(HEADER_CORRELATION_ID) or str(uuid4())
            headers = dict(request.headers.items())
            headers.setdefault(HEADER_CORRELATION_ID, correlation_id)
            project_id = project_id_resolver(request) if project_id_resolver else None
            context = _build_context(
                headers,
                default_interaction_type=default_interaction_type,
                domain_area=domain_area,
                project_id=project_id,
                source_entry_point=f"{request.method} {request.url.path}",
                internal_secret=internal_secret,
                internal_audience=internal_audience,
            )
            token = set_interaction_context(context)
            if getattr(request.state, "correlation_id", None) is None:
                request.state.correlation_id = correlation_id
            request.state.taproot_interaction_id = context.interaction_id
            structlog.contextvars.bind_contextvars(
                interaction_id=context.interaction_id
            )
            bound_structlog = True
            await _record_interaction(context, recorder_provider, service_name)
        except Exception:
            logger.warning(
                "activity.ingress.bind_failed",
                extra={"service": service_name},
                exc_info=True,
            )
        try:
            return await call_next(request)
        finally:
            if bound_structlog:
                structlog.contextvars.unbind_contextvars("interaction_id")
            if token is not None:
                reset_interaction_context(token)


async def _record_interaction(
    context: InteractionContext,
    recorder_provider: RecorderProvider | None,
    service_name: str,
) -> None:
    if recorder_provider is None:
        return
    try:
        recorder = recorder_provider()
        if recorder is not None:
            await recorder.record_interaction(context)
    except Exception:
        logger.warning(
            "activity.ingress.interaction_record_failed",
            extra={
                "service": service_name,
                "interaction_id": context.interaction_id,
            },
            exc_info=True,
        )
