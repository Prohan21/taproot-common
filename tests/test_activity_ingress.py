"""Tests for the shared FastAPI interaction-context ingress middleware."""

from typing import Any
from uuid import UUID

import httpx
import structlog
from fastapi import FastAPI, Request

from taproot_common.activity import (
    HEADER_INTERACTION_ID,
    HEADER_PARENT_INTERACTION_ID,
    DomainArea,
    InteractionContext,
    InteractionType,
    get_interaction_context,
)
from taproot_common.activity.ingress import install_interaction_context_middleware
from taproot_common.trust import mint_internal_token
from taproot_common.trust.models import ContextTrustLevel

INTERNAL_SECRET = "test-internal-secret"
INTERNAL_AUDIENCE = "test-service"


def _build_app(**middleware_kwargs: Any) -> tuple[FastAPI, dict[str, Any]]:
    app = FastAPI()
    seen: dict[str, Any] = {}

    @app.get("/probe")
    async def probe(request: Request) -> dict[str, Any]:
        context = get_interaction_context()
        seen["context"] = context
        seen["state_interaction_id"] = getattr(
            request.state, "taproot_interaction_id", None
        )
        seen["structlog"] = dict(structlog.contextvars.get_contextvars())
        return {"interaction_id": context.interaction_id if context else None}

    install_interaction_context_middleware(
        app, service_name="test-service", **middleware_kwargs
    )
    return app, seen


async def _get(app: FastAPI, headers: dict[str, str] | None = None) -> httpx.Response:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.get("/probe", headers=headers)


async def test_mints_one_interaction_id_when_no_inbound_headers() -> None:
    app, seen = _build_app()
    response = await _get(app)

    assert response.status_code == 200
    context = seen["context"]
    assert context is not None
    UUID(context.interaction_id)
    assert seen["state_interaction_id"] == context.interaction_id
    assert response.json()["interaction_id"] == context.interaction_id


async def test_public_inbound_interaction_id_is_observed_only() -> None:
    app, seen = _build_app()
    spoofed = "spoofed-interaction-id"
    response = await _get(app, headers={HEADER_INTERACTION_ID: spoofed})

    assert response.status_code == 200
    context = seen["context"]
    assert context.interaction_id != spoofed
    assert context.observed_context is not None
    assert context.observed_context.public_interaction_id == spoofed
    assert context.provenance is not None
    assert context.provenance.verified is False


async def test_context_is_reset_after_request() -> None:
    app, _ = _build_app()
    await _get(app)
    assert get_interaction_context() is None


async def test_interaction_id_bound_into_structlog_context() -> None:
    app, seen = _build_app()
    await _get(app)
    context = seen["context"]
    assert seen["structlog"].get("interaction_id") == context.interaction_id
    assert "interaction_id" not in structlog.contextvars.get_contextvars()


async def test_default_type_domain_and_entry_point_are_applied() -> None:
    app, seen = _build_app(
        default_interaction_type=InteractionType.ADMIN_ACTION,
        domain_area=DomainArea.PROMPT,
    )
    await _get(app)
    context = seen["context"]
    assert context.interaction_type is InteractionType.ADMIN_ACTION
    assert context.domain_area is DomainArea.PROMPT
    assert context.source_entry_point == "GET /probe"


async def test_bind_failure_does_not_fail_the_request(monkeypatch) -> None:
    import taproot_common.activity.ingress as ingress

    def _boom(*args: Any, **kwargs: Any) -> InteractionContext:
        raise RuntimeError("bind failed")

    monkeypatch.setattr(ingress, "public_interaction_context_from_headers", _boom)
    app, seen = _build_app()
    response = await _get(app)

    assert response.status_code == 200
    assert seen["context"] is None


async def test_internal_bearer_token_yields_verified_child_context() -> None:
    app, seen = _build_app(
        internal_secret=INTERNAL_SECRET, internal_audience=INTERNAL_AUDIENCE
    )
    token = mint_internal_token(
        secret=INTERNAL_SECRET,
        subject="worker-s",
        audience=INTERNAL_AUDIENCE,
    )
    upstream_interaction = "upstream-interaction-id"
    response = await _get(
        app,
        headers={
            "Authorization": f"Bearer {token}",
            HEADER_INTERACTION_ID: upstream_interaction,
        },
    )

    assert response.status_code == 200
    context = seen["context"]
    assert context.provenance.trust_level is ContextTrustLevel.INTERNAL
    assert context.provenance.verified is True
    assert context.parent_interaction_id == upstream_interaction
    assert context.interaction_id != upstream_interaction


async def test_invalid_internal_token_falls_back_to_public_binding() -> None:
    app, seen = _build_app(
        internal_secret=INTERNAL_SECRET, internal_audience=INTERNAL_AUDIENCE
    )
    response = await _get(
        app,
        headers={
            "Authorization": "Bearer not-a-valid-token",
            HEADER_INTERACTION_ID: "spoofed",
            HEADER_PARENT_INTERACTION_ID: "spoofed-parent",
        },
    )

    assert response.status_code == 200
    context = seen["context"]
    assert context.provenance.trust_level is ContextTrustLevel.OBSERVED
    assert context.parent_interaction_id is None
    assert context.interaction_id != "spoofed"


async def test_records_interaction_when_recorder_configured() -> None:
    recorded: list[InteractionContext] = []

    class FakeRecorder:
        async def record_interaction(self, context: InteractionContext) -> None:
            recorded.append(context)

    app, seen = _build_app(recorder_provider=lambda: FakeRecorder())
    await _get(app)

    assert len(recorded) == 1
    assert recorded[0].interaction_id == seen["context"].interaction_id


async def test_recorder_failure_does_not_fail_the_request() -> None:
    class BrokenRecorder:
        async def record_interaction(self, context: InteractionContext) -> None:
            raise RuntimeError("storage down")

    app, seen = _build_app(recorder_provider=lambda: BrokenRecorder())
    response = await _get(app)

    assert response.status_code == 200
    assert seen["context"] is not None


async def test_project_id_resolver_is_applied() -> None:
    app, seen = _build_app(project_id_resolver=lambda request: "proj-42")
    await _get(app)
    assert seen["context"].project_id == "proj-42"


async def test_no_project_yields_system_scoped_context() -> None:
    from taproot_common.activity import RecordScope

    app, seen = _build_app()
    await _get(app)
    assert seen["context"].record_scope is RecordScope.SYSTEM


async def test_resolved_project_yields_project_scoped_context() -> None:
    from taproot_common.activity import RecordScope

    app, seen = _build_app(project_id_resolver=lambda request: "proj-9")
    await _get(app)
    assert seen["context"].record_scope is RecordScope.PROJECT
