"""Tests for taproot_common.http module."""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from taproot_common.http import (
    CircuitOpenError,
    CircuitState,
    ServiceHttpClient,
    _CircuitBreaker,
    _build_traceparent,
    get_service_client,
)


# =============================================================================
# Circuit breaker unit tests
# =============================================================================


class TestCircuitBreaker:
    def test_starts_closed(self) -> None:
        cb = _CircuitBreaker(failure_threshold=3, reset_timeout=10.0)
        assert cb.state == CircuitState.CLOSED

    def test_stays_closed_below_threshold(self) -> None:
        cb = _CircuitBreaker(failure_threshold=3, reset_timeout=10.0)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.CLOSED
        assert cb.allow_request() is True

    def test_opens_after_reaching_threshold(self) -> None:
        cb = _CircuitBreaker(failure_threshold=3, reset_timeout=10.0)
        for _ in range(3):
            cb.record_failure()
        assert cb.state == CircuitState.OPEN
        assert cb.allow_request() is False

    def test_transitions_to_half_open_after_timeout(self) -> None:
        cb = _CircuitBreaker(failure_threshold=2, reset_timeout=0.1)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.OPEN

        # Wait for reset_timeout to elapse
        time.sleep(0.15)
        assert cb.state == CircuitState.HALF_OPEN
        assert cb.allow_request() is True

    def test_half_open_closes_on_success(self) -> None:
        cb = _CircuitBreaker(failure_threshold=2, reset_timeout=0.05)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.1)
        assert cb.state == CircuitState.HALF_OPEN

        cb.record_success()
        assert cb.state == CircuitState.CLOSED

    def test_half_open_opens_on_failure(self) -> None:
        cb = _CircuitBreaker(failure_threshold=2, reset_timeout=0.05)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.1)
        assert cb.state == CircuitState.HALF_OPEN

        cb.record_failure()
        assert cb.state == CircuitState.OPEN

    def test_success_resets_failure_count(self) -> None:
        cb = _CircuitBreaker(failure_threshold=3, reset_timeout=10.0)
        cb.record_failure()
        cb.record_failure()
        cb.record_success()
        # One more failure should not open (count was reset)
        cb.record_failure()
        assert cb.state == CircuitState.CLOSED


# =============================================================================
# W3C traceparent tests
# =============================================================================


class TestTraceparent:
    def test_returns_none_without_otel(self) -> None:
        with patch("taproot_common.http._OTEL_AVAILABLE", False):
            assert _build_traceparent() is None

    def test_builds_traceparent_from_otel_span(self) -> None:
        mock_span_ctx = MagicMock()
        mock_span_ctx.trace_id = 0x0AF7651916CD43DD8448EB211C80319C
        mock_span_ctx.span_id = 0x00F067AA0BA902B7
        mock_span_ctx.trace_flags = 1

        mock_span = MagicMock()
        mock_span.get_span_context.return_value = mock_span_ctx

        with (
            patch("taproot_common.http._OTEL_AVAILABLE", True),
            patch(
                "taproot_common.http.otel_trace", create=True
            ) as mock_trace,
            patch(
                "taproot_common.http.otel_context", create=True
            ) as mock_context,
        ):
            mock_context.get_current.return_value = MagicMock()
            mock_trace.get_current_span.return_value = mock_span

            result = _build_traceparent()

        assert result is not None
        assert result.startswith("00-")
        parts = result.split("-")
        assert len(parts) == 4
        assert parts[0] == "00"  # version
        assert len(parts[1]) == 32  # trace-id
        assert len(parts[2]) == 16  # span-id
        assert parts[3] == "01"  # trace-flags

    def test_returns_none_when_no_active_span(self) -> None:
        mock_span_ctx = MagicMock()
        mock_span_ctx.trace_id = 0  # No trace ID

        mock_span = MagicMock()
        mock_span.get_span_context.return_value = mock_span_ctx

        with (
            patch("taproot_common.http._OTEL_AVAILABLE", True),
            patch(
                "taproot_common.http.otel_trace", create=True
            ) as mock_trace,
            patch(
                "taproot_common.http.otel_context", create=True
            ) as mock_context,
        ):
            mock_context.get_current.return_value = MagicMock()
            mock_trace.get_current_span.return_value = mock_span

            result = _build_traceparent()

        assert result is None


# =============================================================================
# ServiceHttpClient tests
# =============================================================================


class TestServiceHttpClient:
    @pytest.fixture
    def client(self) -> ServiceHttpClient:
        return ServiceHttpClient(
            "https://example.com",
            timeout=5.0,
            max_retries=2,
            backoff_base=0.01,
            failure_threshold=3,
            reset_timeout=0.1,
        )

    async def test_successful_get(self, client: ServiceHttpClient) -> None:
        mock_response = httpx.Response(
            200,
            json={"ok": True},
            request=httpx.Request("GET", "https://example.com/health"),
        )
        with patch.object(client._client, "request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = mock_response
            resp = await client.get("/health")
        assert resp.status_code == 200
        assert client.circuit_state == CircuitState.CLOSED

    async def test_retry_on_503(self, client: ServiceHttpClient) -> None:
        error_response = httpx.Response(
            503,
            request=httpx.Request("GET", "https://example.com/api"),
        )
        ok_response = httpx.Response(
            200,
            json={"ok": True},
            request=httpx.Request("GET", "https://example.com/api"),
        )
        with patch.object(
            client._client, "request", new_callable=AsyncMock
        ) as mock_req:
            mock_req.side_effect = [error_response, ok_response]
            resp = await client.get("/api")
        assert resp.status_code == 200
        assert mock_req.call_count == 2

    async def test_retry_on_502(self, client: ServiceHttpClient) -> None:
        error_response = httpx.Response(
            502,
            request=httpx.Request("POST", "https://example.com/api"),
        )
        ok_response = httpx.Response(
            200,
            json={"ok": True},
            request=httpx.Request("POST", "https://example.com/api"),
        )
        with patch.object(
            client._client, "request", new_callable=AsyncMock
        ) as mock_req:
            mock_req.side_effect = [error_response, ok_response]
            resp = await client.post("/api", json={"data": 1})
        assert resp.status_code == 200
        assert mock_req.call_count == 2

    async def test_no_retry_on_400(self, client: ServiceHttpClient) -> None:
        bad_request = httpx.Response(
            400,
            request=httpx.Request("POST", "https://example.com/api"),
        )
        with patch.object(
            client._client, "request", new_callable=AsyncMock
        ) as mock_req:
            mock_req.return_value = bad_request
            resp = await client.post("/api")
        assert resp.status_code == 400
        assert mock_req.call_count == 1

    async def test_retry_exhausted_returns_last_response(
        self, client: ServiceHttpClient
    ) -> None:
        """After all retries exhausted on retryable status, return last response."""
        error_response = httpx.Response(
            504,
            request=httpx.Request("GET", "https://example.com/api"),
        )
        with patch.object(
            client._client, "request", new_callable=AsyncMock
        ) as mock_req:
            mock_req.return_value = error_response
            resp = await client.get("/api")
        assert resp.status_code == 504
        # max_retries=2, so initial + 2 retries = 3 attempts
        assert mock_req.call_count == 3

    async def test_retry_on_connect_error(self, client: ServiceHttpClient) -> None:
        ok_response = httpx.Response(
            200,
            json={"ok": True},
            request=httpx.Request("GET", "https://example.com/api"),
        )
        with patch.object(
            client._client, "request", new_callable=AsyncMock
        ) as mock_req:
            mock_req.side_effect = [
                httpx.ConnectError("connection refused"),
                ok_response,
            ]
            resp = await client.get("/api")
        assert resp.status_code == 200
        assert mock_req.call_count == 2

    async def test_connect_error_exhausted_raises(
        self, client: ServiceHttpClient
    ) -> None:
        with patch.object(
            client._client, "request", new_callable=AsyncMock
        ) as mock_req:
            mock_req.side_effect = httpx.ConnectError("connection refused")
            with pytest.raises(httpx.ConnectError):
                await client.get("/api")
        # initial + 2 retries = 3 attempts
        assert mock_req.call_count == 3

    async def test_circuit_opens_after_failures(self) -> None:
        client = ServiceHttpClient(
            "https://example.com",
            max_retries=0,
            failure_threshold=2,
            reset_timeout=60.0,
        )
        error_response = httpx.Response(
            503,
            request=httpx.Request("GET", "https://example.com/api"),
        )
        with patch.object(
            client._client, "request", new_callable=AsyncMock
        ) as mock_req:
            mock_req.return_value = error_response
            # First failure
            await client.get("/api")
            # Second failure -> circuit opens
            await client.get("/api")

        assert client.circuit_state == CircuitState.OPEN

        # Next request should raise CircuitOpenError without making HTTP call
        with pytest.raises(CircuitOpenError):
            await client.get("/api")

    async def test_circuit_half_open_recovery(self) -> None:
        client = ServiceHttpClient(
            "https://example.com",
            max_retries=0,
            failure_threshold=2,
            reset_timeout=0.05,
        )
        error_response = httpx.Response(
            503,
            request=httpx.Request("GET", "https://example.com/api"),
        )
        ok_response = httpx.Response(
            200,
            json={"recovered": True},
            request=httpx.Request("GET", "https://example.com/api"),
        )
        with patch.object(
            client._client, "request", new_callable=AsyncMock
        ) as mock_req:
            mock_req.return_value = error_response
            await client.get("/api")
            await client.get("/api")
        assert client.circuit_state == CircuitState.OPEN

        # Wait for reset timeout
        time.sleep(0.1)
        assert client.circuit_state == CircuitState.HALF_OPEN

        with patch.object(
            client._client, "request", new_callable=AsyncMock
        ) as mock_req:
            mock_req.return_value = ok_response
            resp = await client.get("/api")

        assert resp.status_code == 200
        assert client.circuit_state == CircuitState.CLOSED

    async def test_traceparent_injected(self, client: ServiceHttpClient) -> None:
        mock_span_ctx = MagicMock()
        mock_span_ctx.trace_id = 0x0AF7651916CD43DD8448EB211C80319C
        mock_span_ctx.span_id = 0x00F067AA0BA902B7
        mock_span_ctx.trace_flags = 1

        mock_span = MagicMock()
        mock_span.get_span_context.return_value = mock_span_ctx

        ok_response = httpx.Response(
            200,
            request=httpx.Request("GET", "https://example.com/api"),
        )
        with (
            patch("taproot_common.http._OTEL_AVAILABLE", True),
            patch(
                "taproot_common.http.otel_trace", create=True
            ) as mock_trace,
            patch(
                "taproot_common.http.otel_context", create=True
            ) as mock_context,
            patch.object(
                client._client, "request", new_callable=AsyncMock
            ) as mock_req,
        ):
            mock_context.get_current.return_value = MagicMock()
            mock_trace.get_current_span.return_value = mock_span
            mock_req.return_value = ok_response

            await client.get("/api")

        # Verify traceparent was in the headers
        call_kwargs = mock_req.call_args
        headers = call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers", {})
        assert "traceparent" in headers
        assert headers["traceparent"].startswith("00-")

    async def test_existing_headers_preserved(self, client: ServiceHttpClient) -> None:
        ok_response = httpx.Response(
            200,
            request=httpx.Request("GET", "https://example.com/api"),
        )
        with (
            patch("taproot_common.http._OTEL_AVAILABLE", False),
            patch.object(
                client._client, "request", new_callable=AsyncMock
            ) as mock_req,
        ):
            mock_req.return_value = ok_response
            await client.get("/api", headers={"Authorization": "Bearer token"})

        call_kwargs = mock_req.call_args
        headers = call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers", {})
        assert headers["Authorization"] == "Bearer token"

    async def test_connection_pooling_reuses_client(self) -> None:
        """Verify the same httpx.AsyncClient is reused across requests."""
        client = ServiceHttpClient("https://example.com", max_retries=0)
        ok_response = httpx.Response(
            200,
            request=httpx.Request("GET", "https://example.com/api"),
        )
        with patch.object(
            client._client, "request", new_callable=AsyncMock
        ) as mock_req:
            mock_req.return_value = ok_response
            await client.get("/first")
            await client.get("/second")

        # Same underlying client was used both times
        assert mock_req.call_count == 2

    async def test_convenience_methods(self, client: ServiceHttpClient) -> None:
        ok_response = httpx.Response(
            200,
            request=httpx.Request("GET", "https://example.com/api"),
        )
        with (
            patch("taproot_common.http._OTEL_AVAILABLE", False),
            patch.object(
                client._client, "request", new_callable=AsyncMock
            ) as mock_req,
        ):
            mock_req.return_value = ok_response
            await client.put("/r")
            await client.patch("/r")
            await client.delete("/r")

        methods = [call.args[0] for call in mock_req.call_args_list]
        assert methods == ["PUT", "PATCH", "DELETE"]

    async def test_aclose(self, client: ServiceHttpClient) -> None:
        with patch.object(
            client._client, "aclose", new_callable=AsyncMock
        ) as mock_close:
            await client.aclose()
        mock_close.assert_awaited_once()


# =============================================================================
# Factory tests
# =============================================================================


class TestGetServiceClient:
    def test_returns_service_http_client(self) -> None:
        client = get_service_client("https://example.com")
        assert isinstance(client, ServiceHttpClient)

    def test_custom_parameters(self) -> None:
        client = get_service_client(
            "https://example.com",
            timeout=10.0,
            max_retries=5,
            backoff_base=1.0,
            failure_threshold=10,
            reset_timeout=60.0,
        )
        assert isinstance(client, ServiceHttpClient)
        assert client._max_retries == 5
        assert client._backoff_base == 1.0


# =============================================================================
# CircuitOpenError tests
# =============================================================================


class TestCircuitOpenError:
    def test_is_taproot_service_error(self) -> None:
        from taproot_common.exceptions import TaprootServiceError
        exc = CircuitOpenError("https://example.com")
        assert isinstance(exc, TaprootServiceError)

    def test_has_correct_attributes(self) -> None:
        exc = CircuitOpenError("https://example.com")
        assert exc.code == "CIRCUIT_OPEN"
        assert exc.status_code == 503
        assert exc.details == {"base_url": "https://example.com"}
        assert "https://example.com" in exc.message
