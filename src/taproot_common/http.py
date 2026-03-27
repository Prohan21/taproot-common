"""Shared HTTP client with retry, circuit breaker, and W3C trace context injection."""

from __future__ import annotations

import enum
import logging
import time
from typing import Any

import httpx

from taproot_common.exceptions import TaprootServiceError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional OpenTelemetry support
# ---------------------------------------------------------------------------
try:
    from opentelemetry import context as otel_context  # type: ignore[import-untyped]
    from opentelemetry import trace as otel_trace  # type: ignore[import-untyped]

    _OTEL_AVAILABLE = True
except ImportError:
    _OTEL_AVAILABLE = False


# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------

class CircuitState(enum.Enum):
    """Circuit breaker states."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitOpenError(TaprootServiceError):
    """Raised when the circuit breaker is open and requests are rejected."""

    def __init__(self, base_url: str) -> None:
        super().__init__(
            f"Circuit breaker is open for {base_url}",
            code="CIRCUIT_OPEN",
            status_code=503,
            details={"base_url": base_url},
        )


class _CircuitBreaker:
    """Simple circuit breaker state machine.

    State transitions:
        CLOSED  -> OPEN       after ``failure_threshold`` consecutive failures.
        OPEN    -> HALF_OPEN  after ``reset_timeout`` seconds.
        HALF_OPEN -> CLOSED   on first success.
        HALF_OPEN -> OPEN     on first failure.
    """

    def __init__(self, failure_threshold: int, reset_timeout: float) -> None:
        self._failure_threshold = failure_threshold
        self._reset_timeout = reset_timeout
        self._state = CircuitState.CLOSED
        self._failure_count: int = 0
        self._last_failure_time: float = 0.0

    @property
    def state(self) -> CircuitState:
        if self._state == CircuitState.OPEN:
            elapsed = time.monotonic() - self._last_failure_time
            if elapsed >= self._reset_timeout:
                self._state = CircuitState.HALF_OPEN
        return self._state

    def record_success(self) -> None:
        self._failure_count = 0
        self._state = CircuitState.CLOSED

    def record_failure(self) -> None:
        self._failure_count += 1
        self._last_failure_time = time.monotonic()
        if (
            self._state == CircuitState.HALF_OPEN
            or self._failure_count >= self._failure_threshold
        ):
            self._state = CircuitState.OPEN

    def allow_request(self) -> bool:
        current = self.state
        return current in (CircuitState.CLOSED, CircuitState.HALF_OPEN)


# ---------------------------------------------------------------------------
# W3C traceparent helper
# ---------------------------------------------------------------------------

_RETRYABLE_STATUS_CODES = frozenset({502, 503, 504})


def _build_traceparent() -> str | None:
    """Build a W3C ``traceparent`` header value from the current OTel span context.

    Returns ``None`` when OpenTelemetry is not installed or there is no active span.
    """
    if not _OTEL_AVAILABLE:
        return None

    try:
        span = otel_trace.get_current_span(otel_context.get_current())
        ctx = span.get_span_context()
        if ctx is None or not ctx.trace_id:
            return None
        trace_id = format(ctx.trace_id, "032x")
        span_id = format(ctx.span_id, "016x")
        trace_flags = format(ctx.trace_flags, "02x")
        return f"00-{trace_id}-{span_id}-{trace_flags}"
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------------------
# ServiceHttpClient
# ---------------------------------------------------------------------------


class ServiceHttpClient:
    """HTTP client with retry, circuit breaker, and W3C trace context injection.

    Wraps ``httpx.AsyncClient`` with:
    - Connection pooling (reusable across requests)
    - Configurable retry with exponential backoff (502/503/504 + connection errors)
    - Simple circuit breaker (failure_threshold / reset_timeout)
    - W3C ``traceparent`` header injection from OTel span context

    Args:
        base_url: Base URL for all requests.
        timeout: Request timeout in seconds.
        max_retries: Maximum number of retry attempts.
        backoff_base: Base delay (seconds) for exponential backoff.
        failure_threshold: Consecutive failures before circuit opens.
        reset_timeout: Seconds before an open circuit transitions to half-open.
    """

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 30.0,
        max_retries: int = 3,
        backoff_base: float = 0.5,
        failure_threshold: int = 5,
        reset_timeout: float = 30.0,
    ) -> None:
        self._base_url = base_url
        self._max_retries = max_retries
        self._backoff_base = backoff_base
        self._circuit = _CircuitBreaker(failure_threshold, reset_timeout)
        self._client = httpx.AsyncClient(
            base_url=base_url,
            timeout=httpx.Timeout(timeout),
        )

    # -- internal helpers ---------------------------------------------------

    def _inject_traceparent(self, headers: dict[str, str]) -> dict[str, str]:
        """Inject W3C ``traceparent`` header if OTel context is available."""
        traceparent = _build_traceparent()
        if traceparent is not None:
            headers.setdefault("traceparent", traceparent)
        return headers

    async def _execute_with_retry(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> httpx.Response:
        """Execute a request with retry logic and circuit breaker checks."""
        if not self._circuit.allow_request():
            raise CircuitOpenError(self._base_url)

        headers: dict[str, str] = dict(kwargs.pop("headers", None) or {})
        headers = self._inject_traceparent(headers)
        kwargs["headers"] = headers

        last_exc: BaseException | None = None
        for attempt in range(self._max_retries + 1):
            try:
                response = await self._client.request(method, url, **kwargs)

                if response.status_code in _RETRYABLE_STATUS_CODES:
                    last_exc = httpx.HTTPStatusError(
                        f"Server error {response.status_code}",
                        request=response.request,
                        response=response,
                    )
                    if attempt < self._max_retries:
                        delay = self._backoff_base * (2 ** attempt)
                        logger.warning(
                            "http.retry",
                            extra={
                                "method": method,
                                "url": url,
                                "status_code": response.status_code,
                                "attempt": attempt + 1,
                                "delay": delay,
                            },
                        )
                        import asyncio
                        await asyncio.sleep(delay)
                        continue
                    # Final attempt failed with retryable status
                    self._circuit.record_failure()
                    return response

                # Non-retryable status or success
                self._circuit.record_success()
                return response

            except httpx.ConnectError as exc:
                last_exc = exc
                if attempt < self._max_retries:
                    delay = self._backoff_base * (2 ** attempt)
                    logger.warning(
                        "http.retry.connection_error",
                        extra={
                            "method": method,
                            "url": url,
                            "attempt": attempt + 1,
                            "delay": delay,
                            "error": str(exc),
                        },
                    )
                    import asyncio
                    await asyncio.sleep(delay)
                    continue

                self._circuit.record_failure()
                raise

        # Should not reach here, but satisfy type checker
        if last_exc is not None:
            self._circuit.record_failure()
            raise last_exc  # pragma: no cover
        raise RuntimeError("Unexpected retry loop exit")  # pragma: no cover

    # -- public API ---------------------------------------------------------

    async def request(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> httpx.Response:
        """Send an HTTP request with retry and circuit breaker protection.

        Args:
            method: HTTP method (GET, POST, PUT, PATCH, DELETE).
            url: URL path (relative to base_url) or absolute URL.
            **kwargs: Additional keyword arguments forwarded to ``httpx.AsyncClient.request``.

        Returns:
            The ``httpx.Response`` object.

        Raises:
            CircuitOpenError: When the circuit breaker is open.
            httpx.ConnectError: When all retries are exhausted on connection errors.
        """
        return await self._execute_with_retry(method, url, **kwargs)

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        """Send a GET request."""
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        """Send a POST request."""
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs: Any) -> httpx.Response:
        """Send a PUT request."""
        return await self.request("PUT", url, **kwargs)

    async def patch(self, url: str, **kwargs: Any) -> httpx.Response:
        """Send a PATCH request."""
        return await self.request("PATCH", url, **kwargs)

    async def delete(self, url: str, **kwargs: Any) -> httpx.Response:
        """Send a DELETE request."""
        return await self.request("DELETE", url, **kwargs)

    async def aclose(self) -> None:
        """Close the underlying HTTP client and release connection pool resources."""
        await self._client.aclose()

    @property
    def circuit_state(self) -> CircuitState:
        """Current circuit breaker state."""
        return self._circuit.state


# ---------------------------------------------------------------------------
# Module-level factory
# ---------------------------------------------------------------------------


def get_service_client(
    base_url: str,
    *,
    timeout: float = 30.0,
    max_retries: int = 3,
    backoff_base: float = 0.5,
    failure_threshold: int = 5,
    reset_timeout: float = 30.0,
) -> ServiceHttpClient:
    """Create a new :class:`ServiceHttpClient`.

    This is the recommended entry point for obtaining a client instance.

    Args:
        base_url: Base URL for the target service.
        timeout: Request timeout in seconds.
        max_retries: Maximum retry attempts for retryable errors.
        backoff_base: Base delay (seconds) for exponential backoff.
        failure_threshold: Consecutive failures before circuit opens.
        reset_timeout: Seconds before open circuit transitions to half-open.

    Returns:
        A configured :class:`ServiceHttpClient` instance.
    """
    return ServiceHttpClient(
        base_url,
        timeout=timeout,
        max_retries=max_retries,
        backoff_base=backoff_base,
        failure_threshold=failure_threshold,
        reset_timeout=reset_timeout,
    )
