"""Shared logging configuration for Taproot services."""
import logging
import sys
from typing import Any, Optional

# Noisy loggers to suppress to WARNING level.
_NOISY_LOGGERS = (
    "urllib3",
    "botocore",
    "boto3",
    "s3transfer",
    "aiobotocore",
    "httpx",
    "httpcore",
    "azure",
    "google.auth",
)

# Feature flag: use structlog when available, fall back to stdlib otherwise.
try:
    import structlog
    _STRUCTLOG_AVAILABLE = True
except ImportError:  # pragma: no cover
    _STRUCTLOG_AVAILABLE = False


def _add_service_field(service_name: str) -> Any:
    """Return a structlog processor that injects ``service`` into every log record."""
    def _processor(logger: Any, method: str, event_dict: dict[str, Any]) -> dict[str, Any]:
        event_dict.setdefault("service", service_name)
        return event_dict
    return _processor


def configure_logging(
    service_name: str,
    log_level: str = "INFO",
    environment: str = "production",
) -> None:
    """Configure structured logging for Taproot services.

    Uses structlog when available (JSON in production, colored console in
    development).  Falls back to stdlib logging when structlog is not installed.

    Args:
        service_name: Name of the calling service (added to every log line).
        log_level: Log level string, e.g. ``"INFO"``, ``"DEBUG"``.
        environment: Runtime environment.  ``"development"`` enables colored
            console output; everything else produces JSON.
    """
    level = getattr(logging, log_level.upper(), logging.INFO)

    if _STRUCTLOG_AVAILABLE:
        _configure_structlog(service_name, level, environment)
    else:
        _configure_stdlib(service_name, level)


def _configure_structlog(service_name: str, level: int, environment: str) -> None:
    """Internal: set up structlog-based logging."""
    from structlog.types import Processor  # type: ignore[import-untyped]

    is_dev = environment == "development"

    shared_processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
        _add_service_field(service_name),
    ]

    if is_dev:
        processors: list[Processor] = shared_processors + [
            structlog.dev.ConsoleRenderer(colors=True),
        ]
    else:
        processors = shared_processors + [
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Wire structlog into the stdlib root logger so that libraries that use
    # ``logging.getLogger()`` also emit structured output.
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=level,
    )
    # Ensure root logger level is set even when basicConfig is a no-op (already
    # called earlier in the process).
    logging.getLogger().setLevel(level)

    _suppress_noisy_loggers()

    logger = structlog.get_logger(__name__)
    logger.info(
        "logging.configured",
        service_name=service_name,
        log_level=logging.getLevelName(level),
        environment=environment,
        backend="structlog",
    )


def _configure_stdlib(service_name: str, level: int) -> None:
    """Internal: fall back to plain stdlib logging."""
    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()
    root.addHandler(handler)

    _suppress_noisy_loggers()

    logger = logging.getLogger(__name__)
    logger.info(
        "logging.configured",
        extra={"service_name": service_name, "log_level": logging.getLevelName(level)},
    )


def _suppress_noisy_loggers() -> None:
    """Set WARNING level on known chatty third-party loggers."""
    for name in _NOISY_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)


def get_logger(name: str) -> Any:
    """Return a logger for *name*.

    Returns a ``structlog.stdlib.BoundLogger`` when structlog is available,
    otherwise a standard ``logging.Logger``.

    Args:
        name: Logger name, typically ``__name__``.
    """
    if _STRUCTLOG_AVAILABLE:
        return structlog.get_logger(name)
    return logging.getLogger(name)  # pragma: no cover


def bind_request_context(
    correlation_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    api_key_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    service: Optional[str] = None,
    actor_identity: Optional[str] = None,
    # Canonical log line fields (Stripe model)
    http_method: Optional[str] = None,
    http_path: Optional[str] = None,
    source_ip: Optional[str] = None,
    env: Optional[str] = None,
    version: Optional[str] = None,
    region: Optional[str] = None,
) -> None:
    """Bind request-scoped fields to the structlog context vars.

    Intended for use in FastAPI middleware at the start of each request.  Each
    field is only bound when a non-``None`` value is provided.

    Args:
        correlation_id: Unique request/trace identifier.
        tenant_id: Tenant or store identifier resolved from the API key.
        api_key_id: APIM-injected API key identifier (``X-Api-Key-Id``).
        agent_id: Agent identifier (``X-Agent-Id``).
        service: Service name override.
        actor_identity: Human user identity from ``X-Actor-Identity``.
        http_method: HTTP method (GET, POST, etc.).
        http_path: HTTP request path.
        source_ip: Client IP (from ``X-Forwarded-For`` or ``request.client.host``).
        env: Runtime environment (dev, staging, prod).
        version: Service version / build SHA.
        region: Cloud region (e.g. us-east-1).
    """
    if not _STRUCTLOG_AVAILABLE:
        return  # pragma: no cover

    ctx: dict[str, Any] = {}
    if correlation_id is not None:
        ctx["correlation_id"] = correlation_id
    if tenant_id is not None:
        ctx["tenant_id"] = tenant_id
    if api_key_id is not None:
        ctx["api_key_id"] = api_key_id
    if agent_id is not None:
        ctx["agent_id"] = agent_id
    if service is not None:
        ctx["service"] = service
    if actor_identity is not None:
        ctx["actor_identity"] = actor_identity
    if http_method is not None:
        ctx["http_method"] = http_method
    if http_path is not None:
        ctx["http_path"] = http_path
    if source_ip is not None:
        ctx["source_ip"] = source_ip
    if env is not None:
        ctx["env"] = env
    if version is not None:
        ctx["version"] = version
    if region is not None:
        ctx["region"] = region

    # Bridge OTel trace context into structlog (Issue #1: OTel-structlog bridge)
    try:
        from opentelemetry.trace import get_current_span  # type: ignore[import-untyped]
        span = get_current_span()
        span_ctx = span.get_span_context()
        if span_ctx and span_ctx.trace_id:
            ctx.setdefault("trace_id", format(span_ctx.trace_id, "032x"))
            ctx.setdefault("span_id", format(span_ctx.span_id, "016x"))
    except Exception:  # noqa: BLE001 — OTel not installed or no active span
        pass

    if ctx:
        structlog.contextvars.bind_contextvars(**ctx)


def clear_request_context() -> None:
    """Clear all structlog context vars bound for the current request.

    Call this in FastAPI middleware after the response has been sent (i.e. in
    the ``finally`` block of the middleware) to avoid context leaking between
    requests on the same event-loop task.
    """
    if not _STRUCTLOG_AVAILABLE:
        return  # pragma: no cover

    structlog.contextvars.clear_contextvars()
