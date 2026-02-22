"""Shared logging configuration for Taproot services."""

import logging
import sys


def configure_logging(
    service_name: str,
    log_level: str = "INFO",
) -> None:
    """Configure structured logging for a Taproot service.

    Sets up a consistent log format with service name prefix across all services.

    Args:
        service_name: Name of the service (e.g. "retrieval-s", "evals-s").
        log_level: Log level string (DEBUG, INFO, WARNING, ERROR, CRITICAL).
    """
    level = getattr(logging, log_level.upper(), logging.INFO)

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.setLevel(level)

    # Remove existing handlers to avoid duplicate output
    root.handlers.clear()
    root.addHandler(handler)

    # Suppress noisy third-party loggers
    for noisy in ("urllib3", "botocore", "boto3", "s3transfer", "aiobotocore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    logger = logging.getLogger(__name__)
    logger.info(
        "logging.configured",
        extra={"service_name": service_name, "log_level": log_level.upper()},
    )
