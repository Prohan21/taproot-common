"""Shared base exception for all Taproot services."""

from __future__ import annotations

from typing import Any


class TaprootServiceError(Exception):
    """Base exception for all Taproot platform services.

    Attributes:
        message: Human-readable error description.
        code: Machine-readable error code (e.g., "STORE_NOT_FOUND").
        status_code: HTTP status code for API responses.
        details: Optional dict of additional context.
    """

    def __init__(
        self,
        message: str,
        *,
        code: str,
        status_code: int = 500,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details or {}
