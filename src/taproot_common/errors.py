"""Shared error handlers for FastAPI services."""

import logging
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger(__name__)


def _request_id(request: Request) -> str | None:
    state_id = getattr(request.state, "correlation_id", None)
    if isinstance(state_id, str) and state_id:
        return state_id
    header_id = request.headers.get("X-Correlation-ID") or request.headers.get("X-Request-ID")
    return header_id or None


def _summarize_validation_errors(exc: RequestValidationError) -> str:
    parts: list[str] = []
    for error in exc.errors()[:3]:
        field = " -> ".join(str(loc) for loc in error["loc"])
        parts.append(f"{field}: {error['msg']}")
    return "; ".join(parts)


def install_error_handlers(app: FastAPI) -> None:
    """Install standard error response handlers on a FastAPI application.

    Handles:
    - HTTPException (4xx/5xx) with consistent JSON envelope
    - RequestValidationError (422) with field-level details
    - Unhandled exceptions (500) with safe error message
    """

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(
        request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        request_id = _request_id(request)
        detail = exc.detail
        if isinstance(detail, str):
            message = detail
        elif isinstance(detail, list):
            message = "; ".join(
                item.get("msg", str(item)) if isinstance(item, dict) else str(item)
                for item in detail
            )
        elif isinstance(detail, dict):
            message = str(detail.get("message") or detail.get("error") or detail)
        else:
            message = str(detail)

        return JSONResponse(
            status_code=exc.status_code,
            content={
                "detail": detail,
                "message": (
                    f"{message}. Request ID: {request_id}."
                    if request_id
                    else message
                ),
                "request_id": request_id,
                "path": request.url.path,
                "method": request.method,
            },
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        request_id = _request_id(request)
        errors: list[dict[str, Any]] = []
        for error in exc.errors():
            errors.append(
                {
                    "field": " -> ".join(str(loc) for loc in error["loc"]),
                    "message": error["msg"],
                    "type": error["type"],
                }
            )
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "detail": "Validation error",
                "message": (
                    f"Validation error on {request.method} {request.url.path}: {_summarize_validation_errors(exc)}. Request ID: {request_id}."
                    if request_id
                    else f"Validation error on {request.method} {request.url.path}: {_summarize_validation_errors(exc)}."
                ),
                "errors": errors,
                "request_id": request_id,
                "path": request.url.path,
                "method": request.method,
            },
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        request_id = _request_id(request)
        logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "detail": "Internal server error",
                "message": (
                    f"Internal server error while handling {request.method} {request.url.path}. Request ID: {request_id}."
                    if request_id
                    else f"Internal server error while handling {request.method} {request.url.path}."
                ),
                "request_id": request_id,
                "path": request.url.path,
                "method": request.method,
            },
        )
