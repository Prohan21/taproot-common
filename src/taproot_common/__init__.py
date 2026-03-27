"""Taproot Common - Shared authentication and utilities for Taproot microservices."""

from taproot_common.auth import ApimAuth, AuthContext
from taproot_common.config import TaprootSettings
from taproot_common.exceptions import TaprootServiceError
from taproot_common.http import CircuitOpenError, ServiceHttpClient, get_service_client
from taproot_common.secrets import (
    SecretNames,
    is_secrets_enabled,
    load_secret,
    load_secrets_to_env,
)

__all__ = [
    "ApimAuth",
    "AuthContext",
    "CircuitOpenError",
    "ServiceHttpClient",
    "TaprootServiceError",
    "TaprootSettings",
    "SecretNames",
    "get_service_client",
    "is_secrets_enabled",
    "load_secret",
    "load_secrets_to_env",
]
