"""Taproot Common - Shared authentication and utilities for Taproot microservices."""

from taproot_common.auth import ApimAuth, AuthContext
from taproot_common.config import TaprootSettings
from taproot_common.exceptions import TaprootServiceError
from taproot_common.fastapi import (
    delegated_actor_token_http_exception,
    verify_delegated_actor_from_request,
)
from taproot_common.http import CircuitOpenError, ServiceHttpClient, get_service_client
from taproot_common.llm_providers import (
    LLMProviderPreset,
    load_llm_provider_key,
    resolve_llm_provider_preset,
)
from taproot_common.secrets import (
    SecretNames,
    is_secrets_enabled,
    load_secret,
)

__all__ = [
    "ApimAuth",
    "AuthContext",
    "CircuitOpenError",
    "ServiceHttpClient",
    "TaprootServiceError",
    "TaprootSettings",
    "SecretNames",
    "LLMProviderPreset",
    "delegated_actor_token_http_exception",
    "get_service_client",
    "is_secrets_enabled",
    "load_llm_provider_key",
    "load_secret",
    "resolve_llm_provider_preset",
    "verify_delegated_actor_from_request",
]
