"""Targeted LLM provider key loading for Taproot services."""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass

from .secrets import (
    RequiredSecretError,
    SecretNames,
    canonical_secret_name,
    get_runtime_environment,
    is_secrets_enabled,
    load_secret,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class LLMProviderPreset:
    """Resolved provider key preset; contains identifiers, never key values."""

    provider: str
    secret_name: str
    env_vars: tuple[str, ...]


@dataclass(frozen=True)
class _ProviderConfig:
    secret_scope: str
    legacy_secret_name: str
    env_vars: tuple[str, ...]


_PROVIDER_CONFIGS: dict[str, _ProviderConfig] = {
    "openai": _ProviderConfig(
        "openai",
        SecretNames.OPENAI_API_KEY,
        ("OPENAI_API_KEY",),
    ),
    "anthropic": _ProviderConfig(
        "anthropic",
        SecretNames.ANTHROPIC_API_KEY,
        ("ANTHROPIC_API_KEY",),
    ),
    "azure_openai": _ProviderConfig(
        "azure-openai",
        SecretNames.AZURE_OPENAI_API_KEY,
        ("AZURE_OPENAI_API_KEY", "AZURE_API_KEY"),
    ),
    "cohere": _ProviderConfig(
        "cohere",
        SecretNames.COHERE_API_KEY,
        ("COHERE_API_KEY",),
    ),
    "google": _ProviderConfig(
        "google",
        SecretNames.GOOGLE_API_KEY,
        ("GOOGLE_API_KEY",),
    ),
    "gemini": _ProviderConfig(
        "gemini",
        SecretNames.GEMINI_API_KEY,
        ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
    ),
    "mistral": _ProviderConfig(
        "mistral",
        SecretNames.MISTRAL_API_KEY,
        ("MISTRAL_API_KEY",),
    ),
    "voyage": _ProviderConfig(
        "voyage",
        SecretNames.VOYAGE_API_KEY,
        ("VOYAGE_API_KEY",),
    ),
    "huggingface": _ProviderConfig(
        "huggingface",
        SecretNames.HUGGINGFACE_API_KEY,
        ("HUGGINGFACE_API_KEY", "HF_TOKEN"),
    ),
}

_PROVIDER_ALIASES: dict[str, str] = {
    "azure": "azure_openai",
    "azure-openai": "azure_openai",
    "azure_openai": "azure_openai",
    "hf": "huggingface",
    "hugging-face": "huggingface",
    "google-ai": "gemini",
}


def _normalize_provider(provider: str) -> str:
    normalized = provider.strip().lower().replace(" ", "-")
    normalized = _PROVIDER_ALIASES.get(normalized, normalized.replace("-", "_"))
    if normalized not in _PROVIDER_CONFIGS:
        supported = ", ".join(sorted(_PROVIDER_CONFIGS))
        raise ValueError(
            f"Unsupported LLM provider preset: {provider!r}; supported: {supported}"
        )
    return normalized


def _selected_environment(environment: str | None) -> str | None:
    value = get_runtime_environment() if environment is None else environment
    stripped = value.strip().lower()
    return stripped or None


def _api_key_value(secret_value: str, *, secret_name: str) -> str | None:
    stripped = secret_value.strip()
    if not stripped:
        return None
    if not stripped.startswith("{"):
        return stripped

    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        logger.warning("LLM provider secret '%s' is malformed JSON", secret_name)
        return None
    if not isinstance(parsed, dict):
        return None

    value = parsed.get("api_key")
    return value.strip() if isinstance(value, str) and value.strip() else None


def resolve_llm_provider_preset(
    provider: str,
    *,
    environment: str | None = None,
) -> LLMProviderPreset:
    """Resolve the canonical secret/env fallback for one LLM provider."""

    normalized_provider = _normalize_provider(provider)
    config = _PROVIDER_CONFIGS[normalized_provider]
    selected_environment = _selected_environment(environment)
    secret_name = (
        canonical_secret_name(selected_environment, config.secret_scope, "api-key")
        if selected_environment
        else config.legacy_secret_name
    )
    return LLMProviderPreset(
        provider=normalized_provider,
        secret_name=secret_name,
        env_vars=config.env_vars,
    )


def load_llm_provider_key(
    provider: str,
    *,
    environment: str | None = None,
    required: bool = False,
) -> str | None:
    """Load exactly one provider key for direct ``litellm(..., api_key=value)`` use.

    Local/operator env vars are read as fallbacks. This function never writes to
    ``os.environ`` and never scans unrelated provider secrets.
    """

    preset = resolve_llm_provider_preset(provider, environment=environment)
    for env_var in preset.env_vars:
        value = os.environ.get(env_var, "").strip()
        if value:
            return value

    if is_secrets_enabled():
        secret_value = load_secret(preset.secret_name)
        if secret_value:
            api_key = _api_key_value(secret_value, secret_name=preset.secret_name)
            if api_key:
                return api_key
    else:
        logger.debug(
            "Secret manager integration disabled; not loading %s",
            preset.secret_name,
        )

    if required:
        raise RequiredSecretError(
            "Required LLM provider key could not be loaded "
            f"(provider={preset.provider!r}, secret_name={preset.secret_name!r})"
        )
    return None


__all__ = [
    "LLMProviderPreset",
    "load_llm_provider_key",
    "resolve_llm_provider_preset",
]
