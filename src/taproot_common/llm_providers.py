"""Centralized LLM provider key resolution for all Taproot services.

This module owns the authoritative mapping from Taproot cloud-secret names
to the standard key names expected by LiteLLM and provider SDKs. Services
should use load_all_llm_key_values() and pass values directly to clients.
load_all_llm_keys() remains only as a legacy env-mirroring shim.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from .secrets import SecretNames, is_secrets_enabled, load_secret

logger = logging.getLogger(__name__)

# Authoritative registry: Taproot cloud secret name -> list of env var names to
# populate. A single secret may map to multiple env vars when SDKs disagree on
# naming (e.g. Azure OpenAI SDK uses AZURE_OPENAI_API_KEY while LiteLLM uses
# AZURE_API_KEY -- we mirror to both).
LLM_PROVIDER_ENV_MAP: dict[str, list[str]] = {
    SecretNames.OPENAI_API_KEY: ["OPENAI_API_KEY"],
    SecretNames.ANTHROPIC_API_KEY: ["ANTHROPIC_API_KEY"],
    SecretNames.AZURE_OPENAI_API_KEY: ["AZURE_OPENAI_API_KEY", "AZURE_API_KEY"],
    SecretNames.COHERE_API_KEY: ["COHERE_API_KEY"],
    SecretNames.GOOGLE_API_KEY: ["GOOGLE_API_KEY"],
    SecretNames.GEMINI_API_KEY: ["GEMINI_API_KEY"],
    SecretNames.MISTRAL_API_KEY: ["MISTRAL_API_KEY"],
    SecretNames.VOYAGE_API_KEY: ["VOYAGE_API_KEY"],
    SecretNames.HUGGINGFACE_API_KEY: ["HUGGINGFACE_API_KEY", "HF_TOKEN"],
    SecretNames.VERTEX_API_KEY: ["VERTEX_API_KEY"],
    SecretNames.VERTEX_PROJECT: ["VERTEX_PROJECT"],
    SecretNames.BEDROCK_ACCESS_KEY_ID: ["AWS_ACCESS_KEY_ID"],
    SecretNames.BEDROCK_SECRET_ACCESS_KEY: ["AWS_SECRET_ACCESS_KEY"],
}


def load_all_llm_key_values(critical: Optional[list[str]] = None) -> dict[str, str]:
    """Load known LLM provider keys into memory without mutating ``os.environ``.

    Returned keys use the SDK-compatible names from ``LLM_PROVIDER_ENV_MAP`` so
    services can pass values directly to clients while keeping provider naming in
    one place. Local/operator env overrides are read but never written.

    Args:
        critical: Optional list of cloud secret names that should log a warning
            when missing. Startup still proceeds.
    """
    values: dict[str, str] = {}
    critical_set = set(critical) if critical else set()

    secrets_enabled = is_secrets_enabled()
    if not secrets_enabled:
        logger.debug(
            "Secret manager integration disabled "
            "(set TAPROOT_SECRETS_ENABLED=true to enable)"
        )

    for secret_name, env_vars in LLM_PROVIDER_ENV_MAP.items():
        local_value = None
        for env_var in env_vars:
            env_value = os.environ.get(env_var)
            if env_value:
                values[env_var] = env_value
                local_value = local_value or env_value

        secret_value = local_value or (load_secret(secret_name) if secrets_enabled else None)
        if secret_value:
            for env_var in env_vars:
                values.setdefault(env_var, secret_value)
        elif secrets_enabled and secret_name in critical_set:
            logger.warning("Could not load critical LLM provider secret '%s'", secret_name)

    return values


def load_all_llm_keys(critical: Optional[list[str]] = None) -> None:
    """Deprecated: mirror LLM provider keys into environment variables.

    Use ``load_all_llm_key_values`` and pass returned values directly to provider
    clients. This shim remains because several services still depend on env-based
    LiteLLM/provider wiring.
    """
    # ponytail: legacy env bridge; delete once services pass returned key values
    # directly to LiteLLM/provider clients.
    logger.warning(
        "load_all_llm_keys() is deprecated; use load_all_llm_key_values() and "
        "pass keys directly to LLM clients instead of os.environ"
    )
    for env_var, value in load_all_llm_key_values(critical).items():
        if value and not os.environ.get(env_var):
            os.environ[env_var] = value
            logger.debug("loaded LLM provider key for %s", env_var)


__all__ = ["LLM_PROVIDER_ENV_MAP", "load_all_llm_key_values", "load_all_llm_keys"]
