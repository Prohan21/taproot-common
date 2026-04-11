"""Centralized LLM provider key resolution for all Taproot services.

This module owns the authoritative mapping from Taproot cloud-secret names
to the standard environment variable names expected by LiteLLM and provider
SDKs. Services should call load_all_llm_keys() once at startup instead of
maintaining their own provider->env var mapping.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from .secrets import SecretNames, load_secrets_to_env

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


def load_all_llm_keys(critical: Optional[list[str]] = None) -> None:
    """Load every known LLM provider key from the cloud secret manager and
    populate standard env vars. Safe to call when most secrets do not exist
    -- missing keys are silently skipped (services declare what is critical).

    Args:
        critical: Optional list of secret names that MUST be present. If any
            are missing, a warning is logged but startup proceeds (LiteLLM
            will surface a clearer error at call time).
    """
    # Flatten the multi-env-var map into a single-env-var map for the existing
    # load_secrets_to_env helper, by loading each secret once and mirroring
    # it to every destination env var.
    flat_mapping: dict[str, str] = {}
    mirror_pairs: list[tuple[str, str]] = []  # (primary_env, mirror_env)
    for secret_name, env_vars in LLM_PROVIDER_ENV_MAP.items():
        primary, *mirrors = env_vars
        flat_mapping[secret_name] = primary
        for mirror in mirrors:
            mirror_pairs.append((primary, mirror))

    critical_set = set(critical) if critical else None
    load_secrets_to_env(flat_mapping, critical_secrets=critical_set)

    # Mirror: copy primary env var to each additional SDK-variant name.
    # Do not overwrite mirror env vars that are already set by the user.
    for primary, mirror in mirror_pairs:
        value = os.environ.get(primary)
        if value and not os.environ.get(mirror):
            os.environ[mirror] = value
            logger.debug("mirrored %s -> %s", primary, mirror)


__all__ = ["LLM_PROVIDER_ENV_MAP", "load_all_llm_keys"]
