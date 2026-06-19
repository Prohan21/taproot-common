"""Tests for taproot_common.llm_providers module."""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest
import taproot_common

from taproot_common import llm_providers as llm_provider_helpers
from taproot_common.llm_providers import (
    load_llm_provider_key,
    resolve_llm_provider_preset,
)
from taproot_common.secrets import RequiredSecretError


_ENV_VARS = {
    "ANTHROPIC_API_KEY",
    "AZURE_API_KEY",
    "AZURE_OPENAI_API_KEY",
    "COHERE_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "HUGGINGFACE_API_KEY",
    "HF_TOKEN",
    "MISTRAL_API_KEY",
    "OPENAI_API_KEY",
    "VOYAGE_API_KEY",
}
_CONTROL_VARS = {
    "TAPROOT_CLOUD_PROVIDER",
    "TAPROOT_ENV",
    "TAPROOT_ENVIRONMENT",
    "TAPROOT_SECRETS_ENABLED",
}


@pytest.fixture(autouse=True)
def _clean_env() -> Iterator[None]:
    tracked = _ENV_VARS | _CONTROL_VARS
    saved: dict[str, str | None] = {name: os.environ.get(name) for name in tracked}
    for name in tracked:
        os.environ.pop(name, None)
    try:
        yield
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def test_broad_llm_loaders_are_not_public() -> None:
    removed_exports = (
        "load_" + "all_" + "llm_keys",
        "load_" + "all_" + "llm_key_values",
    )
    for export in removed_exports:
        assert not hasattr(llm_provider_helpers, export)
        assert not hasattr(taproot_common, export)
        assert export not in taproot_common.__all__


@pytest.mark.parametrize(
    ("provider", "expected_provider", "expected_secret"),
    (
        ("openai", "openai", "taproot-prod-openai-api-key"),
        ("anthropic", "anthropic", "taproot-prod-anthropic-api-key"),
        ("azure_openai", "azure_openai", "taproot-prod-azure-openai-api-key"),
        ("azure-openai", "azure_openai", "taproot-prod-azure-openai-api-key"),
        ("azure", "azure_openai", "taproot-prod-azure-openai-api-key"),
        ("cohere", "cohere", "taproot-prod-cohere-api-key"),
        ("google", "google", "taproot-prod-google-api-key"),
        ("gemini", "gemini", "taproot-prod-gemini-api-key"),
        ("mistral", "mistral", "taproot-prod-mistral-api-key"),
        ("voyage", "voyage", "taproot-prod-voyage-api-key"),
        ("huggingface", "huggingface", "taproot-prod-huggingface-api-key"),
    ),
)
def test_resolves_supported_provider_presets(
    provider: str,
    expected_provider: str,
    expected_secret: str,
) -> None:
    preset = resolve_llm_provider_preset(provider, environment="Prod")

    assert preset.provider == expected_provider
    assert preset.secret_name == expected_secret
    assert preset.env_vars


def test_resolves_environment_from_runtime_env(monkeypatch) -> None:
    monkeypatch.setenv("TAPROOT_ENV", "staging")

    preset = resolve_llm_provider_preset("openai")

    assert preset.secret_name == "taproot-staging-openai-api-key"


def test_rejects_unknown_provider() -> None:
    with pytest.raises(ValueError, match="Unsupported LLM provider preset"):
        resolve_llm_provider_preset("bedrock")


def test_loads_only_selected_cloud_key_without_mutating_env(monkeypatch) -> None:
    requested: list[str] = []
    monkeypatch.setenv("TAPROOT_SECRETS_ENABLED", "true")
    before_env = dict(os.environ)

    def load_secret(secret_name: str) -> str | None:
        requested.append(secret_name)
        return '{"api_key":"sk-azure-cloud"}'

    monkeypatch.setattr(llm_provider_helpers, "load_secret", load_secret)

    key = load_llm_provider_key("azure", environment="prod")

    assert key == "sk-azure-cloud"
    assert requested == ["taproot-prod-azure-openai-api-key"]
    assert dict(os.environ) == before_env


def test_reads_operator_env_override_without_mirroring(monkeypatch) -> None:
    monkeypatch.setenv("HUGGINGFACE_API_KEY", "hf-local")
    before_env = dict(os.environ)

    key = load_llm_provider_key("huggingface", environment="prod")

    assert key == "hf-local"
    assert "HF_TOKEN" not in os.environ
    assert dict(os.environ) == before_env


def test_reads_provider_alias_env_override(monkeypatch) -> None:
    monkeypatch.setenv("HF_TOKEN", "hf-token-local")

    assert load_llm_provider_key("huggingface", environment="prod") == "hf-token-local"


def test_required_provider_key_raises_sanitized_error() -> None:
    with pytest.raises(RequiredSecretError) as exc_info:
        load_llm_provider_key("openai", environment="prod", required=True)

    error_text = str(exc_info.value)
    assert "openai" in error_text
    assert "taproot-prod-openai-api-key" in error_text
    assert "sk-" not in error_text
