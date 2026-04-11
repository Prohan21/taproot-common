"""Tests for taproot_common.llm_providers module."""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from taproot_common.llm_providers import LLM_PROVIDER_ENV_MAP, load_all_llm_keys
from taproot_common.secrets import SecretNames


# Every env var touched by LLM_PROVIDER_ENV_MAP plus any mirror targets.
_ALL_ENV_VARS = {
    env_var
    for env_vars in LLM_PROVIDER_ENV_MAP.values()
    for env_var in env_vars
}
# Control vars that influence load_secrets_to_env behavior.
_CONTROL_VARS = {
    "TAPROOT_SECRETS_ENABLED",
    "RETRIEVAL_SECRETS_ENABLED",
    "FRONTS_SECRETS_ENABLED",
    "TAPROOT_CLOUD_PROVIDER",
    "RETRIEVAL_CLOUD_PROVIDER",
    "FRONTS_CLOUD_PROVIDER",
}


@pytest.fixture(autouse=True)
def _clean_env() -> Iterator[None]:
    """Snapshot and restore env vars touched by these tests."""
    tracked = _ALL_ENV_VARS | _CONTROL_VARS
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


class TestLlmProviderEnvMap:
    """Coverage of the authoritative provider registry."""

    def test_contains_all_known_providers(self) -> None:
        expected = {
            SecretNames.OPENAI_API_KEY,
            SecretNames.ANTHROPIC_API_KEY,
            SecretNames.AZURE_OPENAI_API_KEY,
            SecretNames.COHERE_API_KEY,
            SecretNames.GOOGLE_API_KEY,
            SecretNames.GEMINI_API_KEY,
            SecretNames.MISTRAL_API_KEY,
            SecretNames.VOYAGE_API_KEY,
            SecretNames.HUGGINGFACE_API_KEY,
            SecretNames.VERTEX_API_KEY,
            SecretNames.VERTEX_PROJECT,
            SecretNames.BEDROCK_ACCESS_KEY_ID,
            SecretNames.BEDROCK_SECRET_ACCESS_KEY,
        }
        assert expected <= set(LLM_PROVIDER_ENV_MAP.keys())
        # Sanity: at least 13 providers registered.
        assert len(LLM_PROVIDER_ENV_MAP) >= 13

    def test_every_secret_has_at_least_one_env_var(self) -> None:
        for secret_name, env_vars in LLM_PROVIDER_ENV_MAP.items():
            assert env_vars, f"{secret_name} must map to at least one env var"
            for env_var in env_vars:
                assert isinstance(env_var, str) and env_var

    def test_azure_openai_mirrors_to_litellm_variant(self) -> None:
        env_vars = LLM_PROVIDER_ENV_MAP[SecretNames.AZURE_OPENAI_API_KEY]
        assert "AZURE_OPENAI_API_KEY" in env_vars
        assert "AZURE_API_KEY" in env_vars

    def test_huggingface_mirrors_to_hf_token(self) -> None:
        env_vars = LLM_PROVIDER_ENV_MAP[SecretNames.HUGGINGFACE_API_KEY]
        assert "HUGGINGFACE_API_KEY" in env_vars
        assert "HF_TOKEN" in env_vars


class TestLoadAllLlmKeys:
    """Coverage of the mirroring behavior in load_all_llm_keys()."""

    def test_mirrors_azure_openai_to_azure_api_key(self) -> None:
        # Simulate the primary env var being populated (e.g. by a previous
        # load_secrets_to_env call or an operator-provided override).
        os.environ["AZURE_OPENAI_API_KEY"] = "sk-azure-primary"

        load_all_llm_keys()

        assert os.environ["AZURE_OPENAI_API_KEY"] == "sk-azure-primary"
        assert os.environ["AZURE_API_KEY"] == "sk-azure-primary"

    def test_mirrors_huggingface_to_hf_token(self) -> None:
        os.environ["HUGGINGFACE_API_KEY"] = "hf-primary"

        load_all_llm_keys()

        assert os.environ["HUGGINGFACE_API_KEY"] == "hf-primary"
        assert os.environ["HF_TOKEN"] == "hf-primary"

    def test_does_not_overwrite_existing_mirror(self) -> None:
        os.environ["AZURE_OPENAI_API_KEY"] = "sk-azure-primary"
        os.environ["AZURE_API_KEY"] = "user-set-override"

        load_all_llm_keys()

        # Primary stays, mirror is NOT clobbered.
        assert os.environ["AZURE_OPENAI_API_KEY"] == "sk-azure-primary"
        assert os.environ["AZURE_API_KEY"] == "user-set-override"

    def test_skips_mirror_when_primary_missing(self) -> None:
        # Neither primary nor mirror should exist after the call.
        load_all_llm_keys()

        assert "AZURE_OPENAI_API_KEY" not in os.environ
        assert "AZURE_API_KEY" not in os.environ
        assert "HUGGINGFACE_API_KEY" not in os.environ
        assert "HF_TOKEN" not in os.environ

    def test_accepts_critical_list_argument(self) -> None:
        # Should accept a list without raising and with secrets disabled by
        # default, should not populate anything.
        load_all_llm_keys(critical=[SecretNames.OPENAI_API_KEY])

        assert "OPENAI_API_KEY" not in os.environ
