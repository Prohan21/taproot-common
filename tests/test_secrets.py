"""Tests for shared secret-loading helpers."""

import logging
import os
import sys
import types
from pathlib import Path

import pytest

from taproot_common import secrets as secret_helpers

from taproot_common.secrets import (
    CANONICAL_SECRET_DEFAULTS,
    RequiredSecretError,
    RuntimeSecretRequirement,
    RUNTIME_SECRET_REQUIREMENTS,
    SecretNames,
    build_runtime_secret_requirement,
    canonical_secret_name,
    canonical_service_secret_names,
    extract_secret_json_field,
    format_secret_log_context,
    get_runtime_secret_requirement,
    is_production_environment,
    load_required_secret,
    load_required_secret_json_field,
    load_required_runtime_secret,
    load_runtime_secret,
    load_runtime_secret_json_field,
    load_startup_secrets,
    load_service_database_url,
    load_secret_json_field,
    parse_service_database_secret_payload,
    resolve_service_database_secret_identifier,
    resolve_secret_identifier,
    secret_log_context,
)


def _registry_defaults() -> dict[str, str]:
    registry_path = None
    for parent in Path(__file__).resolve().parents:
        candidate = (
            parent
            / "taproot-infra"
            / "deploy"
            / "customer"
            / "docs"
            / "secrets"
            / "canonical-secret-registry.yaml"
        )
        if candidate.is_file():
            registry_path = candidate
            break
    if registry_path is None:
        pytest.skip("customer canonical-secret-registry.yaml is unavailable")

    defaults: dict[str, str] = {}
    current_logical_id: str | None = None
    for line in registry_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("- logical_id:"):
            current_logical_id = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("canonical_default_name:") and current_logical_id:
            defaults[current_logical_id] = stripped.split(":", 1)[1].strip()
            current_logical_id = None
    return defaults


def test_canonical_secret_defaults_include_runtime_contract_names():
    assert CANONICAL_SECRET_DEFAULTS["system-record-writer"] == (
        SecretNames.SYSTEM_RECORD_WRITER
    )
    assert CANONICAL_SECRET_DEFAULTS["internal-service-auth"] == (
        SecretNames.INTERNAL_SERVICE_AUTH
    )
    assert CANONICAL_SECRET_DEFAULTS["trusted-proxy"] == SecretNames.TRUSTED_PROXY


def test_canonical_secret_defaults_align_with_customer_registry():
    registry_defaults = _registry_defaults()
    common_runtime_logical_ids = {
        "system-record-writer",
        "internal-service-auth",
        "trusted-proxy-compatibility",
        "admin-api-key-material",
        "front-jwt-session-secret",
        "worker-session-token-secret",
        "service-database-credentials",
        "provider-openai-api-key",
        "provider-anthropic-api-key",
        "provider-azure-openai-api-key",
        "retrieval-integration-credentials",
        "evals-storage-credentials",
    }

    assert common_runtime_logical_ids <= set(registry_defaults)
    for logical_id in common_runtime_logical_ids:
        assert CANONICAL_SECRET_DEFAULTS[logical_id] == registry_defaults[logical_id]


def test_legacy_short_logical_keys_remain_aliases_to_registry_defaults():
    assert SecretNames.DB == "taproot-service-db"
    assert SecretNames.DB_LEGACY == "taproot-db"
    assert CANONICAL_SECRET_DEFAULTS["db"] == SecretNames.DB
    assert CANONICAL_SECRET_DEFAULTS["trusted-proxy"] == (
        CANONICAL_SECRET_DEFAULTS["trusted-proxy-compatibility"]
    )
    assert CANONICAL_SECRET_DEFAULTS["admin-api-key"] == (
        CANONICAL_SECRET_DEFAULTS["admin-api-key-material"]
    )
    assert CANONICAL_SECRET_DEFAULTS["front-jwt-secret"] == (
        CANONICAL_SECRET_DEFAULTS["front-jwt-session-secret"]
    )


def test_canonical_secret_name_builds_environment_scoped_names():
    assert canonical_secret_name("Prod", "front", "db") == "taproot-prod-front-db"
    assert canonical_secret_name("dev", "internal", "service_auth") == (
        "taproot-dev-internal-service-auth"
    )


def test_canonical_service_secret_names_returns_simple_matrix():
    names = canonical_service_secret_names("prod", "front")

    assert names["db"] == "taproot-prod-front-db"
    assert names["internal-service-auth"] == "taproot-prod-internal-service-auth"
    assert names["trusted-proxy"] == "taproot-prod-trusted-proxy"


def test_runtime_secret_requirements_cover_common_registry_defaults():
    assert set(RUNTIME_SECRET_REQUIREMENTS) >= {
        "system-record-writer",
        "internal-service-auth",
        "trusted-proxy-compatibility",
        "service-database-credentials",
        "provider-openai-api-key",
    }

    for logical_id, requirement in RUNTIME_SECRET_REQUIREMENTS.items():
        assert requirement.logical_id == logical_id
        assert requirement.default_name == CANONICAL_SECRET_DEFAULTS[logical_id]

    assert RUNTIME_SECRET_REQUIREMENTS["system-record-writer"].json_field == "url"
    assert RUNTIME_SECRET_REQUIREMENTS["service-database-credentials"].env_prefix == (
        "DATABASE"
    )
    assert RUNTIME_SECRET_REQUIREMENTS[
        "service-database-credentials"
    ].env_alias_prefixes == ("SERVICE_DATABASE",)
    assert not RUNTIME_SECRET_REQUIREMENTS["provider-openai-api-key"].required_in_production


def test_build_runtime_secret_requirement_uses_canonical_default():
    requirement = build_runtime_secret_requirement(
        "system-record-writer",
        env_prefix="CUSTOM_WRITER",
        json_field="url",
        required=True,
    )

    assert requirement == RuntimeSecretRequirement(
        logical_id="system-record-writer",
        default_name=SecretNames.SYSTEM_RECORD_WRITER,
        env_prefix="CUSTOM_WRITER",
        json_field="url",
        required=True,
    )


def test_get_runtime_secret_requirement_rejects_unknown_logical_id():
    with pytest.raises(KeyError):
        get_runtime_secret_requirement("unknown-secret")


def test_resolve_secret_identifier_prefers_aws_provider_specific_override(
    monkeypatch,
):
    monkeypatch.setenv(
        "SYSTEM_RECORD_WRITER_SECRET_ARN",
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:custom-writer",
    )
    monkeypatch.setenv("SYSTEM_RECORD_WRITER_SECRET_NAME", "custom-writer-name")

    assert resolve_secret_identifier(
        SecretNames.SYSTEM_RECORD_WRITER,
        env_prefix="SYSTEM_RECORD_WRITER",
        provider="aws",
    ) == "arn:aws:secretsmanager:us-east-1:123456789012:secret:custom-writer"


def test_resolve_secret_identifier_prefers_azure_provider_specific_override(
    monkeypatch,
):
    monkeypatch.setenv(
        "SYSTEM_RECORD_WRITER_SECRET_URI",
        "https://taproot.vault.azure.net/secrets/custom-writer/version-a",
    )
    monkeypatch.setenv("SYSTEM_RECORD_WRITER_SECRET_NAME", "custom-writer-name")

    assert resolve_secret_identifier(
        SecretNames.SYSTEM_RECORD_WRITER,
        env_prefix="SYSTEM_RECORD_WRITER",
        provider="azure",
    ) == "https://taproot.vault.azure.net/secrets/custom-writer/version-a"


def test_resolve_secret_identifier_prefers_gcp_provider_specific_override(
    monkeypatch,
):
    monkeypatch.setenv(
        "SYSTEM_RECORD_WRITER_SECRET_RESOURCE",
        "projects/taproot-prod/secrets/custom-writer/versions/latest",
    )
    monkeypatch.setenv("SYSTEM_RECORD_WRITER_SECRET_NAME", "custom-writer-name")

    assert resolve_secret_identifier(
        SecretNames.SYSTEM_RECORD_WRITER,
        env_prefix="SYSTEM_RECORD_WRITER",
        provider="gcp",
    ) == "projects/taproot-prod/secrets/custom-writer/versions/latest"


def test_resolve_secret_identifier_uses_name_override_before_default(monkeypatch):
    monkeypatch.setenv("SYSTEM_RECORD_WRITER_SECRET_NAME", "custom-writer-name")

    assert resolve_secret_identifier(
        SecretNames.SYSTEM_RECORD_WRITER,
        env_prefix="SYSTEM_RECORD_WRITER",
        provider="aws",
    ) == "custom-writer-name"


def test_resolve_secret_identifier_uses_canonical_default(monkeypatch):
    monkeypatch.delenv("SYSTEM_RECORD_WRITER_SECRET_ARN", raising=False)
    monkeypatch.delenv("SYSTEM_RECORD_WRITER_SECRET_NAME", raising=False)

    assert resolve_secret_identifier(
        SecretNames.SYSTEM_RECORD_WRITER,
        env_prefix="SYSTEM_RECORD_WRITER",
        provider="aws",
    ) == SecretNames.SYSTEM_RECORD_WRITER


def test_service_database_identifier_prefers_canonical_database_env(monkeypatch):
    monkeypatch.setenv(
        "DATABASE_SECRET_ARN",
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:canonical-db",
    )
    monkeypatch.setenv(
        "SERVICE_DATABASE_SECRET_ARN",
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:legacy-db",
    )
    monkeypatch.setenv("DATABASE_SECRET_NAME", "canonical-db-name")

    assert resolve_service_database_secret_identifier(provider="aws") == (
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:canonical-db"
    )


@pytest.mark.parametrize(
    ("canonical_env_var", "canonical_value"),
    (
        (
            "DATABASE_SECRET_ARN",
            "arn:aws:secretsmanager:us-east-1:123456789012:secret:canonical-db",
        ),
        (
            "DATABASE_SECRET_URI",
            "https://taproot.vault.azure.net/secrets/canonical-db/version-a",
        ),
        (
            "DATABASE_SECRET_RESOURCE",
            "projects/taproot-prod/secrets/canonical-db/versions/latest",
        ),
        ("DATABASE_SECRET_NAME", "canonical-db-name"),
    ),
)
def test_service_database_identifier_all_canonical_envs_beat_all_aliases(
    monkeypatch,
    canonical_env_var,
    canonical_value,
):
    monkeypatch.setenv(canonical_env_var, canonical_value)
    monkeypatch.setenv(
        "SERVICE_DATABASE_SECRET_ARN",
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:legacy-db",
    )
    monkeypatch.setenv(
        "SERVICE_DATABASE_SECRET_URI",
        "https://taproot.vault.azure.net/secrets/legacy-db/version-a",
    )
    monkeypatch.setenv(
        "SERVICE_DATABASE_SECRET_RESOURCE",
        "projects/taproot-prod/secrets/legacy-db/versions/latest",
    )
    monkeypatch.setenv("SERVICE_DATABASE_SECRET_NAME", "legacy-db-name")

    assert resolve_service_database_secret_identifier(provider="aws") == canonical_value


def test_service_database_identifier_preserves_service_database_alias(monkeypatch):
    monkeypatch.delenv("DATABASE_SECRET_ARN", raising=False)
    monkeypatch.delenv("DATABASE_SECRET_NAME", raising=False)
    monkeypatch.setenv("SERVICE_DATABASE_SECRET_NAME", "legacy-db-bundle")

    assert resolve_service_database_secret_identifier(provider="aws") == (
        "legacy-db-bundle"
    )


def test_load_required_secret_uses_resolved_identifier(monkeypatch):
    requested_identifiers: list[str] = []
    monkeypatch.setenv("SYSTEM_RECORD_WRITER_SECRET_NAME", "custom-writer-name")

    def load_secret(requested_name: str) -> str:
        requested_identifiers.append(requested_name)
        return "required-secret-value"

    monkeypatch.setattr(secret_helpers, "load_secret_from_aws", load_secret)

    assert load_required_secret(
        SecretNames.SYSTEM_RECORD_WRITER,
        env_prefix="SYSTEM_RECORD_WRITER",
        provider="aws",
    ) == "required-secret-value"
    assert requested_identifiers == ["custom-writer-name"]


def test_load_required_secret_raises_sanitized_error(monkeypatch):
    raw_payload = "super-secret-value-that-must-not-appear"
    monkeypatch.setenv("SYSTEM_RECORD_WRITER_SECRET_NAME", "custom-writer-name")
    monkeypatch.setattr(secret_helpers, "load_secret_from_aws", lambda _name: None)

    with pytest.raises(RequiredSecretError) as exc_info:
        load_required_secret(
            SecretNames.SYSTEM_RECORD_WRITER,
            env_prefix="SYSTEM_RECORD_WRITER",
            logical_name="system-record-writer",
            provider="aws",
        )

    error_text = str(exc_info.value)
    assert "system-record-writer" in error_text
    assert "custom-writer-name" in error_text
    assert raw_payload not in error_text


def test_runtime_environment_detects_production(monkeypatch):
    monkeypatch.delenv("TAPROOT_ENVIRONMENT", raising=False)
    monkeypatch.setenv("TAPROOT_ENV", "production")

    assert is_production_environment()


def test_secret_log_context_formats_identifier_only():
    raw_payload = "postgres://writer:raw-password@example.test/taproot"
    context = secret_log_context(
        logical_name="system-record-writer",
        provider="aws",
        identifier="custom-writer-name",
        field="url",
    )
    formatted = format_secret_log_context(**context)

    assert context == {
        "logical_name": "system-record-writer",
        "provider": "aws",
        "identifier": "custom-writer-name",
        "field": "url",
    }
    assert "system-record-writer" in formatted
    assert "custom-writer-name" in formatted
    assert raw_payload not in formatted


def test_secret_log_context_redacts_payload_shaped_identifiers():
    payload_identifiers = {
        "dsn": "postgres://writer:dsn-password@example.test/taproot",
        "url": "https://example.test/secrets/not-a-secret-manager-id?token=raw-token",
        "token": "sk-proj-rawtokenvaluethatmustnotappearinlogs",
        "connection_string": (
            "DefaultEndpointsProtocol=https;AccountName=taproot;"
            "AccountKey=raw-account-key-value;EndpointSuffix=core.windows.net"
        ),
        "long_value": "raw-secret-value-" + "a" * 120,
    }

    for category, raw_identifier in payload_identifiers.items():
        context = secret_log_context(
            logical_name="system-record-writer",
            provider="aws",
            identifier=raw_identifier,
            field="url",
        )
        formatted_from_context = format_secret_log_context(**context)
        formatted_direct = format_secret_log_context(
            logical_name="system-record-writer",
            provider="aws",
            identifier=raw_identifier,
            field="url",
        )

        assert context["identifier"].startswith(f"<redacted:{category}:")
        assert "sha256=" in context["identifier"]
        assert raw_identifier not in context["identifier"]
        assert raw_identifier not in formatted_from_context
        assert raw_identifier not in formatted_direct
        assert "system-record-writer" in formatted_direct
        assert "field='url'" in formatted_direct


def test_load_runtime_secret_error_redacts_misconfigured_dsn_identifier(monkeypatch):
    raw_identifier = "postgres://writer:dsn-password@example.test/taproot"
    monkeypatch.delenv("TAPROOT_ENVIRONMENT", raising=False)
    monkeypatch.setenv("TAPROOT_ENV", "production")
    monkeypatch.setenv("SYSTEM_RECORD_WRITER_SECRET_ARN", raw_identifier)
    monkeypatch.setattr(secret_helpers, "_load_secret_string_from_aws", lambda _name: None)

    with pytest.raises(RequiredSecretError) as exc_info:
        load_runtime_secret("system-record-writer", provider="aws")

    error_text = str(exc_info.value)
    assert "system-record-writer" in error_text
    assert "<redacted:dsn:" in error_text
    assert "sha256=" in error_text
    assert raw_identifier not in error_text
    assert "dsn-password" not in error_text
    assert "example.test" not in error_text


def test_load_runtime_secret_uses_provider_override_and_json_field(monkeypatch, caplog):
    writer_url = "postgres://writer:raw-password@example.test/taproot"
    requested_identifiers: list[str] = []
    monkeypatch.setenv("TAPROOT_CLOUD_PROVIDER", "azure")
    monkeypatch.setenv(
        "SYSTEM_RECORD_WRITER_SECRET_URI",
        "https://taproot.vault.azure.net/secrets/custom-writer/version-a",
    )

    def load_azure_secret(requested_name: str) -> str:
        requested_identifiers.append(requested_name)
        return f'{{"url":"{writer_url}"}}'

    monkeypatch.setattr(secret_helpers, "load_secret_from_azure", load_azure_secret)
    caplog.set_level(logging.WARNING, logger=secret_helpers.__name__)

    assert load_runtime_secret("system-record-writer") == writer_url
    assert requested_identifiers == [
        "https://taproot.vault.azure.net/secrets/custom-writer/version-a"
    ]
    assert writer_url not in caplog.text


def test_load_runtime_secret_uses_name_override_before_default(monkeypatch):
    requested_identifiers: list[str] = []
    monkeypatch.delenv("DATABASE_SECRET_ARN", raising=False)
    monkeypatch.delenv("DATABASE_SECRET_NAME", raising=False)
    monkeypatch.setenv("SERVICE_DATABASE_SECRET_NAME", "custom-db-bundle")

    def load_secret(requested_name: str) -> str:
        requested_identifiers.append(requested_name)
        return "database-secret"

    monkeypatch.setattr(secret_helpers, "load_secret_from_aws", load_secret)

    assert load_runtime_secret("service-database-credentials", provider="aws") == (
        "database-secret"
    )
    assert requested_identifiers == ["custom-db-bundle"]


def test_load_runtime_secret_uses_canonical_default(monkeypatch):
    requested_identifiers: list[str] = []
    monkeypatch.delenv("DATABASE_SECRET_ARN", raising=False)
    monkeypatch.delenv("DATABASE_SECRET_NAME", raising=False)
    monkeypatch.delenv("SERVICE_DATABASE_SECRET_ARN", raising=False)
    monkeypatch.delenv("SERVICE_DATABASE_SECRET_NAME", raising=False)

    def load_secret(requested_name: str) -> str:
        requested_identifiers.append(requested_name)
        return "database-secret"

    monkeypatch.setattr(secret_helpers, "load_secret_from_aws", load_secret)

    assert load_runtime_secret("service-database-credentials", provider="aws") == (
        "database-secret"
    )
    assert requested_identifiers == [SecretNames.DB]


def test_load_startup_secrets_reads_once_without_mutating_env(monkeypatch):
    requested_identifiers: list[str] = []
    raw_secret_name = "taproot-dev-front-db"

    def load_secret(requested_name: str) -> str:
        requested_identifiers.append(requested_name)
        return f"value-for-{requested_name}"

    monkeypatch.setattr(secret_helpers, "load_secret_from_aws", load_secret)
    before_env = dict(os.environ)

    bundle = load_startup_secrets(
        ["provider-openai-api-key", raw_secret_name],
        provider="aws",
        required=True,
    )

    assert bundle.provider == "aws"
    assert bundle.require("provider-openai-api-key") == (
        f"value-for-{SecretNames.OPENAI_API_KEY}"
    )
    assert bundle.require(raw_secret_name) == f"value-for-{raw_secret_name}"
    assert requested_identifiers == [SecretNames.OPENAI_API_KEY, raw_secret_name]
    assert dict(os.environ) == before_env


def test_load_runtime_secret_optional_provider_missing_does_not_raise_in_prod(
    monkeypatch,
):
    monkeypatch.delenv("TAPROOT_ENVIRONMENT", raising=False)
    monkeypatch.setenv("TAPROOT_ENV", "production")
    monkeypatch.setattr(secret_helpers, "load_secret_from_aws", lambda _name: None)

    assert load_runtime_secret("provider-openai-api-key", provider="aws") is None


def test_load_runtime_secret_production_required_failure_is_sanitized(monkeypatch):
    raw_payload = "super-secret-value-that-must-not-appear"
    monkeypatch.delenv("TAPROOT_ENVIRONMENT", raising=False)
    monkeypatch.setenv("TAPROOT_ENV", "production")
    monkeypatch.setenv(
        "SYSTEM_RECORD_WRITER_SECRET_RESOURCE",
        "projects/taproot-prod/secrets/custom-writer/versions/latest",
    )
    monkeypatch.setattr(secret_helpers, "load_secret_from_gcp", lambda _name: None)

    with pytest.raises(RequiredSecretError) as exc_info:
        load_runtime_secret("system-record-writer", provider="gcp")

    error_text = str(exc_info.value)
    assert "system-record-writer" in error_text
    assert "projects/taproot-prod/secrets/custom-writer/versions/latest" in error_text
    assert "url" in error_text
    assert raw_payload not in error_text


def test_load_required_runtime_secret_fails_closed_outside_production(monkeypatch):
    monkeypatch.delenv("TAPROOT_ENVIRONMENT", raising=False)
    monkeypatch.setenv("TAPROOT_ENV", "dev")
    monkeypatch.setattr(secret_helpers, "load_secret_from_aws", lambda _name: None)

    with pytest.raises(RequiredSecretError):
        load_required_runtime_secret("provider-openai-api-key", provider="aws")


def test_load_runtime_secret_json_field_overrides_requirement_field(monkeypatch):
    monkeypatch.setenv("TAPROOT_CLOUD_PROVIDER", "aws")
    monkeypatch.setattr(
        secret_helpers,
        "_load_secret_string_from_aws",
        lambda _name: '{"password":"db-password","url":"postgres://example"}',
    )

    assert load_runtime_secret_json_field(
        "service-database-credentials",
        "password",
    ) == "db-password"


def test_parse_service_database_secret_payload_accepts_url_shape():
    database_url = "postgresql://svc:raw-password@db.example.test:5432/taproot"

    assert parse_service_database_secret_payload(
        f'{{"url":"{database_url}"}}',
        secret_name="taproot-service-db",
    ) == database_url


def test_parse_service_database_secret_payload_accepts_component_shape():
    database_url = parse_service_database_secret_payload(
        {
            "host": "db.example.test",
            "port": 5432,
            "database": "taproot",
            "username": "svc-user",
            "password": "raw:p@ss/word",
            "sslmode": "require",
        },
        secret_name="taproot-service-db",
    )

    assert database_url == (
        "postgresql://svc-user:raw%3Ap%40ss%2Fword@"
        "db.example.test:5432/taproot?sslmode=require"
    )


def test_parse_service_database_secret_payload_accepts_alias_component_shape():
    database_url = parse_service_database_secret_payload(
        {
            "host": "db.example.test",
            "port": "5432",
            "dbname": "taproot_db",
            "user": "svc_user",
            "password": "raw-password",
            "ssl_mode": "verify-full",
        },
        secret_name="taproot-service-db",
    )

    assert database_url == (
        "postgresql://svc_user:raw-password@"
        "db.example.test:5432/taproot_db?sslmode=verify-full"
    )


def test_parse_service_database_secret_payload_rejects_missing_fields_safely():
    raw_password = "raw-password-that-must-not-appear"
    raw_payload = {
        "host": "db.example.test",
        "port": "5432",
        "username": "svc_user",
        "password": raw_password,
    }

    with pytest.raises(RequiredSecretError) as exc_info:
        parse_service_database_secret_payload(
            raw_payload,
            secret_name="taproot-service-db",
        )

    error_text = str(exc_info.value)
    assert "service-database-credentials" in error_text
    assert "database|dbname" in error_text
    assert "taproot-service-db" in error_text
    assert raw_password not in error_text
    assert str(raw_payload) not in error_text


def test_parse_service_database_secret_payload_rejects_malformed_json_safely():
    raw_payload = '{"url":"postgresql://svc:raw-password@db.example.test/taproot"'

    with pytest.raises(RequiredSecretError) as exc_info:
        parse_service_database_secret_payload(
            raw_payload,
            secret_name="taproot-service-db",
        )

    error_text = str(exc_info.value)
    assert "service-database-credentials" in error_text
    assert "not valid JSON" in error_text
    assert "raw-password" not in error_text
    assert raw_payload not in error_text


def test_parse_service_database_secret_payload_rejects_invalid_url_safely():
    raw_url = "postgresql://svc:raw-password@db.example.test:99999/taproot"

    with pytest.raises(RequiredSecretError) as exc_info:
        parse_service_database_secret_payload(
            {"url": raw_url},
            secret_name="taproot-service-db",
        )

    error_text = str(exc_info.value)
    assert "service-database-credentials" in error_text
    assert "url" in error_text
    assert raw_url not in error_text
    assert "raw-password" not in error_text


def test_load_service_database_url_uses_canonical_identifier(monkeypatch, caplog):
    requested_identifiers: list[str] = []
    database_url = "postgresql://svc:raw-password@db.example.test:5432/taproot"
    monkeypatch.setenv("TAPROOT_CLOUD_PROVIDER", "aws")
    monkeypatch.setenv("DATABASE_SECRET_ARN", "canonical-db-secret")
    monkeypatch.setenv("SERVICE_DATABASE_SECRET_ARN", "legacy-db-secret")

    def load_raw_secret(requested_name: str) -> str:
        requested_identifiers.append(requested_name)
        return f'{{"url":"{database_url}"}}'

    monkeypatch.setattr(
        secret_helpers,
        "_load_secret_string_from_aws",
        load_raw_secret,
    )
    caplog.set_level(logging.WARNING, logger=secret_helpers.__name__)

    assert load_service_database_url() == database_url
    assert requested_identifiers == ["canonical-db-secret"]
    assert database_url not in caplog.text
    assert "raw-password" not in caplog.text


def test_load_secret_json_field_extracts_aws_single_key_json(monkeypatch, caplog):
    secret_name = "taproot-dev-system-record-writer"
    writer_url = "postgres://writer:password@example.test/taproot"

    def load_raw_secret(requested_name: str) -> str:
        assert requested_name == secret_name
        return f'{{"url":"{writer_url}"}}'

    monkeypatch.setenv("TAPROOT_CLOUD_PROVIDER", "aws")
    monkeypatch.setattr(
        secret_helpers,
        "_load_secret_string_from_aws",
        load_raw_secret,
    )
    caplog.set_level(logging.WARNING, logger=secret_helpers.__name__)

    assert load_secret_json_field(secret_name, "url") == writer_url
    assert writer_url not in caplog.text


def test_load_secret_json_field_extracts_explicit_field_from_multi_key_json(
    monkeypatch,
    caplog,
):
    secret_name = "taproot-dev-system-record-writer"
    writer_url = "postgres://writer:password@example.test/taproot"

    def load_raw_secret(requested_name: str) -> str:
        assert requested_name == secret_name
        return (
            '{"username":"writer","password":"raw-password",'
            f'"url":"{writer_url}"}}'
        )

    monkeypatch.setenv("TAPROOT_CLOUD_PROVIDER", "aws")
    monkeypatch.setattr(
        secret_helpers,
        "_load_secret_string_from_aws",
        load_raw_secret,
    )
    caplog.set_level(logging.WARNING, logger=secret_helpers.__name__)

    assert load_secret_json_field(secret_name, "url") == writer_url
    assert writer_url not in caplog.text
    assert "raw-password" not in caplog.text


def test_load_secret_json_field_extracts_gcp_json(monkeypatch):
    secret_name = "taproot-dev-system-record-writer"

    def load_gcp_secret(requested_name: str) -> str:
        assert requested_name == secret_name
        return '{"url":"postgres://writer@example.test/taproot"}'

    monkeypatch.setenv("TAPROOT_CLOUD_PROVIDER", "gcp")
    monkeypatch.setattr(secret_helpers, "load_secret_from_gcp", load_gcp_secret)

    assert load_secret_json_field(secret_name, "url") == (
        "postgres://writer@example.test/taproot"
    )


def test_load_secret_from_azure_accepts_full_secret_uri(monkeypatch):
    calls: dict[str, object] = {}

    class FakeSecretClient:
        def __init__(self, *, vault_url: str, credential: object) -> None:
            calls["vault_url"] = vault_url
            calls["credential"] = credential

        def get_secret(self, name: str, version: str | None = None) -> object:
            calls["name"] = name
            calls["version"] = version
            return types.SimpleNamespace(value="azure-secret-value")

    class FakeDefaultAzureCredential:
        pass

    azure_module = types.ModuleType("azure")
    identity_module = types.ModuleType("azure.identity")
    keyvault_module = types.ModuleType("azure.keyvault")
    secrets_module = types.ModuleType("azure.keyvault.secrets")
    identity_module.DefaultAzureCredential = FakeDefaultAzureCredential
    secrets_module.SecretClient = FakeSecretClient
    azure_module.identity = identity_module
    azure_module.keyvault = keyvault_module
    keyvault_module.secrets = secrets_module
    monkeypatch.setitem(sys.modules, "azure", azure_module)
    monkeypatch.setitem(sys.modules, "azure.identity", identity_module)
    monkeypatch.setitem(sys.modules, "azure.keyvault", keyvault_module)
    monkeypatch.setitem(sys.modules, "azure.keyvault.secrets", secrets_module)

    secret_value = secret_helpers.load_secret_from_azure(
        "https://taproot.vault.azure.net/secrets/system-record-writer/version-a"
    )

    assert secret_value == "azure-secret-value"
    assert calls["vault_url"] == "https://taproot.vault.azure.net"
    assert calls["name"] == "system-record-writer"
    assert calls["version"] == "version-a"
    assert isinstance(calls["credential"], FakeDefaultAzureCredential)


def test_load_secret_from_gcp_accepts_full_resource_with_version(monkeypatch):
    requested_names: list[str] = []

    class FakeSecretManagerServiceClient:
        def access_secret_version(self, *, request: dict[str, str]) -> object:
            requested_names.append(request["name"])
            return types.SimpleNamespace(
                payload=types.SimpleNamespace(data=b"gcp-versioned-secret")
            )

    secretmanager_module = types.ModuleType("google.cloud.secretmanager")
    secretmanager_module.SecretManagerServiceClient = FakeSecretManagerServiceClient
    cloud_module = types.ModuleType("google.cloud")
    google_module = types.ModuleType("google")
    google_module.cloud = cloud_module
    cloud_module.secretmanager = secretmanager_module
    monkeypatch.setitem(sys.modules, "google", google_module)
    monkeypatch.setitem(sys.modules, "google.cloud", cloud_module)
    monkeypatch.setitem(sys.modules, "google.cloud.secretmanager", secretmanager_module)

    secret_value = secret_helpers.load_secret_from_gcp(
        "projects/taproot-prod/secrets/system-record-writer/versions/42"
    )

    assert secret_value == "gcp-versioned-secret"
    assert requested_names == [
        "projects/taproot-prod/secrets/system-record-writer/versions/42"
    ]


def test_load_secret_from_gcp_accepts_full_resource_without_version(monkeypatch):
    requested_names: list[str] = []

    class FakeSecretManagerServiceClient:
        def access_secret_version(self, *, request: dict[str, str]) -> object:
            requested_names.append(request["name"])
            return types.SimpleNamespace(
                payload=types.SimpleNamespace(data=b"gcp-latest-secret")
            )

    secretmanager_module = types.ModuleType("google.cloud.secretmanager")
    secretmanager_module.SecretManagerServiceClient = FakeSecretManagerServiceClient
    cloud_module = types.ModuleType("google.cloud")
    google_module = types.ModuleType("google")
    google_module.cloud = cloud_module
    cloud_module.secretmanager = secretmanager_module
    monkeypatch.setitem(sys.modules, "google", google_module)
    monkeypatch.setitem(sys.modules, "google.cloud", cloud_module)
    monkeypatch.setitem(sys.modules, "google.cloud.secretmanager", secretmanager_module)

    secret_value = secret_helpers.load_secret_from_gcp(
        "projects/taproot-prod/secrets/system-record-writer"
    )

    assert secret_value == "gcp-latest-secret"
    assert requested_names == [
        "projects/taproot-prod/secrets/system-record-writer/versions/latest"
    ]


def test_extract_secret_json_field_does_not_log_secret_value(caplog):
    secret_name = "taproot-dev-system-record-writer"
    writer_url = "postgres://writer:password@example.test/taproot"

    caplog.set_level(logging.WARNING, logger=secret_helpers.__name__)

    extracted = extract_secret_json_field(
        '{"url":"%s"}' % writer_url,
        "missing",
        secret_name=secret_name,
    )

    assert extracted is None
    assert secret_name in caplog.text
    assert "missing" in caplog.text
    assert writer_url not in caplog.text


def test_extract_secret_json_field_rejects_non_string_without_logging_value(caplog):
    secret_name = "taproot-dev-system-record-writer"

    caplog.set_level(logging.WARNING, logger=secret_helpers.__name__)

    extracted = extract_secret_json_field(
        '{"url":{"raw":"postgres://writer:password@example.test/taproot"}}',
        "url",
        secret_name=secret_name,
    )

    assert extracted is None
    assert secret_name in caplog.text
    assert "url" in caplog.text
    assert "postgres://writer:password@example.test/taproot" not in caplog.text


def test_load_required_secret_json_field_raises_sanitized_error(
    monkeypatch,
    caplog,
):
    secret_name = SecretNames.SYSTEM_RECORD_WRITER
    raw_payload = "postgres://writer:raw-password@example.test/taproot"

    def load_raw_secret(requested_name: str) -> str:
        assert requested_name == "custom-writer-name"
        return f'{{"url":"{raw_payload}"}}'

    monkeypatch.setenv("TAPROOT_CLOUD_PROVIDER", "aws")
    monkeypatch.setenv("SYSTEM_RECORD_WRITER_SECRET_NAME", "custom-writer-name")
    monkeypatch.setattr(
        secret_helpers,
        "_load_secret_string_from_aws",
        load_raw_secret,
    )
    caplog.set_level(logging.WARNING, logger=secret_helpers.__name__)

    with pytest.raises(RequiredSecretError) as exc_info:
        load_required_secret_json_field(
            secret_name,
            "missing",
            env_prefix="SYSTEM_RECORD_WRITER",
            logical_name="system-record-writer",
            provider="aws",
        )

    error_text = str(exc_info.value)
    assert "system-record-writer" in error_text
    assert "missing" in error_text
    assert "custom-writer-name" in error_text
    assert raw_payload not in error_text
    assert raw_payload not in caplog.text
