"""Multi-cloud secret manager integration for Taproot microservices.

Provides cloud-agnostic secret loading from AWS Secrets Manager, GCP Secret Manager,
and Azure Key Vault. Services import this module and call load_secrets_to_env() with
their own secret-to-env-var mappings at startup.

Usage (in a service's main.py or settings.py):
    from taproot_common.secrets import load_secrets_to_env

    # Service-specific mappings
    SECRETS = {
        SecretNames.OPENAI_API_KEY: "OPENAI_API_KEY",
        "taproot-myservice-db-password": "DATABASE_PASSWORD",
    }

    load_secrets_to_env(SECRETS)

Environment variables:
    - TAPROOT_SECRETS_ENABLED=true   (enable secret loading)
    - TAPROOT_CLOUD_PROVIDER=aws|gcp|azure|local
    - AWS_REGION or AWS_DEFAULT_REGION (for AWS)
    - GCP_PROJECT_ID or GOOGLE_CLOUD_PROJECT (for GCP)
    - AZURE_KEY_VAULT_URL (for Azure)
"""

import hashlib
import json
import logging
import os
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from typing import Any, Optional
from urllib.parse import quote, urlparse

logger = logging.getLogger(__name__)


# =============================================================================
# Standard Secret Names (taproot-* naming convention)
# =============================================================================


class SecretNames:
    """Standard secret names shared across Taproot services.

    Services should reference these constants instead of hardcoding names.
    All secrets follow the pattern: taproot-{scope}-{credential}

    Shared secrets (used by all services):
        taproot-db-password              — legacy Aurora master password
        taproot-service-db               — canonical service DB credential bundle
        taproot-openai-api-key
        taproot-anthropic-api-key
        taproot-azure-openai-api-key
        taproot-cohere-api-key
        taproot-google-api-key

    Service-specific secrets follow: taproot-{service}-{credential}
    """

    # Shared Aurora database password (legacy value-oriented secret name).
    DB_PASSWORD = "taproot-db-password"

    # Canonical runtime secret contracts shared by services and deployment tooling.
    # These names identify cloud secret objects, never raw secret payloads.
    SYSTEM_RECORD_WRITER = "taproot-system-record-writer"
    INTERNAL_SERVICE_AUTH = "taproot-internal-service-auth"
    TRUSTED_PROXY = "taproot-trusted-proxy"
    DB = "taproot-service-db"
    DB_LEGACY = "taproot-db"
    ADMIN_API_KEY = "taproot-admin-api-key"
    FRONT_JWT_SECRET = "taproot-front-jwt-secret"
    WORKER_SESSION_TOKEN_SECRET = "taproot-worker-session-token-secret"
    RETRIEVAL_INTEGRATION_CREDENTIALS = "taproot-retrieval-integration-credentials"
    EVALS_STORAGE_CREDENTIALS = "taproot-evals-storage-credentials"

    # LLM provider keys (shared across services)
    OPENAI_API_KEY = "taproot-openai-api-key"
    ANTHROPIC_API_KEY = "taproot-anthropic-api-key"
    AZURE_OPENAI_API_KEY = "taproot-azure-openai-api-key"
    COHERE_API_KEY = "taproot-cohere-api-key"
    GOOGLE_API_KEY = "taproot-google-api-key"
    VERTEX_API_KEY = "taproot-vertex-api-key"
    VERTEX_PROJECT = "taproot-vertex-project"
    BEDROCK_ACCESS_KEY_ID = "taproot-bedrock-access-key-id"
    BEDROCK_SECRET_ACCESS_KEY = "taproot-bedrock-secret-access-key"
    MISTRAL_API_KEY = "taproot-mistral-api-key"
    GEMINI_API_KEY = "taproot-gemini-api-key"
    VOYAGE_API_KEY = "taproot-voyage-api-key"
    HUGGINGFACE_API_KEY = "taproot-huggingface-api-key"

    # AWS credentials (shared)
    AWS_ACCESS_KEY_ID = "taproot-aws-access-key-id"
    AWS_SECRET_ACCESS_KEY = "taproot-aws-secret-access-key"

    # Retrieval-S specific
    RETRIEVAL_API_KEY = "taproot-retrieval-api-key"
    RETRIEVAL_AZURE_BLOB_KEY = "taproot-retrieval-azure-blob-key"
    RETRIEVAL_SERVICE_BUS_CONN = "taproot-retrieval-service-bus-conn"
    RETRIEVAL_SHAREPOINT_SECRET = "taproot-retrieval-sharepoint-secret"

    # Front-S auth provider secrets
    FRONTS_AZURE_CLIENT_SECRET = "taproot-fronts-azure-client-secret"
    FRONTS_OKTA_CLIENT_SECRET = "taproot-fronts-okta-client-secret"


CANONICAL_SECRET_DEFAULTS: dict[str, str] = {
    # Canonical logical IDs from the customer deployment secret registry.
    "system-record-writer": SecretNames.SYSTEM_RECORD_WRITER,
    "internal-service-auth": SecretNames.INTERNAL_SERVICE_AUTH,
    "trusted-proxy-compatibility": SecretNames.TRUSTED_PROXY,
    "admin-api-key-material": SecretNames.ADMIN_API_KEY,
    "front-jwt-session-secret": SecretNames.FRONT_JWT_SECRET,
    "worker-session-token-secret": SecretNames.WORKER_SESSION_TOKEN_SECRET,
    "service-database-credentials": SecretNames.DB,
    "provider-openai-api-key": SecretNames.OPENAI_API_KEY,
    "provider-anthropic-api-key": SecretNames.ANTHROPIC_API_KEY,
    "provider-azure-openai-api-key": SecretNames.AZURE_OPENAI_API_KEY,
    "retrieval-integration-credentials": SecretNames.RETRIEVAL_INTEGRATION_CREDENTIALS,
    "evals-storage-credentials": SecretNames.EVALS_STORAGE_CREDENTIALS,
    # Backward-compatible aliases retained for early adopters of Wave 2 helpers.
    "trusted-proxy": SecretNames.TRUSTED_PROXY,
    "db": SecretNames.DB,
    "admin-api-key": SecretNames.ADMIN_API_KEY,
    "front-jwt-secret": SecretNames.FRONT_JWT_SECRET,
    "openai-api-key": SecretNames.OPENAI_API_KEY,
    "anthropic-api-key": SecretNames.ANTHROPIC_API_KEY,
    "azure-openai-api-key": SecretNames.AZURE_OPENAI_API_KEY,
    "cohere-api-key": SecretNames.COHERE_API_KEY,
    "google-api-key": SecretNames.GOOGLE_API_KEY,
    "gemini-api-key": SecretNames.GEMINI_API_KEY,
    "mistral-api-key": SecretNames.MISTRAL_API_KEY,
    "voyage-api-key": SecretNames.VOYAGE_API_KEY,
    "huggingface-api-key": SecretNames.HUGGINGFACE_API_KEY,
}

PROVIDER_SECRET_IDENTIFIER_ENV_SUFFIXES: dict[str, str] = {
    "aws": "SECRET_ARN",
    "azure": "SECRET_URI",
    "gcp": "SECRET_RESOURCE",
}

RUNTIME_ENVIRONMENT_ENV_VARS: tuple[str, ...] = (
    "TAPROOT_ENVIRONMENT",
    "TAPROOT_ENV",
    "DEPLOY_ENV",
    "ENVIRONMENT",
    "APP_ENV",
)

PRODUCTION_ENVIRONMENT_VALUES = frozenset({"prod", "production"})

_REDACTED_IDENTIFIER_PREFIX = "<redacted:"
_MAX_SAFE_IDENTIFIER_LENGTH = 96
_SAFE_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@+=-]{0,95}$")
_TOKENISH_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9_+./=-]+$")
_JWT_SEGMENT_PATTERN = re.compile(r"^[A-Za-z0-9_-]{8,}={0,2}$")
_SECRETISH_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|"
    r"account[_-]?key|sharedaccesssignature|client[_-]?secret)\s*=",
)
_SECRETISH_CONNECTION_KEYS = frozenset(
    {
        "accountkey",
        "accesskey",
        "apikey",
        "api_key",
        "clientsecret",
        "client_secret",
        "password",
        "passwd",
        "pwd",
        "secret",
        "sharedaccesskey",
        "sharedaccesssignature",
        "sig",
        "token",
    }
)
_SECRETISH_TOKEN_PREFIXES = (
    "sk-",
    "xoxb-",
    "xoxp-",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "github_pat_",
    "glpat-",
    "AIza",
)
_DSN_SCHEMES = frozenset(
    {
        "amqp",
        "amqps",
        "kafka",
        "mongodb",
        "mongodb+srv",
        "mssql",
        "mysql",
        "postgres",
        "postgresql",
        "redis",
        "rediss",
        "sqlserver",
    }
)
SERVICE_DATABASE_LOGICAL_ID = "service-database-credentials"
SERVICE_DATABASE_ENV_PREFIX = "DATABASE"
SERVICE_DATABASE_COMPATIBILITY_ENV_PREFIXES = ("SERVICE_DATABASE",)
_SERVICE_DATABASE_URL_SCHEMES = frozenset({"postgres", "postgresql"})


CANONICAL_SERVICE_SECRET_PURPOSES: Mapping[str, Mapping[str, tuple[str, str]]] = {
    "front": {
        "db": ("front", "db"),
        "jwt-secret": ("front", "jwt-secret"),
        "internal-service-auth": ("internal", "service-auth"),
        "admin-api-key": ("admin", "api-key"),
        "worker-entitlement-manifest": ("worker", "entitlement-manifest"),
        "trusted-proxy": ("trusted", "proxy"),
    },
    "prompt": {
        "db": ("prompt", "db"),
        "system-record-writer": ("system", "record-writer"),
        "internal-service-auth": ("internal", "service-auth"),
        "trusted-proxy": ("trusted", "proxy"),
        "openai-api-key": ("openai", "api-key"),
    },
    "evals": {
        "db": ("evals", "db"),
        "secret-key": ("evals", "secret-key"),
        "system-record-writer": ("system", "record-writer"),
        "internal-service-auth": ("internal", "service-auth"),
        "trusted-proxy": ("trusted", "proxy"),
        "taproot-api-key": ("taproot", "api-key"),
        "openai-api-key": ("openai", "api-key"),
    },
    "retrieval": {
        "db": ("retrieval", "db"),
        "api-key": ("retrieval", "api-key"),
        "openai-api-key": ("openai", "api-key"),
        "integrations": ("retrieval", "integrations"),
    },
    "toolbox": {
        "db": ("toolbox", "db"),
        "secret-key": ("toolbox", "secret-key"),
        "system-record-writer": ("system", "record-writer"),
        "internal-service-auth": ("internal", "service-auth"),
    },
    "worker": {
        "db": ("worker", "db"),
        "system-record-writer": ("system", "record-writer"),
        "internal-service-auth": ("internal", "service-auth"),
        "entitlement-manifest": ("worker", "entitlement-manifest"),
        "session-token": ("worker", "session-token"),
        "openai-api-key": ("openai", "api-key"),
    },
    "guardrail": {
        "db": ("guardrail", "db"),
        "system-record-writer": ("system", "record-writer"),
        "internal-service-auth": ("internal", "service-auth"),
        "webhook-secret": ("guardrail", "webhook-secret"),
        "openai-api-key": ("openai", "api-key"),
    },
}


_CANONICAL_SECRET_PART_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def _canonical_secret_part(value: str, field_name: str) -> str:
    part = re.sub(r"-+", "-", value.strip().lower().replace("_", "-"))
    if not _CANONICAL_SECRET_PART_PATTERN.fullmatch(part):
        raise ValueError(f"Invalid canonical secret {field_name}: {value!r}")
    return part


def canonical_secret_name(environment: str, service_or_shared: str, purpose: str) -> str:
    """Return ``taproot-<env>-<service-or-shared>-<purpose>``."""

    return "taproot-{}-{}-{}".format(
        _canonical_secret_part(environment, "environment"),
        _canonical_secret_part(service_or_shared, "service_or_shared"),
        _canonical_secret_part(purpose, "purpose"),
    )


def canonical_service_secret_names(environment: str, service: str) -> dict[str, str]:
    """Return the simple service secret-name matrix for ``service``."""

    service_key = _canonical_secret_part(service, "service")
    try:
        purposes = CANONICAL_SERVICE_SECRET_PURPOSES[service_key]
    except KeyError as exc:
        raise KeyError(f"Unknown Taproot service secret matrix: {service}") from exc
    return {
        logical_name: canonical_secret_name(environment, scope, purpose)
        for logical_name, (scope, purpose) in purposes.items()
    }


class RequiredSecretError(RuntimeError):
    """Raised when a required secret or required JSON field is unavailable.

    Error messages intentionally include only logical names, sanitized identifiers,
    provider names, and field names. They must never include secret payload contents.
    """


@dataclass(frozen=True)
class RuntimeSecretRequirement:
    """Declarative runtime contract for a Taproot secret.

    The requirement describes the secret object identifier contract only. It is
    safe to use in logs, tests, deployment docs, and service startup code because
    it never stores or returns secret payload values.
    """

    logical_id: str
    default_name: str
    env_prefix: str | None = None
    json_field: str | None = None
    required: bool = False
    required_in_production: bool = True
    provider_env_vars: Mapping[str, str] | None = None
    name_env_var: str | None = None
    env_alias_prefixes: tuple[str, ...] = ()

    def with_overrides(self, **changes: Any) -> "RuntimeSecretRequirement":
        """Return a copy with service-local policy or env-var overrides."""

        return replace(self, **changes)


@dataclass(frozen=True)
class ResolvedRuntimeSecrets:
    """In-memory startup secret bundle; values are never written to env."""

    values: Mapping[str, str]
    provider: str

    def get(self, logical_name: str, default: str | None = None) -> str | None:
        return self.values.get(logical_name, default)

    def require(self, logical_name: str) -> str:
        try:
            return self.values[logical_name]
        except KeyError as exc:
            raise RequiredSecretError(
                f"Startup secret was not loaded: {logical_name}"
            ) from exc


RUNTIME_SECRET_REQUIREMENTS: dict[str, RuntimeSecretRequirement] = {
    "system-record-writer": RuntimeSecretRequirement(
        logical_id="system-record-writer",
        default_name=SecretNames.SYSTEM_RECORD_WRITER,
        env_prefix="SYSTEM_RECORD_WRITER",
        json_field="url",
    ),
    "internal-service-auth": RuntimeSecretRequirement(
        logical_id="internal-service-auth",
        default_name=SecretNames.INTERNAL_SERVICE_AUTH,
        env_prefix="INTERNAL_SERVICE_AUTH",
    ),
    "trusted-proxy-compatibility": RuntimeSecretRequirement(
        logical_id="trusted-proxy-compatibility",
        default_name=SecretNames.TRUSTED_PROXY,
        env_prefix="TRUSTED_PROXY",
        required_in_production=False,
    ),
    "admin-api-key-material": RuntimeSecretRequirement(
        logical_id="admin-api-key-material",
        default_name=SecretNames.ADMIN_API_KEY,
        env_prefix="ADMIN_API_KEY",
    ),
    "front-jwt-session-secret": RuntimeSecretRequirement(
        logical_id="front-jwt-session-secret",
        default_name=SecretNames.FRONT_JWT_SECRET,
        env_prefix="FRONT_JWT_SECRET",
    ),
    "worker-session-token-secret": RuntimeSecretRequirement(
        logical_id="worker-session-token-secret",
        default_name=SecretNames.WORKER_SESSION_TOKEN_SECRET,
        env_prefix="WORKER_SESSION_TOKEN_SECRET",
    ),
    SERVICE_DATABASE_LOGICAL_ID: RuntimeSecretRequirement(
        logical_id=SERVICE_DATABASE_LOGICAL_ID,
        default_name=SecretNames.DB,
        env_prefix=SERVICE_DATABASE_ENV_PREFIX,
        env_alias_prefixes=SERVICE_DATABASE_COMPATIBILITY_ENV_PREFIXES,
    ),
    "provider-openai-api-key": RuntimeSecretRequirement(
        logical_id="provider-openai-api-key",
        default_name=SecretNames.OPENAI_API_KEY,
        env_prefix="OPENAI_API_KEY",
        required_in_production=False,
    ),
    "provider-anthropic-api-key": RuntimeSecretRequirement(
        logical_id="provider-anthropic-api-key",
        default_name=SecretNames.ANTHROPIC_API_KEY,
        env_prefix="ANTHROPIC_API_KEY",
        required_in_production=False,
    ),
    "provider-azure-openai-api-key": RuntimeSecretRequirement(
        logical_id="provider-azure-openai-api-key",
        default_name=SecretNames.AZURE_OPENAI_API_KEY,
        env_prefix="AZURE_OPENAI_API_KEY",
        required_in_production=False,
    ),
    "retrieval-integration-credentials": RuntimeSecretRequirement(
        logical_id="retrieval-integration-credentials",
        default_name=SecretNames.RETRIEVAL_INTEGRATION_CREDENTIALS,
        env_prefix="RETRIEVAL_INTEGRATION_CREDENTIALS",
        required_in_production=False,
    ),
    "evals-storage-credentials": RuntimeSecretRequirement(
        logical_id="evals-storage-credentials",
        default_name=SecretNames.EVALS_STORAGE_CREDENTIALS,
        env_prefix="EVALS_STORAGE_CREDENTIALS",
        required_in_production=False,
    ),
}


def _non_empty_env(name: str) -> str | None:
    value = os.environ.get(name)
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _provider_specific_env_var(env_prefix: str, provider: str) -> str | None:
    suffix = PROVIDER_SECRET_IDENTIFIER_ENV_SUFFIXES.get(provider.lower())
    if suffix is None:
        return None
    return f"{env_prefix}_{suffix}"


def _env_prefix_candidates(
    env_prefix: str | None,
    env_alias_prefixes: tuple[str, ...] | None = None,
) -> tuple[str, ...]:
    prefixes: list[str] = []
    if env_prefix:
        prefixes.append(env_prefix)
    for alias_prefix in env_alias_prefixes or ():
        if alias_prefix and alias_prefix not in prefixes:
            prefixes.append(alias_prefix)
    return tuple(prefixes)


def get_runtime_environment() -> str:
    """Return the normalized deployment environment name, if configured."""

    for env_var in RUNTIME_ENVIRONMENT_ENV_VARS:
        value = _non_empty_env(env_var)
        if value:
            return value.lower()
    return ""


def is_production_environment() -> bool:
    """Return whether runtime policy should use production fail-closed defaults."""

    return get_runtime_environment() in PRODUCTION_ENVIRONMENT_VALUES


def get_runtime_secret_requirement(logical_id: str) -> RuntimeSecretRequirement:
    """Return the canonical runtime requirement for a logical secret ID."""

    try:
        return RUNTIME_SECRET_REQUIREMENTS[logical_id]
    except KeyError as exc:
        raise KeyError(f"Unknown Taproot runtime secret logical ID: {logical_id}") from exc


def build_runtime_secret_requirement(
    logical_id: str,
    *,
    env_prefix: str | None = None,
    json_field: str | None = None,
    required: bool = False,
    required_in_production: bool = True,
    default_name: str | None = None,
    provider_env_vars: Mapping[str, str] | None = None,
    name_env_var: str | None = None,
    env_alias_prefixes: tuple[str, ...] = (),
) -> RuntimeSecretRequirement:
    """Build a requirement from the shared canonical default registry.

    Services should prefer ``get_runtime_secret_requirement`` for common
    Taproot secrets and use this helper for service-specific runtime secrets
    that still follow the canonical-default/override resolution contract.
    """

    resolved_default = default_name or CANONICAL_SECRET_DEFAULTS[logical_id]
    return RuntimeSecretRequirement(
        logical_id=logical_id,
        default_name=resolved_default,
        env_prefix=env_prefix,
        json_field=json_field,
        required=required,
        required_in_production=required_in_production,
        provider_env_vars=provider_env_vars,
        name_env_var=name_env_var,
        env_alias_prefixes=env_alias_prefixes,
    )


def _identifier_digest(identifier: str) -> str:
    return hashlib.sha256(identifier.encode("utf-8")).hexdigest()[:12]


def _looks_like_connection_string(identifier: str) -> bool:
    if ";" not in identifier or "=" not in identifier:
        return False

    for part in identifier.split(";"):
        key, separator, _value = part.partition("=")
        normalized_key = key.strip().lower().replace(" ", "")
        if separator and normalized_key in _SECRETISH_CONNECTION_KEYS:
            return True
    return False


def _looks_like_jwt(identifier: str) -> bool:
    parts = identifier.split(".")
    return len(parts) == 3 and all(_JWT_SEGMENT_PATTERN.fullmatch(part) for part in parts)


def _secret_identifier_category(identifier: str) -> str:
    stripped = identifier.strip()
    if not stripped:
        return "empty"
    if stripped.startswith(_REDACTED_IDENTIFIER_PREFIX) and stripped.endswith(">"):
        return "already_redacted"
    if any(character in stripped for character in ("\n", "\r", "\t")):
        return "opaque_value"
    if _looks_like_connection_string(stripped):
        return "connection_string"

    parsed = urlparse(stripped)
    scheme = parsed.scheme.lower()
    if scheme in _DSN_SCHEMES:
        return "dsn"
    if scheme in {"http", "https"} or "://" in stripped:
        return "url"
    if parsed.username or parsed.password:
        return "url_with_credentials"
    if "@" in stripped and ":" in stripped.split("@", 1)[0]:
        return "credential_pair"

    lowered = stripped.lower()
    if _SECRETISH_ASSIGNMENT_PATTERN.search(stripped):
        return "secret_assignment"
    if any(stripped.startswith(prefix) for prefix in _SECRETISH_TOKEN_PREFIXES):
        return "token"
    if any(lowered.startswith(prefix.lower()) for prefix in _SECRETISH_TOKEN_PREFIXES):
        return "token"
    if _looks_like_jwt(stripped):
        return "token"
    if len(stripped) > _MAX_SAFE_IDENTIFIER_LENGTH:
        return "long_value"
    if len(stripped) >= 64 and _TOKENISH_IDENTIFIER_PATTERN.fullmatch(stripped):
        return "long_tokenish_value"
    if _SAFE_IDENTIFIER_PATTERN.fullmatch(stripped):
        return "safe_identifier"
    return "opaque_value"


def _sanitize_secret_identifier(identifier: str) -> str:
    category = _secret_identifier_category(identifier)
    stripped = identifier.strip()
    if category in {"safe_identifier", "already_redacted"}:
        return stripped
    return (
        f"{_REDACTED_IDENTIFIER_PREFIX}{category}:"
        f"sha256={_identifier_digest(identifier)}:length={len(identifier)}>"
    )


def secret_log_context(
    *,
    logical_name: str | None = None,
    provider: str | None = None,
    identifier: str | None = None,
    field: str | None = None,
    env_prefix: str | None = None,
    name_env_var: str | None = None,
) -> dict[str, str]:
    """Return structured, no-value context for secret logs/errors."""

    context = {
        "logical_name": logical_name,
        "provider": provider,
        "identifier": _sanitize_secret_identifier(identifier) if identifier else None,
        "field": field,
        "env_prefix": env_prefix,
        "name_env_var": name_env_var,
    }
    return {key: value for key, value in context.items() if value}


def format_secret_log_context(**context: str | None) -> str:
    """Format secret log context without accepting or exposing payload values."""

    sanitized = secret_log_context(**context)
    return ", ".join(f"{key}={value!r}" for key, value in sanitized.items())


def _required_secret_error(message: str, **context: str | None) -> RequiredSecretError:
    formatted_context = format_secret_log_context(**context)
    if formatted_context:
        return RequiredSecretError(f"{message} ({formatted_context})")
    return RequiredSecretError(message)


def _is_runtime_secret_required(
    requirement: RuntimeSecretRequirement,
    *,
    required: bool | None = None,
) -> bool:
    if required is not None:
        return required
    if requirement.required:
        return True
    return requirement.required_in_production and is_production_environment()


def resolve_secret_identifier(
    default_name: str,
    *,
    env_prefix: str | None = None,
    env_alias_prefixes: tuple[str, ...] | None = None,
    provider: str | None = None,
    provider_env_vars: Mapping[str, str] | None = None,
    name_env_var: str | None = None,
) -> str:
    """Resolve the cloud secret identifier for a logical Taproot secret.

    Resolution order is intentionally fail-safe and deterministic:

    1. canonical prefix provider-specific overrides, preferring the active
       provider, for example ``SYSTEM_RECORD_WRITER_SECRET_ARN`` on AWS;
    2. canonical provider-neutral name override, for example
       ``SYSTEM_RECORD_WRITER_SECRET_NAME``;
    3. compatibility alias overrides, when configured; and
    4. shared canonical default, for example ``taproot-system-record-writer``.

    ``env_alias_prefixes`` can be used to preserve older environment contracts
    after a canonical prefix is introduced. Canonical variables are always
    checked before aliases.

    The returned value is a secret object identifier only. This helper never reads
    or returns secret payloads.
    """

    selected_provider = (provider or get_cloud_provider()).lower()
    prefix_candidates = _env_prefix_candidates(env_prefix, env_alias_prefixes)

    if provider_env_vars or name_env_var:
        provider_override_var = (
            provider_env_vars.get(selected_provider) if provider_env_vars else None
        )
        if provider_override_var:
            provider_override = _non_empty_env(provider_override_var)
            if provider_override:
                return provider_override

        neutral_name_vars = (
            [name_env_var]
            if name_env_var
            else [f"{prefix}_SECRET_NAME" for prefix in prefix_candidates]
        )
        for neutral_name_var in neutral_name_vars:
            neutral_name = _non_empty_env(neutral_name_var)
            if neutral_name:
                return neutral_name

        return default_name

    include_all_provider_suffixes = bool(env_alias_prefixes)
    for prefix in prefix_candidates:
        env_vars: list[str] = []
        provider_var = _provider_specific_env_var(prefix, selected_provider)
        if provider_var:
            env_vars.append(provider_var)
        if include_all_provider_suffixes:
            for suffix in PROVIDER_SECRET_IDENTIFIER_ENV_SUFFIXES.values():
                env_var = f"{prefix}_{suffix}"
                if env_var not in env_vars:
                    env_vars.append(env_var)
        env_vars.append(f"{prefix}_SECRET_NAME")

        for env_var in env_vars:
            override = _non_empty_env(env_var)
            if override:
                return override

    return default_name


def resolve_service_database_secret_identifier(*, provider: str | None = None) -> str:
    """Resolve the service DB credential bundle identifier.

    The canonical runtime contract is ``DATABASE_SECRET_ARN`` on AWS,
    ``DATABASE_SECRET_URI`` on Azure, ``DATABASE_SECRET_RESOURCE`` on GCP, and
    ``DATABASE_SECRET_NAME`` as the provider-neutral fallback. The historical
    ``SERVICE_DATABASE_*`` names remain compatibility aliases and are checked
    only after canonical variables.
    """

    requirement = get_runtime_secret_requirement(SERVICE_DATABASE_LOGICAL_ID)
    return resolve_secret_identifier(
        requirement.default_name,
        env_prefix=requirement.env_prefix,
        env_alias_prefixes=requirement.env_alias_prefixes,
        provider=provider,
        provider_env_vars=requirement.provider_env_vars,
        name_env_var=requirement.name_env_var,
    )


def _service_database_payload_error(
    message: str,
    *,
    secret_name: str | None = None,
    field: str | None = None,
) -> RequiredSecretError:
    return _required_secret_error(
        message,
        logical_name=SERVICE_DATABASE_LOGICAL_ID,
        identifier=secret_name,
        field=field,
    )


def _payload_field_label(field_names: tuple[str, ...]) -> str:
    return "|".join(field_names)


def _payload_text_field(
    payload: Mapping[str, Any],
    field_names: tuple[str, ...],
    *,
    secret_name: str | None,
) -> str:
    for field_name in field_names:
        if field_name not in payload:
            continue
        value = payload[field_name]
        if isinstance(value, str) and value.strip():
            return value.strip()

    field_label = _payload_field_label(field_names)
    raise _service_database_payload_error(
        "Service database secret payload is missing a required field",
        secret_name=secret_name,
        field=field_label,
    )


def _payload_optional_text_field(
    payload: Mapping[str, Any],
    field_names: tuple[str, ...],
    *,
    secret_name: str | None,
) -> str | None:
    for field_name in field_names:
        if field_name not in payload:
            continue
        value = payload[field_name]
        if value is None:
            continue
        if not isinstance(value, str):
            raise _service_database_payload_error(
                "Service database secret payload field must be a string",
                secret_name=secret_name,
                field=_payload_field_label(field_names),
            )
        stripped = value.strip()
        if stripped:
            return stripped
    return None


def _payload_port_field(
    payload: Mapping[str, Any],
    *,
    secret_name: str | None,
) -> int:
    if "port" not in payload:
        raise _service_database_payload_error(
            "Service database secret payload is missing a required field",
            secret_name=secret_name,
            field="port",
        )

    value = payload["port"]
    if isinstance(value, bool):
        raise _service_database_payload_error(
            "Service database secret payload port must be an integer",
            secret_name=secret_name,
            field="port",
        )
    if isinstance(value, int):
        port = value
    elif isinstance(value, str) and value.strip().isdigit():
        port = int(value.strip())
    else:
        raise _service_database_payload_error(
            "Service database secret payload port must be an integer",
            secret_name=secret_name,
            field="port",
        )

    if not 1 <= port <= 65535:
        raise _service_database_payload_error(
            "Service database secret payload port is out of range",
            secret_name=secret_name,
            field="port",
        )
    return port


def _validate_service_database_url(
    url: Any,
    *,
    secret_name: str | None,
) -> str:
    if not isinstance(url, str) or not url.strip():
        raise _service_database_payload_error(
            "Service database secret payload field must be a non-empty URL",
            secret_name=secret_name,
            field="url",
        )

    stripped = url.strip()
    try:
        parsed = urlparse(stripped)
        # Accessing ``port`` deliberately validates URL ports without including
        # the URL in any exception or log output.
        _ = parsed.port
    except ValueError as exc:
        raise _service_database_payload_error(
            "Service database secret payload field must be a valid URL",
            secret_name=secret_name,
            field="url",
        ) from exc

    if (
        parsed.scheme.lower() not in _SERVICE_DATABASE_URL_SCHEMES
        or not parsed.hostname
        or parsed.path in {"", "/"}
    ):
        raise _service_database_payload_error(
            "Service database secret payload field must be a PostgreSQL URL",
            secret_name=secret_name,
            field="url",
        )
    return stripped


def _validate_service_database_host(host: str, *, secret_name: str | None) -> None:
    if any(character.isspace() for character in host) or any(
        character in host for character in ("/", "@")
    ):
        raise _service_database_payload_error(
            "Service database secret payload host is invalid",
            secret_name=secret_name,
            field="host",
        )


def _host_for_url(host: str) -> str:
    if ":" in host and not (host.startswith("[") and host.endswith("]")):
        return f"[{host}]"
    return host


def _service_database_url_from_components(
    payload: Mapping[str, Any],
    *,
    secret_name: str | None,
) -> str:
    host = _payload_text_field(payload, ("host",), secret_name=secret_name)
    _validate_service_database_host(host, secret_name=secret_name)
    port = _payload_port_field(payload, secret_name=secret_name)
    database = _payload_text_field(
        payload,
        ("database", "dbname"),
        secret_name=secret_name,
    )
    username = _payload_text_field(
        payload,
        ("username", "user"),
        secret_name=secret_name,
    )
    password = _payload_text_field(payload, ("password",), secret_name=secret_name)
    sslmode = _payload_optional_text_field(
        payload,
        ("sslmode", "ssl_mode"),
        secret_name=secret_name,
    )

    userinfo = f"{quote(username, safe='')}:{quote(password, safe='')}"
    url = (
        f"postgresql://{userinfo}@{_host_for_url(host)}:{port}/"
        f"{quote(database, safe='')}"
    )
    if sslmode:
        url = f"{url}?sslmode={quote(sslmode, safe='')}"
    return url


def parse_service_database_secret_payload(
    secret_value: str | Mapping[str, Any],
    *,
    secret_name: str | None = None,
) -> str:
    """Normalize a service DB credential bundle to a PostgreSQL URL.

    Accepted payload shapes are:

    * ``{"url": "postgresql://..."}`` (preferred, returned unchanged after
      basic PostgreSQL URL validation); and
    * component bundles containing ``host``, ``port``, ``database`` or
      ``dbname``, ``username`` or ``user``, ``password``, and optional
      ``sslmode`` or ``ssl_mode``.

    Errors are fail-closed and sanitized: they include the logical secret,
    sanitized identifier, and field name only. They never include the raw secret
    payload, DB URL, or password.
    """

    if isinstance(secret_value, str):
        try:
            parsed_payload = json.loads(secret_value)
        except json.JSONDecodeError as exc:
            raise _service_database_payload_error(
                "Service database secret payload is not valid JSON",
                secret_name=secret_name,
            ) from exc
    elif isinstance(secret_value, Mapping):
        parsed_payload = secret_value
    else:
        raise _service_database_payload_error(
            "Service database secret payload must be a JSON object",
            secret_name=secret_name,
        )

    if not isinstance(parsed_payload, Mapping):
        raise _service_database_payload_error(
            "Service database secret payload must be a JSON object",
            secret_name=secret_name,
        )

    if "url" in parsed_payload:
        return _validate_service_database_url(
            parsed_payload["url"],
            secret_name=secret_name,
        )

    return _service_database_url_from_components(
        parsed_payload,
        secret_name=secret_name,
    )


def load_service_database_url(
    *,
    provider: str | None = None,
    required: bool | None = None,
) -> str | None:
    """Load and normalize the configured service DB credential bundle.

    Missing secrets follow the standard runtime requirement policy. Present but
    malformed service DB bundles always fail closed because silently ignoring a
    bad credential payload would mask an operator/rotation automation failure.
    """

    requirement = get_runtime_secret_requirement(SERVICE_DATABASE_LOGICAL_ID)
    selected_provider = (provider or get_cloud_provider()).lower()
    resolved_identifier = resolve_service_database_secret_identifier(
        provider=selected_provider,
    )
    secret_value = _load_raw_secret_value(resolved_identifier, provider=selected_provider)
    if secret_value:
        return parse_service_database_secret_payload(
            secret_value,
            secret_name=resolved_identifier,
        )

    if _is_runtime_secret_required(requirement, required=required):
        raise _required_secret_error(
            "Required service database secret could not be loaded",
            logical_name=SERVICE_DATABASE_LOGICAL_ID,
            provider=selected_provider,
            identifier=resolved_identifier,
            env_prefix=requirement.env_prefix,
            name_env_var=requirement.name_env_var,
        )

    return None


# =============================================================================
# Cloud-Specific Secret Loaders
# =============================================================================


def _load_secret_string_from_aws(secret_name: str) -> Optional[str]:
    """Load the raw SecretString from AWS Secrets Manager."""
    log_secret_name = _sanitize_secret_identifier(secret_name)
    try:
        import boto3
        from botocore.exceptions import ClientError

        region = os.environ.get("AWS_REGION") or os.environ.get(
            "AWS_DEFAULT_REGION", "us-east-1"
        )
        client = boto3.client("secretsmanager", region_name=region)
        response = client.get_secret_value(SecretId=secret_name)
        return response.get("SecretString")

    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code == "ResourceNotFoundException":
            logger.warning(f"Secret not found in AWS: {log_secret_name}")
        elif error_code == "AccessDeniedException":
            logger.error(f"Access denied to AWS secret: {log_secret_name}")
        else:
            logger.error(
                f"Error retrieving AWS secret {log_secret_name}: {type(e).__name__}"
            )
    except ImportError:
        logger.error("boto3 not installed. Install with: pip install boto3")
    except Exception as e:
        logger.error(
            f"Unexpected error retrieving AWS secret {log_secret_name}: "
            f"{type(e).__name__}"
        )

    return None


def load_secret_from_aws(secret_name: str) -> Optional[str]:
    """Load a secret from AWS Secrets Manager."""

    secret_value = _load_secret_string_from_aws(secret_name)
    if secret_value:
        try:
            parsed = json.loads(secret_value)
            if isinstance(parsed, dict) and len(parsed) == 1:
                return list(parsed.values())[0]
            elif isinstance(parsed, dict):
                return json.dumps(parsed)
        except json.JSONDecodeError:
            pass
        return secret_value

    return None


def load_secret_from_gcp(
    secret_name: str, project_id: Optional[str] = None
) -> Optional[str]:
    """Load a secret from GCP Secret Manager."""
    log_secret_name = _sanitize_secret_identifier(secret_name)
    try:
        from google.cloud import secretmanager

        client = secretmanager.SecretManagerServiceClient()
        project = (
            project_id
            or os.environ.get("GCP_PROJECT_ID")
            or os.environ.get("GOOGLE_CLOUD_PROJECT")
        )

        if not project:
            if not secret_name.startswith("projects/"):
                logger.warning(
                    "GCP project ID not configured. Set GCP_PROJECT_ID environment variable."
                )
                return None

        if secret_name.startswith("projects/"):
            name = secret_name
            if "/versions/" not in name:
                name = f"{name}/versions/latest"
        else:
            name = f"projects/{project}/secrets/{secret_name}/versions/latest"
        response = client.access_secret_version(request={"name": name})
        return response.payload.data.decode("UTF-8")

    except ImportError:
        logger.error(
            "google-cloud-secret-manager not installed. "
            "Install with: pip install google-cloud-secret-manager"
        )
    except Exception as e:
        logger.warning(
            f"Failed to load secret '{log_secret_name}' from GCP: {type(e).__name__}"
        )

    return None


def _parse_azure_secret_identifier(
    secret_identifier: str,
    vault_url: Optional[str] = None,
) -> tuple[str | None, str, str | None]:
    """Return ``(vault_url, secret_name, version)`` from name or Key Vault URI."""

    parsed = urlparse(secret_identifier)
    if parsed.scheme and parsed.netloc:
        path_parts = [part for part in parsed.path.split("/") if part]
        if len(path_parts) >= 2 and path_parts[0].lower() == "secrets":
            parsed_vault_url = f"{parsed.scheme}://{parsed.netloc}"
            secret_name = path_parts[1]
            version = path_parts[2] if len(path_parts) >= 3 else None
            return parsed_vault_url, secret_name, version
    return vault_url, secret_identifier, None


def load_secret_from_azure(
    secret_name: str, vault_url: Optional[str] = None
) -> Optional[str]:
    """Load a secret from Azure Key Vault.

    Note: Azure Key Vault secret names cannot contain underscores.
    Use hyphens instead (e.g., taproot-retrieval-db-password).
    """
    log_secret_name = _sanitize_secret_identifier(secret_name)
    try:
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.secrets import SecretClient

        parsed_vault_url, parsed_secret_name, version = _parse_azure_secret_identifier(
            secret_name,
            vault_url,
        )
        vault = parsed_vault_url or os.environ.get("AZURE_KEY_VAULT_URL")

        if not vault:
            logger.warning(
                "Azure Key Vault URL not configured. "
                "Set AZURE_KEY_VAULT_URL environment variable."
            )
            return None

        credential = DefaultAzureCredential()
        client = SecretClient(vault_url=vault, credential=credential)
        secret = client.get_secret(parsed_secret_name, version=version)
        return secret.value

    except ImportError:
        logger.error(
            "azure-identity and azure-keyvault-secrets not installed. "
            "Install with: pip install azure-identity azure-keyvault-secrets"
        )
    except Exception as e:
        logger.warning(
            f"Failed to load secret '{log_secret_name}' from Azure: {type(e).__name__}"
        )

    return None


# =============================================================================
# Unified Secret Loading
# =============================================================================


def get_cloud_provider() -> str:
    """Get the configured cloud provider from TAPROOT_CLOUD_PROVIDER.

    Falls back to service-specific env vars for backwards compatibility.
    """
    return (
        os.environ.get("TAPROOT_CLOUD_PROVIDER")
        or os.environ.get("RETRIEVAL_CLOUD_PROVIDER")
        or os.environ.get("FRONTS_CLOUD_PROVIDER")
        or "local"
    ).lower()


def is_secrets_enabled() -> bool:
    """Check if secret loading is enabled.

    Checks TAPROOT_SECRETS_ENABLED first, falls back to service-specific vars.
    """
    for var in (
        "TAPROOT_SECRETS_ENABLED",
        "RETRIEVAL_SECRETS_ENABLED",
        "FRONTS_SECRETS_ENABLED",
    ):
        val = os.environ.get(var, "").lower()
        if val in ("true", "1", "yes"):
            return True
    return False


def _load_secret_value(secret_name: str, *, provider: str | None = None) -> Optional[str]:
    selected_provider = (provider or get_cloud_provider()).lower()

    if selected_provider == "aws":
        return load_secret_from_aws(secret_name)
    elif selected_provider == "gcp":
        return load_secret_from_gcp(secret_name)
    elif selected_provider == "azure":
        return load_secret_from_azure(secret_name)
    elif selected_provider == "local":
        logger.debug(
            f"Local mode - skipping secret loading for "
            f"{_sanitize_secret_identifier(secret_name)}"
        )
        return None
    else:
        logger.warning(f"Unknown cloud provider: {selected_provider}")
        return None


def load_secret(secret_name: str) -> Optional[str]:
    """Load a single secret from the configured cloud provider.

    Args:
        secret_name: The secret name in the cloud secret manager.

    Returns:
        The secret value, or None if not found or loading failed.
    """
    return _load_secret_value(secret_name)


def load_required_secret(
    secret_name: str,
    *,
    env_prefix: str | None = None,
    logical_name: str | None = None,
    provider: str | None = None,
) -> str:
    """Load a required secret value or raise a sanitized exception.

    ``secret_name`` is the canonical default identifier. When ``env_prefix`` is
    provided, the active cloud provider's full-identifier override and the
    provider-neutral ``*_SECRET_NAME`` override are resolved before falling back
    to that default. The exception text never includes secret payload contents.
    """

    selected_provider = (provider or get_cloud_provider()).lower()
    resolved_identifier = resolve_secret_identifier(
        secret_name,
        env_prefix=env_prefix,
        provider=selected_provider,
    )
    value = _load_secret_value(resolved_identifier, provider=selected_provider)
    if value:
        return value

    label = logical_name or env_prefix or secret_name
    raise _required_secret_error(
        "Required secret could not be loaded",
        logical_name=label,
        provider=selected_provider,
        identifier=resolved_identifier,
    )


def load_runtime_secret(
    requirement: RuntimeSecretRequirement | str,
    *,
    provider: str | None = None,
    required: bool | None = None,
) -> str | None:
    """Load a runtime secret using a declarative requirement.

    ``required=None`` applies the requirement policy: explicit required secrets
    always fail closed, and production defaults fail closed when
    ``required_in_production`` is true. Optional provider/integration secrets can
    pass ``required=True`` when a feature or provider is enabled.
    """

    selected_requirement = (
        get_runtime_secret_requirement(requirement)
        if isinstance(requirement, str)
        else requirement
    )
    selected_provider = (provider or get_cloud_provider()).lower()
    resolved_identifier = resolve_secret_identifier(
        selected_requirement.default_name,
        env_prefix=selected_requirement.env_prefix,
        env_alias_prefixes=selected_requirement.env_alias_prefixes,
        provider=selected_provider,
        provider_env_vars=selected_requirement.provider_env_vars,
        name_env_var=selected_requirement.name_env_var,
    )

    if selected_requirement.json_field:
        secret_value = _load_raw_secret_value(
            resolved_identifier,
            provider=selected_provider,
        )
        value = (
            extract_secret_json_field(
                secret_value,
                selected_requirement.json_field,
                secret_name=selected_requirement.logical_id,
            )
            if secret_value
            else None
        )
    else:
        value = _load_secret_value(resolved_identifier, provider=selected_provider)

    if value:
        return value

    if _is_runtime_secret_required(selected_requirement, required=required):
        raise _required_secret_error(
            "Required runtime secret could not be loaded",
            logical_name=selected_requirement.logical_id,
            provider=selected_provider,
            identifier=resolved_identifier,
            field=selected_requirement.json_field,
            env_prefix=selected_requirement.env_prefix,
            name_env_var=selected_requirement.name_env_var,
        )

    return None


def load_startup_secrets(
    requirements: Iterable[RuntimeSecretRequirement | str] | Mapping[str, str],
    *,
    provider: str | None = None,
    required: bool | None = None,
) -> ResolvedRuntimeSecrets:
    """Read startup secrets once into memory without mutating ``os.environ``.

    ``requirements`` may be shared runtime requirements/logical IDs or a mapping
    of ``logical_name -> canonical_secret_name``. Raw names are required by
    default; runtime requirements keep their own required policy when
    ``required`` is ``None``.
    """

    selected_provider = (provider or get_cloud_provider()).lower()
    values: dict[str, str] = {}

    if isinstance(requirements, Mapping):
        for logical_name, secret_name in requirements.items():
            value = _load_secret_value(secret_name, provider=selected_provider)
            if value:
                values[logical_name] = value
            elif required is not False:
                raise _required_secret_error(
                    "Required startup secret could not be loaded",
                    logical_name=logical_name,
                    provider=selected_provider,
                    identifier=secret_name,
                )
        return ResolvedRuntimeSecrets(values=values, provider=selected_provider)

    for requirement in requirements:
        if isinstance(requirement, RuntimeSecretRequirement):
            logical_name = requirement.logical_id
            value = load_runtime_secret(
                requirement,
                provider=selected_provider,
                required=required,
            )
        elif requirement in RUNTIME_SECRET_REQUIREMENTS:
            logical_name = requirement
            value = load_runtime_secret(
                requirement,
                provider=selected_provider,
                required=required,
            )
        else:
            logical_name = requirement
            value = _load_secret_value(requirement, provider=selected_provider)
            if not value and required is not False:
                raise _required_secret_error(
                    "Required startup secret could not be loaded",
                    logical_name=logical_name,
                    provider=selected_provider,
                    identifier=requirement,
                )

        if value:
            values[logical_name] = value

    return ResolvedRuntimeSecrets(values=values, provider=selected_provider)


def load_required_runtime_secret(
    requirement: RuntimeSecretRequirement | str,
    *,
    provider: str | None = None,
) -> str:
    """Load a runtime secret and fail closed regardless of environment."""

    value = load_runtime_secret(requirement, provider=provider, required=True)
    if value is None:
        # ``load_runtime_secret`` raises before returning None when required=True.
        raise RequiredSecretError("Required runtime secret could not be loaded")
    return value


def load_runtime_secret_json_field(
    requirement: RuntimeSecretRequirement | str,
    field_name: str,
    *,
    provider: str | None = None,
    required: bool | None = None,
) -> str | None:
    """Load a named JSON field from a runtime secret requirement."""

    selected_requirement = (
        get_runtime_secret_requirement(requirement)
        if isinstance(requirement, str)
        else requirement
    )
    return load_runtime_secret(
        selected_requirement.with_overrides(json_field=field_name),
        provider=provider,
        required=required,
    )


def _load_raw_secret_value(secret_name: str, *, provider: str | None = None) -> Optional[str]:
    selected_provider = (provider or get_cloud_provider()).lower()

    if selected_provider == "aws":
        return _load_secret_string_from_aws(secret_name)
    elif selected_provider == "gcp":
        return load_secret_from_gcp(secret_name)
    elif selected_provider == "azure":
        return load_secret_from_azure(secret_name)
    elif selected_provider == "local":
        logger.debug(
            f"Local mode - skipping secret loading for "
            f"{_sanitize_secret_identifier(secret_name)}"
        )
        return None
    else:
        logger.warning(f"Unknown cloud provider: {selected_provider}")
        return None


def extract_secret_json_field(
    secret_value: str,
    field_name: str,
    *,
    secret_name: str | None = None,
) -> Optional[str]:
    """Extract a string field from a JSON secret value without logging the value.

    Secret managers often store structured payloads such as
    ``{"url":"postgres://..."}``. This helper parses that payload and returns
    the requested string field while keeping logs limited to secret identifiers
    and field names, never the secret contents.
    """

    try:
        parsed = json.loads(secret_value)
    except json.JSONDecodeError:
        label = f" '{_sanitize_secret_identifier(secret_name)}'" if secret_name else ""
        logger.warning(
            "Secret%s is not a JSON object; field '%s' unavailable",
            label,
            field_name,
        )
        return None

    if not isinstance(parsed, dict):
        label = f" '{_sanitize_secret_identifier(secret_name)}'" if secret_name else ""
        logger.warning(
            "Secret%s is not a JSON object; field '%s' unavailable",
            label,
            field_name,
        )
        return None

    field_value = parsed.get(field_name)
    if field_value is None:
        label = f" '{_sanitize_secret_identifier(secret_name)}'" if secret_name else ""
        logger.warning("Secret%s does not contain field '%s'", label, field_name)
        return None
    if not isinstance(field_value, str):
        label = f" '{_sanitize_secret_identifier(secret_name)}'" if secret_name else ""
        logger.warning("Secret%s field '%s' is not a string", label, field_name)
        return None
    return field_value


def load_secret_json_field(
    secret_name: str,
    field_name: str,
    *,
    env_prefix: str | None = None,
    provider: str | None = None,
) -> Optional[str]:
    """Load a secret and extract a named JSON string field.

    This intentionally bypasses AWS's legacy single-key JSON flattening in
    ``load_secret_from_aws`` so callers can explicitly request fields like the
    system-record writer ``url`` key. Secret values are never logged.
    """

    resolved_identifier = resolve_secret_identifier(
        secret_name,
        env_prefix=env_prefix,
        provider=provider,
    )
    secret_value = _load_raw_secret_value(resolved_identifier, provider=provider)

    if not secret_value:
        return None
    return extract_secret_json_field(
        secret_value,
        field_name,
        secret_name=secret_name,
    )


def load_required_secret_json_field(
    secret_name: str,
    field_name: str,
    *,
    env_prefix: str | None = None,
    logical_name: str | None = None,
    provider: str | None = None,
) -> str:
    """Load a required JSON field from a required secret.

    Missing, unreadable, malformed, non-string, or empty fields fail closed with
    a sanitized ``RequiredSecretError``. Logs and exceptions identify the logical
    secret and field, never the raw payload.
    """

    selected_provider = (provider or get_cloud_provider()).lower()
    resolved_identifier = resolve_secret_identifier(
        secret_name,
        env_prefix=env_prefix,
        provider=selected_provider,
    )
    secret_value = _load_raw_secret_value(resolved_identifier, provider=selected_provider)
    field_value = None
    if secret_value:
        field_value = extract_secret_json_field(
            secret_value,
            field_name,
            secret_name=secret_name,
        )
    if field_value:
        return field_value

    label = logical_name or env_prefix or secret_name
    raise _required_secret_error(
        "Required secret JSON field could not be loaded",
        logical_name=label,
        field=field_name,
        provider=selected_provider,
        identifier=resolved_identifier,
    )


def load_secrets_to_env(
    mappings: dict[str, str],
    *,
    critical_secrets: Optional[set[str]] = None,
) -> int:
    """Legacy compatibility shim: load cloud secrets into environment variables.

    Prefer ``load_startup_secrets`` for production runtime so secret payloads
    stay in memory instead of being copied into ``os.environ``.

    Args:
        mappings: Dict of {secret_name: env_var_name}. Each secret found in
            the cloud provider will be set as the corresponding env var.
        critical_secrets: Optional set of secret names that should emit
            warnings if not found. Defaults to None (no warnings).

    Returns:
        Number of secrets successfully loaded.
    """
    if not is_secrets_enabled():
        logger.debug(
            "Secret manager integration disabled "
            "(set TAPROOT_SECRETS_ENABLED=true to enable)"
        )
        return 0

    provider = get_cloud_provider()
    if provider == "local":
        logger.info("Local mode - secrets will be read from environment variables only")
        return 0

    logger.info(f"Loading secrets from {provider.upper()} secret manager...")

    loaded_count = 0
    for secret_name, env_var in mappings.items():
        if os.environ.get(env_var):
            logger.debug(f"Skipping {env_var} - already set in environment")
            continue

        secret_value = load_secret(secret_name)
        if secret_value:
            os.environ[env_var] = secret_value
            loaded_count += 1
            logger.info(f"Loaded {env_var} from secret manager")
        elif critical_secrets and secret_name in critical_secrets:
            logger.warning(
                f"Could not load critical secret "
                f"'{_sanitize_secret_identifier(secret_name)}' for {env_var}"
            )

    logger.info(f"Loaded {loaded_count} secrets from {provider.upper()} secret manager")
    return loaded_count
