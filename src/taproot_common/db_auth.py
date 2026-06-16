"""Small shared PostgreSQL auth contract for Taproot services."""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import quote

from taproot_common.secrets import load_service_database_url

AuthMode = Literal["secret", "identity"]
Provider = Literal["aws", "azure", "gcp"]


class DbAuthConfigError(ValueError):
    """Raised when DB auth configuration is missing or invalid."""


class DbAuthDependencyError(ImportError):
    """Raised when an identity auth provider needs an optional package."""


@dataclass(frozen=True)
class DbAuthConfig:
    prefix: str
    auth_mode: AuthMode
    host: str | None = None
    port: int | None = None
    database: str | None = None
    user: str | None = None
    sslmode: str | None = None
    provider: Provider | None = None
    secret_url: str | None = None
    aws_region: str | None = None
    azure_managed_identity_client_id: str | None = None
    gcp_instance_connection_name: str | None = None
    gcp_ip_type: str | None = None


def load_db_auth_config(
    prefix: str = "DATABASE",
    *,
    environ: Mapping[str, str] | None = None,
) -> DbAuthConfig:
    """Parse ``<PREFIX>_*`` DB auth env vars without reading secret values into logs."""

    env = environ or os.environ
    prefix = prefix.upper()
    mode = (_env(env, prefix, "AUTH_MODE") or "").lower()
    explicit_url = _env(env, prefix, "URL")
    if not mode:
        mode = "secret" if explicit_url else "identity"
    if mode not in {"secret", "identity"}:
        raise DbAuthConfigError(f"{prefix}_AUTH_MODE must be 'secret' or 'identity'")

    if mode == "secret":
        secret_url = explicit_url or _secret_url_fallback(prefix)
        if not secret_url:
            raise DbAuthConfigError(f"{prefix}_URL is required for secret DB auth")
        return DbAuthConfig(prefix=prefix, auth_mode="secret", secret_url=secret_url)

    provider = (_env(env, prefix, "PROVIDER") or "").lower()
    if provider not in {"aws", "azure", "gcp"}:
        raise DbAuthConfigError(f"{prefix}_PROVIDER must be one of: aws, azure, gcp")

    config = DbAuthConfig(
        prefix=prefix,
        auth_mode="identity",
        host=_required(env, prefix, "HOST"),
        port=_port(_required(env, prefix, "PORT"), f"{prefix}_PORT"),
        database=_required(env, prefix, "NAME"),
        user=_required(env, prefix, "USER"),
        sslmode=_env(env, prefix, "SSLMODE") or "require",
        provider=provider,  # type: ignore[arg-type]
        aws_region=_env(env, prefix, "AWS_REGION")
        or env.get("AWS_REGION")
        or env.get("AWS_DEFAULT_REGION"),
        azure_managed_identity_client_id=_env(
            env,
            prefix,
            "AZURE_MANAGED_IDENTITY_CLIENT_ID",
        )
        or _env(env, prefix, "AZURE_CLIENT_ID"),
        gcp_instance_connection_name=_env(env, prefix, "GCP_INSTANCE_CONNECTION_NAME"),
        gcp_ip_type=_env(env, prefix, "GCP_IP_TYPE"),
    )
    _validate_identity_provider_fields(config)
    return config


def asyncpg_connect_kwargs(
    prefix: str = "DATABASE",
    *,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Return kwargs suitable for ``asyncpg.connect`` or ``asyncpg.create_pool``."""

    config = load_db_auth_config(prefix, environ=environ)
    if config.auth_mode == "secret":
        return {"dsn": config.secret_url}
    return {
        "host": config.host,
        "port": config.port,
        "database": config.database,
        "user": config.user,
        "password": identity_password_callable(config),
        "ssl": config.sslmode,
    }


async def asyncpg_connect(
    prefix: str = "DATABASE",
    *,
    environ: Mapping[str, str] | None = None,
    **kwargs: Any,
) -> Any:
    """Connect with asyncpg using the shared DB auth env contract."""

    try:
        import asyncpg  # type: ignore[import-untyped]
    except ImportError as exc:  # pragma: no cover - depends on service extras
        raise DbAuthDependencyError("asyncpg is required for asyncpg DB auth") from exc

    connect_kwargs = asyncpg_connect_kwargs(prefix, environ=environ)
    connect_kwargs.update(kwargs)
    return await asyncpg.connect(**connect_kwargs)


def sqlalchemy_async_url_and_connect_args(
    prefix: str = "DATABASE",
    *,
    environ: Mapping[str, str] | None = None,
) -> tuple[str, dict[str, Any]]:
    """Return ``(url, connect_args)`` for SQLAlchemy ``create_async_engine``."""

    config = load_db_auth_config(prefix, environ=environ)
    if config.auth_mode == "secret":
        return _async_sqlalchemy_url(config.secret_url or ""), {}
    url = _identity_sqlalchemy_url(config)
    connect_args: dict[str, Any] = {"password": identity_password_callable(config)}
    if config.sslmode:
        connect_args["ssl"] = config.sslmode
    return url, connect_args


def sqlalchemy_async_engine_kwargs(
    prefix: str = "DATABASE",
    *,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Return kwargs that can be splatted into ``create_async_engine``."""

    url, connect_args = sqlalchemy_async_url_and_connect_args(prefix, environ=environ)
    return {"url": url, "connect_args": connect_args}


def identity_password_callable(config: DbAuthConfig) -> Callable[[], str]:
    if config.provider == "aws":
        return lambda: _aws_iam_auth_token(config)
    if config.provider == "azure":
        return lambda: _azure_entra_token(config)
    if config.provider == "gcp":
        return lambda: _gcp_iam_auth_token(config)
    raise DbAuthConfigError("Identity DB auth requires a provider")


def _aws_iam_auth_token(config: DbAuthConfig) -> str:
    try:
        import boto3  # type: ignore[import-untyped]
    except ImportError as exc:  # pragma: no cover - depends on service extras
        raise DbAuthDependencyError(
            "boto3 is required for AWS IAM DB auth; install taproot-common[aws]"
        ) from exc
    if not config.aws_region:
        raise DbAuthConfigError(f"{config.prefix}_AWS_REGION or AWS_REGION is required")
    return boto3.client("rds", region_name=config.aws_region).generate_db_auth_token(
        DBHostname=config.host,
        Port=config.port,
        DBUsername=config.user,
        Region=config.aws_region,
    )


def _azure_entra_token(config: DbAuthConfig) -> str:
    try:
        from azure.identity import DefaultAzureCredential  # type: ignore[import-untyped]
    except ImportError as exc:  # pragma: no cover - depends on service extras
        raise DbAuthDependencyError(
            "azure-identity is required for Azure Entra DB auth; "
            "install taproot-common[azure]"
        ) from exc
    credential_kwargs = {}
    if config.azure_managed_identity_client_id:
        credential_kwargs["managed_identity_client_id"] = (
            config.azure_managed_identity_client_id
        )
    credential = DefaultAzureCredential(**credential_kwargs)
    return credential.get_token(
        "https://ossrdbms-aad.database.windows.net/.default"
    ).token


def _gcp_iam_auth_token(config: DbAuthConfig) -> str:
    try:
        import google.auth  # type: ignore[import-untyped]
        from google.auth.transport.requests import Request  # type: ignore[import-untyped]
    except ImportError as exc:  # pragma: no cover - depends on service extras
        raise DbAuthDependencyError(
            "google-auth is required for manual GCP Cloud SQL IAM DB auth; "
            "prefer the Cloud SQL Python Connector for pooled services"
        ) from exc
    credentials, _project = google.auth.default(
        scopes=["https://www.googleapis.com/auth/sqlservice.login"]
    )
    credentials.refresh(Request())
    return credentials.token


def _validate_identity_provider_fields(config: DbAuthConfig) -> None:
    if config.provider == "aws" and not config.aws_region:
        raise DbAuthConfigError(f"{config.prefix}_AWS_REGION or AWS_REGION is required")
    if config.provider == "gcp" and not config.gcp_instance_connection_name:
        raise DbAuthConfigError(
            f"{config.prefix}_GCP_INSTANCE_CONNECTION_NAME is required for GCP identity DB auth"
        )


def _env(env: Mapping[str, str], prefix: str, suffix: str) -> str | None:
    value = env.get(f"{prefix}_{suffix}")
    return value.strip() if value and value.strip() else None


def _required(env: Mapping[str, str], prefix: str, suffix: str) -> str:
    value = _env(env, prefix, suffix)
    if not value:
        raise DbAuthConfigError(f"{prefix}_{suffix} is required for identity DB auth")
    return value


def _port(value: str, label: str) -> int:
    if not value.isdigit() or not 1 <= int(value) <= 65535:
        raise DbAuthConfigError(f"{label} must be an integer from 1 to 65535")
    return int(value)


def _secret_url_fallback(prefix: str) -> str | None:
    if prefix == "DATABASE":
        return load_service_database_url(required=False)
    return None


def _async_sqlalchemy_url(url: str) -> str:
    if url.startswith("postgresql+asyncpg://"):
        return url
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+asyncpg://", 1)
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+asyncpg://", 1)
    return url


def _identity_sqlalchemy_url(config: DbAuthConfig) -> str:
    host = config.host or ""
    if ":" in host and not (host.startswith("[") and host.endswith("]")):
        host = f"[{host}]"
    return (
        f"postgresql+asyncpg://{quote(config.user or '', safe='')}@"
        f"{host}:{config.port}/{quote(config.database or '', safe='')}"
    )
