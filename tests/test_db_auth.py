"""Tests for shared DB auth helpers."""

from __future__ import annotations

import logging
import sys
import types

import pytest

from taproot_common import db_auth
from taproot_common.db_auth import (
    DbAuthConfigError,
    asyncpg_connect_kwargs,
    load_db_auth_config,
    sqlalchemy_async_engine_kwargs,
    sqlalchemy_async_url_and_connect_args,
)


def test_env_parsing_supports_system_record_database_identity():
    config = load_db_auth_config(
        "SYSTEM_RECORD_DATABASE",
        environ={
            "SYSTEM_RECORD_DATABASE_AUTH_MODE": "identity",
            "SYSTEM_RECORD_DATABASE_PROVIDER": "aws",
            "SYSTEM_RECORD_DATABASE_HOST": "db.example.test",
            "SYSTEM_RECORD_DATABASE_PORT": "5432",
            "SYSTEM_RECORD_DATABASE_NAME": "system_record",
            "SYSTEM_RECORD_DATABASE_USER": "svc_system_record",
            "SYSTEM_RECORD_DATABASE_SSLMODE": "verify-full",
            "SYSTEM_RECORD_DATABASE_AWS_REGION": "us-east-1",
        },
    )

    assert config.auth_mode == "identity"
    assert config.prefix == "SYSTEM_RECORD_DATABASE"
    assert config.provider == "aws"
    assert config.host == "db.example.test"
    assert config.port == 5432
    assert config.database == "system_record"
    assert config.user == "svc_system_record"
    assert config.sslmode == "verify-full"
    assert config.aws_region == "us-east-1"


def test_secret_url_fallback_uses_prefix_url():
    raw_url = "postgresql://svc:raw-password@db.example.test:5432/taproot"

    assert asyncpg_connect_kwargs(
        environ={"DATABASE_AUTH_MODE": "secret", "DATABASE_URL": raw_url}
    ) == {"dsn": raw_url}
    assert sqlalchemy_async_engine_kwargs(
        environ={"DATABASE_AUTH_MODE": "secret", "DATABASE_URL": raw_url}
    ) == {"url": raw_url.replace("postgresql://", "postgresql+asyncpg://", 1), "connect_args": {}}


def test_secret_url_fallback_uses_existing_service_secret_loader(monkeypatch):
    raw_url = "postgres://svc:raw-password@db.example.test/taproot"
    monkeypatch.setattr(db_auth, "load_service_database_url", lambda required=False: raw_url)

    url, connect_args = sqlalchemy_async_url_and_connect_args(
        environ={"DATABASE_AUTH_MODE": "secret"}
    )

    assert url == "postgresql+asyncpg://svc:raw-password@db.example.test/taproot"
    assert connect_args == {}


def test_identity_mode_does_not_probe_secret_fallback(monkeypatch):
    monkeypatch.setattr(
        db_auth,
        "load_service_database_url",
        lambda required=False: (_ for _ in ()).throw(AssertionError("secret read")),
    )

    config = load_db_auth_config(
        environ={
            "DATABASE_AUTH_MODE": "identity",
            "DATABASE_PROVIDER": "aws",
            "DATABASE_HOST": "db.example.test",
            "DATABASE_PORT": "5432",
            "DATABASE_NAME": "taproot",
            "DATABASE_USER": "svc_runtime",
            "DATABASE_AWS_REGION": "us-east-1",
        }
    )

    assert config.auth_mode == "identity"


def test_aws_identity_password_callable_uses_boto3(monkeypatch):
    calls: list[tuple[str, dict[str, object]]] = []

    class FakeRdsClient:
        def generate_db_auth_token(self, **kwargs: object) -> str:
            calls.append(("generate_db_auth_token", kwargs))
            return "generated-token"

    def fake_client(service_name: str, *, region_name: str) -> FakeRdsClient:
        calls.append(("client", {"service_name": service_name, "region_name": region_name}))
        return FakeRdsClient()

    boto3_module = types.ModuleType("boto3")
    boto3_module.client = fake_client
    monkeypatch.setitem(sys.modules, "boto3", boto3_module)

    kwargs = asyncpg_connect_kwargs(
        environ={
            "DATABASE_AUTH_MODE": "identity",
            "DATABASE_PROVIDER": "aws",
            "DATABASE_HOST": "db.example.test",
            "DATABASE_PORT": "5432",
            "DATABASE_NAME": "taproot",
            "DATABASE_USER": "svc_runtime",
            "DATABASE_AWS_REGION": "us-east-1",
        }
    )

    assert kwargs["password"]() == "generated-token"
    assert calls == [
        ("client", {"service_name": "rds", "region_name": "us-east-1"}),
        (
            "generate_db_auth_token",
            {
                "DBHostname": "db.example.test",
                "Port": 5432,
                "DBUsername": "svc_runtime",
                "Region": "us-east-1",
            },
        ),
    ]


def test_missing_required_identity_fields_fail_safely():
    raw_password = "raw-password-that-must-not-appear"

    with pytest.raises(DbAuthConfigError) as exc_info:
        load_db_auth_config(
            environ={
                "DATABASE_AUTH_MODE": "identity",
                "DATABASE_PROVIDER": "aws",
                "DATABASE_PORT": "5432",
                "DATABASE_NAME": "taproot",
                "DATABASE_USER": f"svc:{raw_password}",
                "DATABASE_AWS_REGION": "us-east-1",
            }
        )

    assert "DATABASE_HOST" in str(exc_info.value)
    assert raw_password not in str(exc_info.value)


def test_no_secret_logging_for_url_fallback(caplog):
    raw_url = "postgresql://svc:raw-password@db.example.test:5432/taproot"
    caplog.set_level(logging.DEBUG)

    result = asyncpg_connect_kwargs(
        environ={"DATABASE_AUTH_MODE": "secret", "DATABASE_URL": raw_url}
    )

    assert result == {"dsn": raw_url}
    assert "raw-password" not in caplog.text
    assert raw_url not in caplog.text


def test_gcp_contract_requires_instance_connection_name():
    with pytest.raises(DbAuthConfigError) as exc_info:
        load_db_auth_config(
            environ={
                "DATABASE_AUTH_MODE": "identity",
                "DATABASE_PROVIDER": "gcp",
                "DATABASE_HOST": "10.0.0.5",
                "DATABASE_PORT": "5432",
                "DATABASE_NAME": "taproot",
                "DATABASE_USER": "svc@project.iam",
            }
        )

    assert "DATABASE_GCP_INSTANCE_CONNECTION_NAME" in str(exc_info.value)


def test_identity_sqlalchemy_kwargs_keep_password_out_of_url():
    engine_kwargs = sqlalchemy_async_engine_kwargs(
        environ={
            "DATABASE_AUTH_MODE": "identity",
            "DATABASE_PROVIDER": "aws",
            "DATABASE_HOST": "db.example.test",
            "DATABASE_PORT": "5432",
            "DATABASE_NAME": "taproot",
            "DATABASE_USER": "svc_runtime",
            "DATABASE_AWS_REGION": "us-east-1",
        }
    )

    assert engine_kwargs["url"] == (
        "postgresql+asyncpg://svc_runtime@db.example.test:5432/taproot"
    )
    assert set(engine_kwargs["connect_args"]) == {"password", "ssl"}
    assert callable(engine_kwargs["connect_args"]["password"])
