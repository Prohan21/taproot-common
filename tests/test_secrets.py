"""Tests for shared secret-loading helpers."""

import logging

from taproot_common import secrets as secret_helpers
from taproot_common.secrets import extract_secret_json_field, load_secret_json_field


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
