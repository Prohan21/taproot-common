"""Tests for taproot_common.exceptions module."""

from __future__ import annotations

import pytest

from taproot_common.exceptions import TaprootServiceError


class TestTaprootServiceError:
    """Tests for TaprootServiceError base exception."""

    def test_creation_with_all_fields(self) -> None:
        details = {"resource_id": "abc123", "attempted_action": "delete"}
        exc = TaprootServiceError(
            "Store not found",
            code="STORE_NOT_FOUND",
            status_code=404,
            details=details,
        )
        assert exc.message == "Store not found"
        assert exc.code == "STORE_NOT_FOUND"
        assert exc.status_code == 404
        assert exc.details == details

    def test_default_status_code(self) -> None:
        exc = TaprootServiceError("Something broke", code="INTERNAL_ERROR")
        assert exc.status_code == 500

    def test_default_details_is_empty_dict(self) -> None:
        exc = TaprootServiceError("fail", code="FAIL")
        assert exc.details == {}

    def test_details_none_becomes_empty_dict(self) -> None:
        exc = TaprootServiceError("fail", code="FAIL", details=None)
        assert exc.details == {}

    def test_str_matches_message(self) -> None:
        exc = TaprootServiceError("Human-readable message", code="ERR")
        assert str(exc) == "Human-readable message"

    def test_catchable_as_exception(self) -> None:
        with pytest.raises(Exception, match="catch me"):
            raise TaprootServiceError("catch me", code="TEST")

    def test_catchable_as_taproot_service_error(self) -> None:
        with pytest.raises(TaprootServiceError):
            raise TaprootServiceError("specific catch", code="TEST")

    def test_isinstance_of_exception(self) -> None:
        exc = TaprootServiceError("test", code="TEST")
        assert isinstance(exc, Exception)
        assert isinstance(exc, TaprootServiceError)

    def test_details_not_shared_between_instances(self) -> None:
        exc1 = TaprootServiceError("a", code="A")
        exc2 = TaprootServiceError("b", code="B")
        exc1.details["key"] = "value"
        assert "key" not in exc2.details
