"""Cloud-specific auth context providers.

Each provider knows how to extract the API key identifier from the
headers that its respective API Gateway injects.
"""

import base64
import json
import logging
from abc import ABC, abstractmethod
from typing import Dict

from taproot_common.auth.models import CloudProvider

logger = logging.getLogger(__name__)


class MissingHeaderError(Exception):
    """Raised when the expected identity header is not present."""

    def __init__(self, header_name: str) -> None:
        self.header_name = header_name
        super().__init__(f"Missing required header: {header_name}")


class AuthContextProvider(ABC):
    """Abstract base for extracting API key identity from gateway headers."""

    provider: CloudProvider

    @abstractmethod
    def extract_key_id(self, headers: Dict[str, str]) -> str:
        """Extract the API key identifier from request headers.

        Args:
            headers: Request headers (case-insensitive dict).

        Returns:
            The API key identifier string.

        Raises:
            MissingHeaderError: If the expected header is absent.
        """


class AWSAuthContextProvider(AuthContextProvider):
    """Extracts API key ID from AWS REST API Gateway.

    AWS REST API injects `context.identity.apiKeyId` which we map to
    the `X-Api-Key-Id` header via integration request parameters.
    """

    provider = CloudProvider.AWS

    def extract_key_id(self, headers: Dict[str, str]) -> str:
        logger.debug(
            "auth.provider.extract.start",
            extra={"provider": "aws", "header": "X-Api-Key-Id"},
        )
        value = headers.get("x-api-key-id")
        if not value:
            logger.warning(
                "auth.provider.extract.missing_header",
                extra={"provider": "aws", "header": "X-Api-Key-Id"},
            )
            raise MissingHeaderError("X-Api-Key-Id")
        logger.debug(
            "auth.provider.extract.success",
            extra={"provider": "aws", "api_key_id": value},
        )
        return value


class GCPAuthContextProvider(AuthContextProvider):
    """Extracts API key ID from GCP API Gateway / Endpoints.

    GCP injects `X-Endpoint-API-UserInfo` as a base64-encoded JSON
    containing the authenticated principal's claims.
    """

    provider = CloudProvider.GCP

    def extract_key_id(self, headers: Dict[str, str]) -> str:
        logger.debug(
            "auth.provider.extract.start",
            extra={"provider": "gcp", "header": "X-Endpoint-API-UserInfo"},
        )
        encoded = headers.get("x-endpoint-api-userinfo")
        if not encoded:
            logger.warning(
                "auth.provider.extract.missing_header",
                extra={"provider": "gcp", "header": "X-Endpoint-API-UserInfo"},
            )
            raise MissingHeaderError("X-Endpoint-API-UserInfo")
        try:
            # GCP base64-encodes the user info JSON
            padding = 4 - len(encoded) % 4
            if padding != 4:
                encoded += "=" * padding
            decoded = json.loads(base64.b64decode(encoded))
            key_id = decoded.get("api_key_id") or decoded.get("sub")
            if not key_id:
                logger.warning(
                    "auth.provider.extract.missing_header",
                    extra={
                        "provider": "gcp",
                        "header": "X-Endpoint-API-UserInfo (no api_key_id claim)",
                    },
                )
                raise MissingHeaderError("X-Endpoint-API-UserInfo (no api_key_id claim)")
            logger.debug(
                "auth.provider.extract.success",
                extra={"provider": "gcp", "api_key_id": str(key_id)},
            )
            return str(key_id)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            logger.warning(
                "auth.provider.gcp.decode_failed",
                extra={"error": str(exc)},
            )
            raise MissingHeaderError("X-Endpoint-API-UserInfo (decode error)") from exc


class AzureAuthContextProvider(AuthContextProvider):
    """Extracts API key ID from Azure API Management.

    Azure APIM can inject `X-Api-Key-Id` via an inbound policy.
    """

    provider = CloudProvider.AZURE

    def extract_key_id(self, headers: Dict[str, str]) -> str:
        logger.debug(
            "auth.provider.extract.start",
            extra={"provider": "azure", "header": "X-Api-Key-Id"},
        )
        value = headers.get("x-api-key-id")
        if not value:
            logger.warning(
                "auth.provider.extract.missing_header",
                extra={"provider": "azure", "header": "X-Api-Key-Id"},
            )
            raise MissingHeaderError("X-Api-Key-Id")
        logger.debug(
            "auth.provider.extract.success",
            extra={"provider": "azure", "api_key_id": value},
        )
        return value


class LocalAuthContextProvider(AuthContextProvider):
    """Local development provider.

    Returns a dev default if the header is absent, allowing services
    to run without an API Gateway in front.
    """

    provider = CloudProvider.LOCAL
    DEFAULT_KEY_ID = "local-dev-key"

    def extract_key_id(self, headers: Dict[str, str]) -> str:
        logger.debug(
            "auth.provider.extract.start",
            extra={"provider": "local", "header": "X-Api-Key-Id"},
        )
        value = headers.get("x-api-key-id") or self.DEFAULT_KEY_ID
        logger.debug(
            "auth.provider.extract.success",
            extra={"provider": "local", "api_key_id": value},
        )
        return value


class AuthContextFactory:
    """Factory for creating the appropriate auth context provider."""

    _providers = {
        CloudProvider.AWS: AWSAuthContextProvider,
        CloudProvider.GCP: GCPAuthContextProvider,
        CloudProvider.AZURE: AzureAuthContextProvider,
        CloudProvider.LOCAL: LocalAuthContextProvider,
    }

    @classmethod
    def get_provider(cls, cloud: str) -> AuthContextProvider:
        """Get the auth context provider for the given cloud.

        Args:
            cloud: Cloud provider name (aws, gcp, azure, local).

        Returns:
            An AuthContextProvider instance.
        """
        try:
            provider_enum = CloudProvider(cloud.lower())
        except ValueError:
            provider_enum = CloudProvider.LOCAL
        return cls._providers[provider_enum]()
