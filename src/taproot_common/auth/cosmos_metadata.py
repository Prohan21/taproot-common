"""Cosmos DB metadata store for API key ID to store/tenant ID mapping."""

import logging
from typing import Any, Dict, Optional

from taproot_common.auth.metadata import MetadataStore

logger = logging.getLogger(__name__)


class CosmosDBMetadataStore(MetadataStore):
    """Azure Cosmos DB-backed metadata store.

    Container schema:
        - Partition key: /api_key_id
        - Fields: api_key_id (str), store_id (str), name (str), created_at (str)

    Uses async Cosmos client with DefaultAzureCredential for AAD auth.
    The client is initialized lazily on first call to avoid blocking at import time.
    """

    def __init__(self, endpoint: str, database: str, container: str) -> None:
        self._endpoint = endpoint
        self._database_name = database
        self._container_name = container
        self._container_client: Any = None

    async def _get_container(self) -> Any:
        """Lazily initialize and return the Cosmos container client."""
        if self._container_client is None:
            from azure.cosmos.aio import CosmosClient
            from azure.identity.aio import DefaultAzureCredential

            credential = DefaultAzureCredential()
            client = CosmosClient(url=self._endpoint, credential=credential)
            database = client.get_database_client(self._database_name)
            self._container_client = database.get_container_client(self._container_name)
        return self._container_client

    async def get_store_id(self, api_key_id: str) -> Optional[str]:
        logger.info("auth.metadata.cosmosdb.lookup", extra={"api_key_id": api_key_id})
        try:
            container = await self._get_container()
            item = await container.read_item(item=api_key_id, partition_key=api_key_id)
        except Exception as e:
            if _is_not_found(e):
                logger.warning(
                    "auth.metadata.cosmosdb.not_found",
                    extra={"api_key_id": api_key_id},
                )
                return None
            logger.error(
                "auth.metadata.cosmosdb.error",
                extra={"api_key_id": api_key_id, "error": str(e)},
            )
            raise
        logger.info("auth.metadata.cosmosdb.found", extra={"api_key_id": api_key_id})
        return item.get("store_id")

    async def get_metadata(self, api_key_id: str) -> Optional[Dict[str, Any]]:
        logger.info("auth.metadata.cosmosdb.lookup", extra={"api_key_id": api_key_id})
        try:
            container = await self._get_container()
            item = await container.read_item(item=api_key_id, partition_key=api_key_id)
        except Exception as e:
            if _is_not_found(e):
                logger.warning(
                    "auth.metadata.cosmosdb.not_found",
                    extra={"api_key_id": api_key_id},
                )
                return None
            logger.error(
                "auth.metadata.cosmosdb.error",
                extra={"api_key_id": api_key_id, "error": str(e)},
            )
            raise
        logger.info("auth.metadata.cosmosdb.found", extra={"api_key_id": api_key_id})
        return dict(item)


def _is_not_found(exc: Exception) -> bool:
    """Check if an exception is a Cosmos DB 'not found' error."""
    try:
        from azure.cosmos.exceptions import CosmosResourceNotFoundError

        return isinstance(exc, CosmosResourceNotFoundError)
    except ImportError:
        return False
