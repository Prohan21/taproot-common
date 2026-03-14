"""Metadata store for mapping API key IDs to store/tenant IDs."""

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class MetadataStore(ABC):
    """Abstract base for API key metadata lookup."""

    @abstractmethod
    async def get_store_id(self, api_key_id: str) -> Optional[str]:
        """Look up the store_id for a given API key ID.

        Args:
            api_key_id: The API key identifier from the gateway.

        Returns:
            The store_id string, or None if not found.
        """

    @abstractmethod
    async def get_metadata(self, api_key_id: str) -> Optional[Dict[str, Any]]:
        """Look up full metadata for a given API key ID.

        Args:
            api_key_id: The API key identifier from the gateway.

        Returns:
            A dict of metadata, or None if not found.
        """


class DynamoDBMetadataStore(MetadataStore):
    """DynamoDB-backed metadata store.

    Table schema:
        - Partition key: api_key_id (S)
        - Attributes: store_id (S), name (S), created_at (S)
        - GSI: store_id-index on store_id
    """

    def __init__(self, table_name: str) -> None:
        import boto3

        self._table = boto3.resource("dynamodb").Table(table_name)

    def _sync_get_item(self, api_key_id: str) -> dict:
        """Synchronous DynamoDB get_item call, intended to run via asyncio.to_thread()."""
        return self._table.get_item(Key={"api_key_id": api_key_id})

    async def get_store_id(self, api_key_id: str) -> Optional[str]:
        logger.info("auth.metadata.dynamodb.lookup", extra={"api_key_id": api_key_id})
        try:
            response = await asyncio.to_thread(self._sync_get_item, api_key_id)
        except Exception as e:
            logger.error(
                "auth.metadata.dynamodb.error",
                extra={"api_key_id": api_key_id, "error": str(e)},
            )
            raise
        item = response.get("Item")
        if not item:
            logger.warning("auth.metadata.dynamodb.not_found", extra={"api_key_id": api_key_id})
            return None
        logger.info("auth.metadata.dynamodb.found", extra={"api_key_id": api_key_id})
        return item.get("store_id")

    async def get_metadata(self, api_key_id: str) -> Optional[Dict[str, Any]]:
        logger.info("auth.metadata.dynamodb.lookup", extra={"api_key_id": api_key_id})
        try:
            response = await asyncio.to_thread(self._sync_get_item, api_key_id)
        except Exception as e:
            logger.error(
                "auth.metadata.dynamodb.error",
                extra={"api_key_id": api_key_id, "error": str(e)},
            )
            raise
        item = response.get("Item")
        if item:
            logger.info("auth.metadata.dynamodb.found", extra={"api_key_id": api_key_id})
            return dict(item)
        logger.warning("auth.metadata.dynamodb.not_found", extra={"api_key_id": api_key_id})
        return None


class InMemoryMetadataStore(MetadataStore):
    """In-memory metadata store for local development and testing."""

    def __init__(self) -> None:
        self._data: Dict[str, Dict[str, Any]] = {}

    def add(self, api_key_id: str, store_id: str, **extra: Any) -> None:
        """Add a metadata entry (for testing/local dev)."""
        self._data[api_key_id] = {"api_key_id": api_key_id, "store_id": store_id, **extra}

    async def get_store_id(self, api_key_id: str) -> Optional[str]:
        entry = self._data.get(api_key_id)
        return entry["store_id"] if entry else None

    async def get_metadata(self, api_key_id: str) -> Optional[Dict[str, Any]]:
        return self._data.get(api_key_id)


class CachedMetadataStore(MetadataStore):
    """TTL-caching wrapper around any MetadataStore."""

    def __init__(self, inner: MetadataStore, ttl_seconds: int = 300) -> None:
        self._inner = inner
        self._ttl = ttl_seconds
        self._cache: Dict[str, tuple] = {}  # key -> (value, expiry_time)

    def _get_cached(self, key: str) -> Optional[Any]:
        if key in self._cache:
            value, expiry = self._cache[key]
            if time.monotonic() < expiry:
                logger.debug("auth.metadata.cache_hit", extra={"api_key_id": key})
                return value
            logger.debug("auth.metadata.cache_expired", extra={"api_key_id": key})
            del self._cache[key]
        else:
            logger.debug("auth.metadata.cache_miss", extra={"api_key_id": key})
        return None

    def _set_cached(self, key: str, value: Any) -> None:
        self._cache[key] = (value, time.monotonic() + self._ttl)

    async def get_store_id(self, api_key_id: str) -> Optional[str]:
        cache_key = f"store_id:{api_key_id}"
        cached = self._get_cached(cache_key)
        if cached is not None:
            return cached

        result = await self._inner.get_store_id(api_key_id)
        if result is not None:
            self._set_cached(cache_key, result)
        return result

    async def get_metadata(self, api_key_id: str) -> Optional[Dict[str, Any]]:
        cache_key = f"metadata:{api_key_id}"
        cached = self._get_cached(cache_key)
        if cached is not None:
            return cached

        result = await self._inner.get_metadata(api_key_id)
        if result is not None:
            self._set_cached(cache_key, result)
        return result


class MetadataStoreFactory:
    """Factory for creating metadata store instances."""

    @classmethod
    def create(
        cls,
        backend: str = "memory",
        table_name: str = "taproot-api-key-metadata",
        cache_ttl: int = 300,
        cosmos_endpoint: str = "",
        cosmos_database: str = "taproot",
        cosmos_container: str = "api-key-metadata",
        firestore_project_id: str = "",
        firestore_database: str = "(default)",
        firestore_collection: str = "api-key-metadata",
    ) -> MetadataStore:
        """Create a metadata store instance.

        Args:
            backend: Store backend type (dynamodb, cosmosdb, firestore, memory).
            table_name: DynamoDB table name (only for dynamodb backend).
            cache_ttl: Cache TTL in seconds. 0 disables caching.
            cosmos_endpoint: Cosmos DB account endpoint (only for cosmosdb backend).
            cosmos_database: Cosmos DB database name (only for cosmosdb backend).
            cosmos_container: Cosmos DB container name (only for cosmosdb backend).
            firestore_project_id: GCP project ID (only for firestore backend).
            firestore_database: Firestore database name (only for firestore backend).
            firestore_collection: Firestore collection name (only for firestore backend).

        Returns:
            A MetadataStore instance, optionally wrapped with caching.
        """
        logger.info("auth.metadata.factory.create", extra={"backend": backend})

        if backend == "dynamodb":
            store: MetadataStore = DynamoDBMetadataStore(table_name)
        elif backend == "cosmosdb":
            from taproot_common.auth.cosmos_metadata import CosmosDBMetadataStore

            store = CosmosDBMetadataStore(
                endpoint=cosmos_endpoint,
                database=cosmos_database,
                container=cosmos_container,
            )
        elif backend == "firestore":
            from taproot_common.auth.firestore_metadata import FirestoreMetadataStore

            store = FirestoreMetadataStore(
                project_id=firestore_project_id,
                database=firestore_database,
                collection=firestore_collection,
            )
        else:
            store = InMemoryMetadataStore()

        if cache_ttl > 0:
            store = CachedMetadataStore(store, ttl_seconds=cache_ttl)

        return store
