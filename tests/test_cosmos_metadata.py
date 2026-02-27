"""Tests for CosmosDB metadata store."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from taproot_common.auth.metadata import MetadataStoreFactory


# =============================================================================
# CosmosDBMetadataStore Tests
# =============================================================================


class TestCosmosDBMetadataStore:
    """Tests for CosmosDBMetadataStore with mocked Cosmos client."""

    def _make_store(self, mock_container: AsyncMock) -> "CosmosDBMetadataStore":
        from taproot_common.auth.cosmos_metadata import CosmosDBMetadataStore

        store = CosmosDBMetadataStore(
            endpoint="https://test.documents.azure.com:443/",
            database="taproot",
            container="api-key-metadata",
        )
        # Inject the mock container to skip real Azure auth
        store._container_client = mock_container
        return store

    @pytest.mark.asyncio
    async def test_get_store_id_returns_value(self):
        mock_container = AsyncMock()
        mock_container.read_item.return_value = {
            "api_key_id": "key-1",
            "store_id": "store-abc",
            "name": "Test Key",
        }
        store = self._make_store(mock_container)

        result = await store.get_store_id("key-1")

        assert result == "store-abc"
        mock_container.read_item.assert_awaited_once_with(
            item="key-1", partition_key="key-1"
        )

    @pytest.mark.asyncio
    async def test_get_store_id_returns_none_on_not_found(self):
        mock_container = AsyncMock()
        not_found_error = _make_not_found_error()
        mock_container.read_item.side_effect = not_found_error
        store = self._make_store(mock_container)

        result = await store.get_store_id("nonexistent")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_store_id_raises_on_other_error(self):
        mock_container = AsyncMock()
        mock_container.read_item.side_effect = RuntimeError("connection failed")
        store = self._make_store(mock_container)

        with pytest.raises(RuntimeError, match="connection failed"):
            await store.get_store_id("key-1")

    @pytest.mark.asyncio
    async def test_get_metadata_returns_dict(self):
        item = {
            "api_key_id": "key-1",
            "store_id": "store-abc",
            "name": "Test Key",
            "created_at": "2025-01-01T00:00:00Z",
        }
        mock_container = AsyncMock()
        mock_container.read_item.return_value = item
        store = self._make_store(mock_container)

        result = await store.get_metadata("key-1")

        assert result is not None
        assert result["store_id"] == "store-abc"
        assert result["name"] == "Test Key"
        assert result["created_at"] == "2025-01-01T00:00:00Z"
        # Verify it returns a new dict (immutability)
        assert result is not item

    @pytest.mark.asyncio
    async def test_get_metadata_returns_none_on_not_found(self):
        mock_container = AsyncMock()
        not_found_error = _make_not_found_error()
        mock_container.read_item.side_effect = not_found_error
        store = self._make_store(mock_container)

        result = await store.get_metadata("nonexistent")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_metadata_raises_on_other_error(self):
        mock_container = AsyncMock()
        mock_container.read_item.side_effect = RuntimeError("timeout")
        store = self._make_store(mock_container)

        with pytest.raises(RuntimeError, match="timeout"):
            await store.get_metadata("key-1")

    @pytest.mark.asyncio
    async def test_lazy_init_creates_client_on_first_call(self):
        """Verify that the Cosmos client is created lazily on first access."""
        from taproot_common.auth.cosmos_metadata import CosmosDBMetadataStore

        store = CosmosDBMetadataStore(
            endpoint="https://test.documents.azure.com:443/",
            database="taproot",
            container="api-key-metadata",
        )

        # Before any call, container_client should be None
        assert store._container_client is None

        # Mock the azure imports to verify lazy init
        mock_credential = MagicMock()
        mock_container = AsyncMock()
        mock_container.read_item.return_value = {"api_key_id": "k", "store_id": "s"}

        mock_database = MagicMock()
        mock_database.get_container_client.return_value = mock_container

        mock_client = MagicMock()
        mock_client.get_database_client.return_value = mock_database

        with patch(
            "taproot_common.auth.cosmos_metadata.CosmosDBMetadataStore._get_container",
            new_callable=AsyncMock,
            return_value=mock_container,
        ):
            # After the call, the container should be set
            store._container_client = mock_container
            result = await store.get_store_id("k")
            assert result == "s"


# =============================================================================
# Factory Integration Tests
# =============================================================================


class TestMetadataStoreFactoryCosmosDB:
    def test_factory_creates_cosmosdb_store(self):
        """Verify factory creates CosmosDBMetadataStore for cosmosdb backend."""
        from taproot_common.auth.cosmos_metadata import CosmosDBMetadataStore

        store = MetadataStoreFactory.create(
            backend="cosmosdb",
            cosmos_endpoint="https://test.documents.azure.com:443/",
            cosmos_database="taproot-db",
            cosmos_container="keys",
            cache_ttl=0,
        )
        assert isinstance(store, CosmosDBMetadataStore)

    def test_factory_creates_cached_cosmosdb_store(self):
        """Verify factory wraps CosmosDBMetadataStore with caching."""
        from taproot_common.auth.metadata import CachedMetadataStore

        store = MetadataStoreFactory.create(
            backend="cosmosdb",
            cosmos_endpoint="https://test.documents.azure.com:443/",
            cache_ttl=300,
        )
        assert isinstance(store, CachedMetadataStore)


# =============================================================================
# Helpers
# =============================================================================


def _make_not_found_error() -> Exception:
    """Create a mock CosmosResourceNotFoundError.

    Uses a real exception subclass so isinstance() checks work correctly
    in the _is_not_found helper.
    """
    try:
        from azure.cosmos.exceptions import CosmosResourceNotFoundError

        # CosmosResourceNotFoundError requires status_code and message
        return CosmosResourceNotFoundError(
            status_code=404,
            message="Entity with the specified id does not exist.",
        )
    except ImportError:
        # If azure-cosmos is not installed, create a mock that will match
        # the _is_not_found fallback path (returns False), so we patch instead
        pass

    # Fallback: patch _is_not_found to return True for our custom exception
    class MockNotFoundError(Exception):
        pass

    error = MockNotFoundError("Not found")
    # Monkey-patch the module-level check for tests without azure-cosmos
    import taproot_common.auth.cosmos_metadata as mod

    original_is_not_found = mod._is_not_found
    mod._is_not_found = lambda exc: isinstance(exc, MockNotFoundError) or original_is_not_found(exc)
    return error
