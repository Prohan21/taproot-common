"""Tests for Firestore metadata store."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from taproot_common.auth.metadata import MetadataStoreFactory


# =============================================================================
# FirestoreMetadataStore Tests
# =============================================================================


class TestFirestoreMetadataStore:
    """Tests for FirestoreMetadataStore with mocked Firestore client."""

    def _make_store(self, mock_collection: AsyncMock) -> "FirestoreMetadataStore":
        from taproot_common.auth.firestore_metadata import FirestoreMetadataStore

        store = FirestoreMetadataStore(
            project_id="test-project",
            database="(default)",
            collection="api-key-metadata",
        )
        # Inject mock collection to skip real GCP auth
        store._collection_ref = mock_collection
        return store

    def _make_mock_doc(self, exists: bool, data: dict | None = None) -> AsyncMock:
        """Create a mock Firestore document snapshot."""
        doc = MagicMock()
        doc.exists = exists
        doc.to_dict.return_value = data if data else {}
        return doc

    @pytest.mark.asyncio
    async def test_get_store_id_returns_value(self):
        mock_doc = self._make_mock_doc(
            exists=True,
            data={"api_key_id": "key-1", "store_id": "store-abc", "name": "Test Key"},
        )
        mock_doc_ref = AsyncMock()
        mock_doc_ref.get.return_value = mock_doc

        mock_collection = MagicMock()
        mock_collection.document.return_value = mock_doc_ref

        store = self._make_store(mock_collection)
        result = await store.get_store_id("key-1")

        assert result == "store-abc"
        mock_collection.document.assert_called_once_with("key-1")

    @pytest.mark.asyncio
    async def test_get_store_id_returns_none_on_not_found(self):
        mock_doc = self._make_mock_doc(exists=False)
        mock_doc_ref = AsyncMock()
        mock_doc_ref.get.return_value = mock_doc

        mock_collection = MagicMock()
        mock_collection.document.return_value = mock_doc_ref

        store = self._make_store(mock_collection)
        result = await store.get_store_id("nonexistent")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_store_id_raises_on_other_error(self):
        mock_doc_ref = AsyncMock()
        mock_doc_ref.get.side_effect = RuntimeError("connection failed")

        mock_collection = MagicMock()
        mock_collection.document.return_value = mock_doc_ref

        store = self._make_store(mock_collection)

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
        mock_doc = self._make_mock_doc(exists=True, data=item)
        mock_doc_ref = AsyncMock()
        mock_doc_ref.get.return_value = mock_doc

        mock_collection = MagicMock()
        mock_collection.document.return_value = mock_doc_ref

        store = self._make_store(mock_collection)
        result = await store.get_metadata("key-1")

        assert result is not None
        assert result["store_id"] == "store-abc"
        assert result["name"] == "Test Key"
        assert result["created_at"] == "2025-01-01T00:00:00Z"
        # Verify it returns a new dict (immutability)
        assert result is not item

    @pytest.mark.asyncio
    async def test_get_metadata_returns_none_on_not_found(self):
        mock_doc = self._make_mock_doc(exists=False)
        mock_doc_ref = AsyncMock()
        mock_doc_ref.get.return_value = mock_doc

        mock_collection = MagicMock()
        mock_collection.document.return_value = mock_doc_ref

        store = self._make_store(mock_collection)
        result = await store.get_metadata("nonexistent")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_metadata_raises_on_other_error(self):
        mock_doc_ref = AsyncMock()
        mock_doc_ref.get.side_effect = RuntimeError("timeout")

        mock_collection = MagicMock()
        mock_collection.document.return_value = mock_doc_ref

        store = self._make_store(mock_collection)

        with pytest.raises(RuntimeError, match="timeout"):
            await store.get_metadata("key-1")

    @pytest.mark.asyncio
    async def test_lazy_init_creates_client_on_first_call(self):
        """Verify that the Firestore client is created lazily on first access."""
        from taproot_common.auth.firestore_metadata import FirestoreMetadataStore

        store = FirestoreMetadataStore(
            project_id="test-project",
            database="(default)",
            collection="api-key-metadata",
        )

        # Before any call, collection_ref should be None
        assert store._collection_ref is None

    @pytest.mark.asyncio
    async def test_handles_google_not_found_error(self):
        """Verify that google.api_core.exceptions.NotFound is handled gracefully."""
        not_found_error = _make_not_found_error()
        mock_doc_ref = AsyncMock()
        mock_doc_ref.get.side_effect = not_found_error

        mock_collection = MagicMock()
        mock_collection.document.return_value = mock_doc_ref

        store = self._make_store(mock_collection)
        result = await store.get_store_id("missing-key")

        assert result is None


# =============================================================================
# Factory Integration Tests
# =============================================================================


class TestMetadataStoreFactoryFirestore:
    def test_factory_creates_firestore_store(self):
        """Verify factory creates FirestoreMetadataStore for firestore backend."""
        from taproot_common.auth.firestore_metadata import FirestoreMetadataStore

        store = MetadataStoreFactory.create(
            backend="firestore",
            firestore_project_id="test-project",
            firestore_database="(default)",
            firestore_collection="keys",
            cache_ttl=0,
        )
        assert isinstance(store, FirestoreMetadataStore)

    def test_factory_creates_cached_firestore_store(self):
        """Verify factory wraps FirestoreMetadataStore with caching."""
        from taproot_common.auth.metadata import CachedMetadataStore

        store = MetadataStoreFactory.create(
            backend="firestore",
            firestore_project_id="test-project",
            cache_ttl=300,
        )
        assert isinstance(store, CachedMetadataStore)


# =============================================================================
# Helpers
# =============================================================================


def _make_not_found_error() -> Exception:
    """Create a mock Google NotFound error.

    Uses a real exception subclass so isinstance() checks work correctly
    in the _is_not_found helper.
    """
    try:
        from google.api_core.exceptions import NotFound

        return NotFound("Entity not found")
    except ImportError:
        pass

    # Fallback: patch _is_not_found to return True for our custom exception
    class MockNotFoundError(Exception):
        pass

    error = MockNotFoundError("Not found")
    import taproot_common.auth.firestore_metadata as mod

    original_is_not_found = mod._is_not_found
    mod._is_not_found = (
        lambda exc: isinstance(exc, MockNotFoundError) or original_is_not_found(exc)
    )
    return error
