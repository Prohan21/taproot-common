"""Tests for taproot-common auth module."""

import base64
import json
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from taproot_common.auth.metadata import (
    CachedMetadataStore,
    InMemoryMetadataStore,
    MetadataStoreFactory,
)
from taproot_common.auth.middleware import ApimAuth, get_auth_context, reset_metadata_store
from taproot_common.auth.models import AuthContext, CloudProvider
from taproot_common.auth.provider import (
    AWSAuthContextProvider,
    AzureAuthContextProvider,
    AuthContextFactory,
    GCPAuthContextProvider,
    LocalAuthContextProvider,
    MissingHeaderError,
)


# =============================================================================
# Provider Tests
# =============================================================================


class TestAWSProvider:
    def test_extracts_key_id(self):
        provider = AWSAuthContextProvider()
        key_id = provider.extract_key_id({"x-api-key-id": "abc123"})
        assert key_id == "abc123"

    def test_raises_on_missing_header(self):
        provider = AWSAuthContextProvider()
        with pytest.raises(MissingHeaderError, match="X-Api-Key-Id"):
            provider.extract_key_id({})

    def test_raises_on_empty_header(self):
        provider = AWSAuthContextProvider()
        with pytest.raises(MissingHeaderError):
            provider.extract_key_id({"x-api-key-id": ""})


class TestGCPProvider:
    def test_extracts_key_id_from_base64(self):
        provider = GCPAuthContextProvider()
        payload = {"api_key_id": "gcp-key-123", "email": "test@example.com"}
        encoded = base64.b64encode(json.dumps(payload).encode()).decode()
        key_id = provider.extract_key_id({"x-endpoint-api-userinfo": encoded})
        assert key_id == "gcp-key-123"

    def test_falls_back_to_sub_claim(self):
        provider = GCPAuthContextProvider()
        payload = {"sub": "sub-456"}
        encoded = base64.b64encode(json.dumps(payload).encode()).decode()
        key_id = provider.extract_key_id({"x-endpoint-api-userinfo": encoded})
        assert key_id == "sub-456"

    def test_raises_on_missing_header(self):
        provider = GCPAuthContextProvider()
        with pytest.raises(MissingHeaderError):
            provider.extract_key_id({})

    def test_raises_on_invalid_base64(self):
        provider = GCPAuthContextProvider()
        with pytest.raises(MissingHeaderError, match="decode error"):
            provider.extract_key_id({"x-endpoint-api-userinfo": "not-valid-base64!!!"})


class TestAzureProvider:
    def test_extracts_key_id(self):
        provider = AzureAuthContextProvider()
        key_id = provider.extract_key_id({"x-api-key-id": "azure-key-789"})
        assert key_id == "azure-key-789"

    def test_raises_on_missing_header(self):
        provider = AzureAuthContextProvider()
        with pytest.raises(MissingHeaderError):
            provider.extract_key_id({})


class TestLocalProvider:
    def test_returns_header_if_present(self):
        provider = LocalAuthContextProvider()
        key_id = provider.extract_key_id({"x-api-key-id": "custom-key"})
        assert key_id == "custom-key"

    def test_returns_default_if_absent(self):
        provider = LocalAuthContextProvider()
        key_id = provider.extract_key_id({})
        assert key_id == "local-dev-key"


class TestAuthContextFactory:
    def test_returns_aws_provider(self):
        provider = AuthContextFactory.get_provider("aws")
        assert isinstance(provider, AWSAuthContextProvider)

    def test_returns_gcp_provider(self):
        provider = AuthContextFactory.get_provider("gcp")
        assert isinstance(provider, GCPAuthContextProvider)

    def test_returns_azure_provider(self):
        provider = AuthContextFactory.get_provider("azure")
        assert isinstance(provider, AzureAuthContextProvider)

    def test_returns_local_provider(self):
        provider = AuthContextFactory.get_provider("local")
        assert isinstance(provider, LocalAuthContextProvider)

    def test_defaults_to_local_for_unknown(self):
        provider = AuthContextFactory.get_provider("unknown")
        assert isinstance(provider, LocalAuthContextProvider)

    def test_case_insensitive(self):
        provider = AuthContextFactory.get_provider("AWS")
        assert isinstance(provider, AWSAuthContextProvider)


# =============================================================================
# Metadata Store Tests
# =============================================================================


class TestInMemoryMetadataStore:
    @pytest.mark.asyncio
    async def test_add_and_get_store_id(self):
        store = InMemoryMetadataStore()
        store.add("key-1", "store-1", name="Test Key")
        assert await store.get_store_id("key-1") == "store-1"

    @pytest.mark.asyncio
    async def test_returns_none_for_unknown_key(self):
        store = InMemoryMetadataStore()
        assert await store.get_store_id("nonexistent") is None

    @pytest.mark.asyncio
    async def test_get_metadata(self):
        store = InMemoryMetadataStore()
        store.add("key-1", "store-1", name="Test Key")
        meta = await store.get_metadata("key-1")
        assert meta is not None
        assert meta["store_id"] == "store-1"
        assert meta["name"] == "Test Key"

    @pytest.mark.asyncio
    async def test_get_metadata_returns_none(self):
        store = InMemoryMetadataStore()
        assert await store.get_metadata("nonexistent") is None


class TestCachedMetadataStore:
    @pytest.mark.asyncio
    async def test_caches_results(self):
        inner = InMemoryMetadataStore()
        inner.add("key-1", "store-1")
        cached = CachedMetadataStore(inner, ttl_seconds=60)

        # First call populates cache
        result1 = await cached.get_store_id("key-1")
        assert result1 == "store-1"

        # Remove from inner store
        inner._data.clear()

        # Should still return cached value
        result2 = await cached.get_store_id("key-1")
        assert result2 == "store-1"

    @pytest.mark.asyncio
    async def test_cache_expires(self):
        inner = InMemoryMetadataStore()
        inner.add("key-1", "store-1")
        cached = CachedMetadataStore(inner, ttl_seconds=0)

        # Manually set an expired entry
        cached._cache["store_id:key-1"] = ("store-1", time.monotonic() - 1)

        # Remove from inner
        inner._data.clear()

        # Should return None since cache expired and inner is empty
        result = await cached.get_store_id("key-1")
        assert result is None


class TestMetadataStoreFactory:
    def test_creates_memory_store(self):
        store = MetadataStoreFactory.create(backend="memory", cache_ttl=0)
        assert isinstance(store, InMemoryMetadataStore)

    def test_creates_cached_memory_store(self):
        store = MetadataStoreFactory.create(backend="memory", cache_ttl=300)
        assert isinstance(store, CachedMetadataStore)


# =============================================================================
# Middleware Integration Tests
# =============================================================================


class TestMiddlewareIntegration:
    """Integration tests using FastAPI TestClient."""

    def _create_app(self) -> FastAPI:
        app = FastAPI()

        @app.get("/protected")
        async def protected_endpoint(auth: ApimAuth):
            return {
                "api_key_id": auth.api_key_id,
                "store_id": auth.store_id,
                "provider": auth.provider.value,
            }

        return app

    def setup_method(self):
        """Reset singletons between tests."""
        import os

        reset_metadata_store()
        # Set to local provider for testing
        os.environ["TAPROOT_CLOUD_PROVIDER"] = "local"
        os.environ["TAPROOT_METADATA_BACKEND"] = "memory"

    def teardown_method(self):
        import os

        reset_metadata_store()
        os.environ.pop("TAPROOT_CLOUD_PROVIDER", None)
        os.environ.pop("TAPROOT_METADATA_BACKEND", None)

    def test_local_provider_with_header(self):
        app = self._create_app()
        client = TestClient(app)
        response = client.get("/protected", headers={"X-Api-Key-Id": "test-key-123"})
        assert response.status_code == 200
        data = response.json()
        assert data["api_key_id"] == "test-key-123"
        assert data["provider"] == "local"

    def test_local_provider_without_header(self):
        app = self._create_app()
        client = TestClient(app)
        response = client.get("/protected")
        assert response.status_code == 200
        data = response.json()
        assert data["api_key_id"] == "local-dev-key"

    def test_aws_provider_missing_header_returns_401(self):
        import os

        os.environ["TAPROOT_CLOUD_PROVIDER"] = "aws"
        reset_metadata_store()

        app = self._create_app()
        client = TestClient(app)
        response = client.get("/protected")
        assert response.status_code == 401

    def test_aws_provider_with_header(self):
        import os

        os.environ["TAPROOT_CLOUD_PROVIDER"] = "aws"
        reset_metadata_store()

        app = self._create_app()
        client = TestClient(app)
        response = client.get("/protected", headers={"X-Api-Key-Id": "aws-key-456"})
        assert response.status_code == 200
        data = response.json()
        assert data["api_key_id"] == "aws-key-456"
        assert data["provider"] == "aws"
