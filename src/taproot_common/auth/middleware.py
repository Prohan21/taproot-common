"""FastAPI dependency for API Gateway authentication."""

from functools import lru_cache
from typing import Annotated, Optional

from fastapi import Depends, HTTPException, Request, status

from taproot_common.auth.metadata import MetadataStore, MetadataStoreFactory
from taproot_common.auth.models import AuthContext
from taproot_common.auth.provider import AuthContextFactory, MissingHeaderError
from taproot_common.config import TaprootSettings


@lru_cache
def _get_settings() -> TaprootSettings:
    return TaprootSettings()


_metadata_store: Optional[MetadataStore] = None


def get_metadata_store() -> MetadataStore:
    """Get or create the singleton metadata store."""
    global _metadata_store
    if _metadata_store is None:
        settings = _get_settings()
        _metadata_store = MetadataStoreFactory.create(
            backend=settings.metadata_backend,
            table_name=settings.metadata_table_name,
            cache_ttl=settings.metadata_cache_ttl,
        )
    return _metadata_store


def reset_metadata_store() -> None:
    """Reset the singleton metadata store (for testing)."""
    global _metadata_store
    _metadata_store = None
    _get_settings.cache_clear()


async def get_auth_context(request: Request) -> AuthContext:
    """FastAPI dependency that extracts and resolves auth context.

    1. Reads cloud provider from settings.
    2. Uses the appropriate provider to extract the API key ID from headers.
    3. Looks up store_id from the metadata store.
    4. Returns an AuthContext with all resolved information.

    Raises:
        HTTPException 401: If the identity header is missing (non-local).
        HTTPException 403: If the API key ID is not found in metadata.
    """
    settings = _get_settings()
    provider = AuthContextFactory.get_provider(settings.cloud_provider)

    # Convert headers to a simple lowercase dict
    headers = {k.lower(): v for k, v in request.headers.items()}

    try:
        api_key_id = provider.extract_key_id(headers)
    except MissingHeaderError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key identity header",
        )

    # Look up metadata
    store = get_metadata_store()
    metadata = await store.get_metadata(api_key_id)
    store_id = metadata.get("store_id") if metadata else None
    project_id = metadata.get("project_id") if metadata else None

    return AuthContext(
        api_key_id=api_key_id,
        store_id=store_id,
        project_id=project_id,
        provider=provider.provider,
        metadata=metadata or {},
    )


# Type alias for use as a FastAPI dependency
ApimAuth = Annotated[AuthContext, Depends(get_auth_context)]
