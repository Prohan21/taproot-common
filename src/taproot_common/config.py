"""Taproot shared configuration."""

from pydantic_settings import BaseSettings


class TaprootSettings(BaseSettings):
    """Shared settings for Taproot services.

    All fields are configurable via environment variables with the TAPROOT_ prefix.
    Example: TAPROOT_CLOUD_PROVIDER=aws
    """

    cloud_provider: str = "local"  # aws, gcp, azure, local
    metadata_backend: str = "memory"  # dynamodb, cosmosdb, memory
    metadata_table_name: str = "taproot-api-key-metadata"
    metadata_cache_ttl: int = 300  # seconds

    # Azure Cosmos DB settings (used when metadata_backend=cosmosdb)
    cosmos_endpoint: str = ""
    cosmos_database: str = "taproot"
    cosmos_container: str = "api-key-metadata"

    model_config = {"env_prefix": "TAPROOT_"}
