"""Taproot shared configuration."""

from pydantic_settings import BaseSettings


class TaprootSettings(BaseSettings):
    """Shared settings for Taproot services.

    All fields are configurable via environment variables with the TAPROOT_ prefix.
    Example: TAPROOT_CLOUD_PROVIDER=aws
    """

    cloud_provider: str = "local"  # aws, gcp, azure, local
    metadata_backend: str = "memory"  # dynamodb, memory
    metadata_table_name: str = "taproot-api-key-metadata"
    metadata_cache_ttl: int = 300  # seconds

    model_config = {"env_prefix": "TAPROOT_"}
