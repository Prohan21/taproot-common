"""Taproot shared configuration."""

from pydantic_settings import BaseSettings


class TaprootSettings(BaseSettings):
    """Shared settings for Taproot services.

    All fields are configurable via environment variables with the TAPROOT_ prefix.
    Example: TAPROOT_CLOUD_PROVIDER=aws
    """

    cloud_provider: str = "local"  # aws, gcp, azure, local
    environment: str = "dev"  # dev, staging, production
    # Gateway shared-secret proof (WO-012 T1b): off, observe, enforce.
    # Expected value is read from the cloud secret manager under
    # taproot-<environment>-gateway-shared-secret, never from env.
    gateway_proof_mode: str = "observe"
    metadata_backend: str = "memory"  # dynamodb, cosmosdb, firestore, memory
    metadata_table_name: str = "taproot-api-key-metadata"
    metadata_cache_ttl: int = 300  # seconds

    # Azure Cosmos DB settings (used when metadata_backend=cosmosdb)
    cosmos_endpoint: str = ""
    cosmos_database: str = "taproot"
    cosmos_container: str = "api-key-metadata"

    # GCP Firestore settings (used when metadata_backend=firestore)
    firestore_project_id: str = ""
    firestore_database: str = "(default)"
    firestore_collection: str = "api-key-metadata"

    model_config = {"env_prefix": "TAPROOT_"}
