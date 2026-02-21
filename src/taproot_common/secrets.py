"""Multi-cloud secret manager integration for Taproot microservices.

Provides cloud-agnostic secret loading from AWS Secrets Manager, GCP Secret Manager,
and Azure Key Vault. Services import this module and call load_secrets_to_env() with
their own secret-to-env-var mappings at startup.

Usage (in a service's main.py or settings.py):
    from taproot_common.secrets import load_secrets_to_env

    # Service-specific mappings
    SECRETS = {
        SecretNames.OPENAI_API_KEY: "OPENAI_API_KEY",
        "taproot-myservice-db-password": "DATABASE_PASSWORD",
    }

    load_secrets_to_env(SECRETS)

Environment variables:
    - TAPROOT_SECRETS_ENABLED=true   (enable secret loading)
    - TAPROOT_CLOUD_PROVIDER=aws|gcp|azure|local
    - AWS_REGION or AWS_DEFAULT_REGION (for AWS)
    - GCP_PROJECT_ID or GOOGLE_CLOUD_PROJECT (for GCP)
    - AZURE_KEY_VAULT_URL (for Azure)
"""

import json
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)


# =============================================================================
# Standard Secret Names (taproot-* naming convention)
# =============================================================================


class SecretNames:
    """Standard secret names shared across Taproot services.

    Services should reference these constants instead of hardcoding names.
    All secrets follow the pattern: taproot-{scope}-{credential}

    Shared secrets (used by multiple services):
        taproot-openai-api-key
        taproot-anthropic-api-key
        taproot-azure-openai-api-key
        taproot-cohere-api-key
        taproot-google-api-key

    Service-specific secrets follow: taproot-{service}-{credential}
        taproot-retrieval-db-password
        taproot-evals-db-password
        taproot-fronts-db-password
    """

    # LLM provider keys (shared across services)
    OPENAI_API_KEY = "taproot-openai-api-key"
    ANTHROPIC_API_KEY = "taproot-anthropic-api-key"
    AZURE_OPENAI_API_KEY = "taproot-azure-openai-api-key"
    COHERE_API_KEY = "taproot-cohere-api-key"
    GOOGLE_API_KEY = "taproot-google-api-key"

    # AWS credentials (shared)
    AWS_ACCESS_KEY_ID = "taproot-aws-access-key-id"
    AWS_SECRET_ACCESS_KEY = "taproot-aws-secret-access-key"

    # Service-specific database passwords
    RETRIEVAL_DB_PASSWORD = "taproot-retrieval-db-password"
    EVALS_DB_PASSWORD = "taproot-evals-db-password"
    FRONTS_DB_PASSWORD = "taproot-fronts-db-password"
    PROMPT_S_DB_PASSWORD = "taproot-prompt-s-db-password"

    # Retrieval-S specific
    RETRIEVAL_API_KEY = "taproot-retrieval-api-key"
    RETRIEVAL_AZURE_BLOB_KEY = "taproot-retrieval-azure-blob-key"
    RETRIEVAL_SERVICE_BUS_CONN = "taproot-retrieval-service-bus-conn"
    RETRIEVAL_SHAREPOINT_SECRET = "taproot-retrieval-sharepoint-secret"

    # Front-S auth provider secrets
    FRONTS_AZURE_CLIENT_SECRET = "taproot-fronts-azure-client-secret"
    FRONTS_OKTA_CLIENT_SECRET = "taproot-fronts-okta-client-secret"


# =============================================================================
# Cloud-Specific Secret Loaders
# =============================================================================


def load_secret_from_aws(secret_name: str) -> Optional[str]:
    """Load a secret from AWS Secrets Manager."""
    try:
        import boto3
        from botocore.exceptions import ClientError

        region = os.environ.get("AWS_REGION") or os.environ.get(
            "AWS_DEFAULT_REGION", "us-east-1"
        )
        client = boto3.client("secretsmanager", region_name=region)
        response = client.get_secret_value(SecretId=secret_name)
        secret_value = response.get("SecretString")

        if secret_value:
            try:
                parsed = json.loads(secret_value)
                if isinstance(parsed, dict) and len(parsed) == 1:
                    return list(parsed.values())[0]
                elif isinstance(parsed, dict):
                    return json.dumps(parsed)
            except json.JSONDecodeError:
                pass
            return secret_value

    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code == "ResourceNotFoundException":
            logger.warning(f"Secret not found in AWS: {secret_name}")
        elif error_code == "AccessDeniedException":
            logger.error(f"Access denied to AWS secret: {secret_name}")
        else:
            logger.error(f"Error retrieving AWS secret {secret_name}: {e}")
    except ImportError:
        logger.error("boto3 not installed. Install with: pip install boto3")
    except Exception as e:
        logger.error(f"Unexpected error retrieving AWS secret {secret_name}: {e}")

    return None


def load_secret_from_gcp(
    secret_name: str, project_id: Optional[str] = None
) -> Optional[str]:
    """Load a secret from GCP Secret Manager."""
    try:
        from google.cloud import secretmanager

        client = secretmanager.SecretManagerServiceClient()
        project = (
            project_id
            or os.environ.get("GCP_PROJECT_ID")
            or os.environ.get("GOOGLE_CLOUD_PROJECT")
        )

        if not project:
            logger.warning(
                "GCP project ID not configured. Set GCP_PROJECT_ID environment variable."
            )
            return None

        name = f"projects/{project}/secrets/{secret_name}/versions/latest"
        response = client.access_secret_version(request={"name": name})
        return response.payload.data.decode("UTF-8")

    except ImportError:
        logger.error(
            "google-cloud-secret-manager not installed. "
            "Install with: pip install google-cloud-secret-manager"
        )
    except Exception as e:
        logger.warning(f"Failed to load secret '{secret_name}' from GCP: {e}")

    return None


def load_secret_from_azure(
    secret_name: str, vault_url: Optional[str] = None
) -> Optional[str]:
    """Load a secret from Azure Key Vault.

    Note: Azure Key Vault secret names cannot contain underscores.
    Use hyphens instead (e.g., taproot-retrieval-db-password).
    """
    try:
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.secrets import SecretClient

        vault = vault_url or os.environ.get("AZURE_KEY_VAULT_URL")

        if not vault:
            logger.warning(
                "Azure Key Vault URL not configured. "
                "Set AZURE_KEY_VAULT_URL environment variable."
            )
            return None

        credential = DefaultAzureCredential()
        client = SecretClient(vault_url=vault, credential=credential)
        secret = client.get_secret(secret_name)
        return secret.value

    except ImportError:
        logger.error(
            "azure-identity and azure-keyvault-secrets not installed. "
            "Install with: pip install azure-identity azure-keyvault-secrets"
        )
    except Exception as e:
        logger.warning(f"Failed to load secret '{secret_name}' from Azure: {e}")

    return None


# =============================================================================
# Unified Secret Loading
# =============================================================================


def get_cloud_provider() -> str:
    """Get the configured cloud provider from TAPROOT_CLOUD_PROVIDER.

    Falls back to service-specific env vars for backwards compatibility.
    """
    return (
        os.environ.get("TAPROOT_CLOUD_PROVIDER")
        or os.environ.get("RETRIEVAL_CLOUD_PROVIDER")
        or os.environ.get("FRONTS_CLOUD_PROVIDER")
        or "local"
    ).lower()


def is_secrets_enabled() -> bool:
    """Check if secret loading is enabled.

    Checks TAPROOT_SECRETS_ENABLED first, falls back to service-specific vars.
    """
    for var in (
        "TAPROOT_SECRETS_ENABLED",
        "RETRIEVAL_SECRETS_ENABLED",
        "FRONTS_SECRETS_ENABLED",
    ):
        val = os.environ.get(var, "").lower()
        if val in ("true", "1", "yes"):
            return True
    return False


def load_secret(secret_name: str) -> Optional[str]:
    """Load a single secret from the configured cloud provider.

    Args:
        secret_name: The secret name in the cloud secret manager.

    Returns:
        The secret value, or None if not found or loading failed.
    """
    provider = get_cloud_provider()

    if provider == "aws":
        return load_secret_from_aws(secret_name)
    elif provider == "gcp":
        return load_secret_from_gcp(secret_name)
    elif provider == "azure":
        return load_secret_from_azure(secret_name)
    elif provider == "local":
        logger.debug(f"Local mode - skipping secret loading for {secret_name}")
        return None
    else:
        logger.warning(f"Unknown cloud provider: {provider}")
        return None


def load_secrets_to_env(
    mappings: dict[str, str],
    *,
    critical_secrets: Optional[set[str]] = None,
) -> int:
    """Load secrets from cloud secret manager into environment variables.

    Call this before initializing Pydantic settings so secrets are available
    as environment variables.

    Args:
        mappings: Dict of {secret_name: env_var_name}. Each secret found in
            the cloud provider will be set as the corresponding env var.
        critical_secrets: Optional set of secret names that should emit
            warnings if not found. Defaults to None (no warnings).

    Returns:
        Number of secrets successfully loaded.
    """
    if not is_secrets_enabled():
        logger.debug(
            "Secret manager integration disabled "
            "(set TAPROOT_SECRETS_ENABLED=true to enable)"
        )
        return 0

    provider = get_cloud_provider()
    if provider == "local":
        logger.info("Local mode - secrets will be read from environment variables only")
        return 0

    logger.info(f"Loading secrets from {provider.upper()} secret manager...")

    loaded_count = 0
    for secret_name, env_var in mappings.items():
        if os.environ.get(env_var):
            logger.debug(f"Skipping {env_var} - already set in environment")
            continue

        secret_value = load_secret(secret_name)
        if secret_value:
            os.environ[env_var] = secret_value
            loaded_count += 1
            logger.info(f"Loaded {env_var} from secret manager")
        elif critical_secrets and secret_name in critical_secrets:
            logger.warning(f"Could not load critical secret '{secret_name}' for {env_var}")

    logger.info(f"Loaded {loaded_count} secrets from {provider.upper()} secret manager")
    return loaded_count
