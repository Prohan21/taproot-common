# CLAUDE.md - taproot-common

## Product Overview

taproot-common is the shared authentication middleware and configuration library used by all Taproot platform microservices. It provides:

- **API key authentication** via API Gateway-injected headers (AWS, Azure, GCP, local)
- **Metadata store** for mapping API key IDs to store/tenant/project identifiers (DynamoDB, Cosmos DB, Firestore, in-memory)
- **TTL-based caching** for metadata lookups (default 300s)
- **Multi-cloud secret loading** from AWS Secrets Manager, GCP Secret Manager, Azure Key Vault
- **Shared configuration** via Pydantic settings with `TAPROOT_` env prefix
- **Standardized error handlers** and **logging configuration** for FastAPI services

All Taproot backend services (Retrieval-S, Evals-S, Guardrail-S, Front-S, Prompt-S) depend on this library.

## Architecture

```
taproot-common/
  pyproject.toml              # Build config (hatchling), deps, optional extras
  uv.lock                     # Pinned dependency lock file
  src/taproot_common/
    __init__.py               # Public API exports
    config.py                 # TaprootSettings (Pydantic BaseSettings)
    errors.py                 # install_error_handlers() for FastAPI
    logging.py                # configure_logging() structured logging setup
    secrets.py                # Multi-cloud secret loading + SecretNames constants
    auth/
      __init__.py             # Re-exports ApimAuth, AuthContext, CloudProvider
      models.py               # AuthContext dataclass, CloudProvider enum
      provider.py             # Cloud-specific header extraction (4 providers + factory)
      middleware.py            # FastAPI dependency (get_auth_context, ApimAuth)
      metadata.py             # MetadataStore ABC, DynamoDB, InMemory, Cached, Factory
      cosmos_metadata.py      # CosmosDBMetadataStore (Azure optional)
      firestore_metadata.py   # FirestoreMetadataStore (GCP optional)
  tests/
    test_auth.py              # Provider, metadata store, middleware integration tests
    test_cosmos_metadata.py   # CosmosDB store tests with mocked Azure client
    test_firestore_metadata.py # Firestore store tests with mocked GCP client
```

## Public API

All public exports are defined in `src/taproot_common/__init__.py`:

```python
from taproot_common import (
    ApimAuth,           # Annotated[AuthContext, Depends(get_auth_context)] - FastAPI dependency
    AuthContext,        # Dataclass with api_key_id, store_id, project_id, provider, metadata
    TaprootSettings,    # Pydantic BaseSettings with TAPROOT_ prefix
    SecretNames,        # Constants for standard secret names (DB_PASSWORD, OPENAI_API_KEY, etc.)
    is_secrets_enabled, # Check if TAPROOT_SECRETS_ENABLED=true
    load_secret,        # Load single secret from configured cloud provider
    load_secrets_to_env,# Load multiple secrets into environment variables
)
```

Additional imports available from submodules:

```python
from taproot_common.auth import CloudProvider, get_auth_context
from taproot_common.auth.middleware import reset_metadata_store, get_metadata_store
from taproot_common.auth.metadata import (
    MetadataStore,          # ABC interface
    MetadataStoreFactory,   # Factory with create() classmethod
    DynamoDBMetadataStore,  # AWS implementation
    InMemoryMetadataStore,  # Local/test implementation
    CachedMetadataStore,    # TTL wrapper
)
from taproot_common.auth.cosmos_metadata import CosmosDBMetadataStore  # Azure implementation
from taproot_common.auth.firestore_metadata import FirestoreMetadataStore  # GCP implementation
from taproot_common.auth.provider import (
    AuthContextProvider,        # ABC for header extraction
    AuthContextFactory,         # Factory: get_provider(cloud_name) -> AuthContextProvider
    AWSAuthContextProvider,     # Reads X-Api-Key-Id header
    AzureAuthContextProvider,   # Reads X-Api-Key-Id header
    GCPAuthContextProvider,     # Reads X-Endpoint-API-UserInfo (base64 JSON)
    LocalAuthContextProvider,   # Returns header value or "local-dev-key" default
    MissingHeaderError,         # Raised when expected header is absent
)
from taproot_common.auth.models import AuthContext, CloudProvider
from taproot_common.errors import install_error_handlers
from taproot_common.logging import configure_logging
```

## Features & Components

### TaprootSettings (`config.py`)

Pydantic `BaseSettings` subclass. All fields are set via environment variables with the `TAPROOT_` prefix.

| Env Var | Field | Default | Description |
|---------|-------|---------|-------------|
| `TAPROOT_CLOUD_PROVIDER` | `cloud_provider` | `"local"` | Cloud provider: `aws`, `azure`, `gcp`, `local` |
| `TAPROOT_METADATA_BACKEND` | `metadata_backend` | `"memory"` | Metadata store backend: `dynamodb`, `cosmosdb`, `firestore`, `memory` |
| `TAPROOT_METADATA_TABLE_NAME` | `metadata_table_name` | `"taproot-api-key-metadata"` | DynamoDB table name |
| `TAPROOT_METADATA_CACHE_TTL` | `metadata_cache_ttl` | `300` | Cache TTL in seconds (0 disables) |
| `TAPROOT_COSMOS_ENDPOINT` | `cosmos_endpoint` | `""` | Azure Cosmos DB endpoint URL |
| `TAPROOT_COSMOS_DATABASE` | `cosmos_database` | `"taproot"` | Cosmos DB database name |
| `TAPROOT_COSMOS_CONTAINER` | `cosmos_container` | `"api-key-metadata"` | Cosmos DB container name |

### AuthContext (`auth/models.py`)

Frozen dataclass carrying the resolved identity for a request:

| Field | Type | Description |
|-------|------|-------------|
| `api_key_id` | `str` | API key identifier from the gateway |
| `store_id` | `Optional[str]` | Store/tenant ID from metadata lookup |
| `project_id` | `Optional[str]` | Front-S project slug from metadata |
| `provider` | `CloudProvider` | Which cloud supplied the identity |
| `metadata` | `Dict[str, Any]` | Full metadata dict from the store |

Property: `is_admin` -- checks `metadata.get("is_admin")`, handles `bool`, `str` (`"true"/"1"/"yes"`), and other truthy values.

### CloudProvider Enum (`auth/models.py`)

```python
class CloudProvider(str, Enum):
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    LOCAL = "local"
```

### ApimAuth Dependency (`auth/middleware.py`)

`ApimAuth` is a type alias: `Annotated[AuthContext, Depends(get_auth_context)]`. Use it as a FastAPI dependency parameter:

```python
from taproot_common import ApimAuth

@app.get("/protected")
async def my_endpoint(auth: ApimAuth):
    print(auth.api_key_id, auth.store_id, auth.project_id, auth.is_admin)
```

### Auth Providers (`auth/provider.py`)

Four cloud-specific providers, selected via `AuthContextFactory.get_provider(cloud_name)`:

| Provider | Cloud | Header | Behavior |
|----------|-------|--------|----------|
| `AWSAuthContextProvider` | `aws` | `X-Api-Key-Id` | Raises `MissingHeaderError` if absent or empty |
| `AzureAuthContextProvider` | `azure` | `X-Api-Key-Id` | Raises `MissingHeaderError` if absent or empty |
| `GCPAuthContextProvider` | `gcp` | `X-Endpoint-API-UserInfo` | Base64-decodes JSON, extracts `api_key_id` or `sub` claim |
| `LocalAuthContextProvider` | `local` | `X-Api-Key-Id` (optional) | Returns header value if present, otherwise `"local-dev-key"` |

Unknown provider names fall back to `LocalAuthContextProvider`.

### Error Handlers (`errors.py`)

`install_error_handlers(app: FastAPI)` registers three exception handlers:
- `HTTPException` -- returns `{"detail": ...}` with the exception's status code
- `RequestValidationError` (422) -- returns `{"detail": "Validation error", "errors": [...]}` with field-level details
- `Exception` (500) -- logs the traceback, returns `{"detail": "Internal server error"}`

### Logging (`logging.py`)

`configure_logging(service_name: str, log_level: str = "INFO")` sets up stdout logging with format `%(asctime)s [%(levelname)s] %(name)s: %(message)s`. Suppresses noisy loggers: `urllib3`, `botocore`, `boto3`, `s3transfer`, `aiobotocore`.

### Secrets (`secrets.py`)

Multi-cloud secret loading. Services call `load_secrets_to_env(mappings)` at startup before Pydantic settings initialization.

**SecretNames constants:**
- `DB_PASSWORD` -- `taproot-db-password`
- `OPENAI_API_KEY` -- `taproot-openai-api-key`
- `ANTHROPIC_API_KEY` -- `taproot-anthropic-api-key`
- `AZURE_OPENAI_API_KEY` -- `taproot-azure-openai-api-key`
- `COHERE_API_KEY` -- `taproot-cohere-api-key`
- `GOOGLE_API_KEY` -- `taproot-google-api-key`
- `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` -- AWS credentials
- `RETRIEVAL_API_KEY`, `RETRIEVAL_AZURE_BLOB_KEY`, `RETRIEVAL_SERVICE_BUS_CONN`, `RETRIEVAL_SHAREPOINT_SECRET` -- Retrieval-S specific
- `FRONTS_AZURE_CLIENT_SECRET`, `FRONTS_OKTA_CLIENT_SECRET` -- Front-S auth secrets

**Env vars controlling secret loading:**

| Env Var | Description |
|---------|-------------|
| `TAPROOT_SECRETS_ENABLED` | Set to `true` to enable (also checks `RETRIEVAL_SECRETS_ENABLED`, `FRONTS_SECRETS_ENABLED` for backward compat) |
| `TAPROOT_CLOUD_PROVIDER` | Determines which secret manager to use (also checks `RETRIEVAL_CLOUD_PROVIDER`, `FRONTS_CLOUD_PROVIDER`) |
| `AWS_REGION` / `AWS_DEFAULT_REGION` | For AWS Secrets Manager (default: `us-east-1`) |
| `GCP_PROJECT_ID` / `GOOGLE_CLOUD_PROJECT` | For GCP Secret Manager |
| `AZURE_KEY_VAULT_URL` | For Azure Key Vault |

**Secret loading behavior:**
- Skips secrets that are already set in the environment
- Supports JSON secrets from AWS (auto-extracts single-value dicts)
- Returns count of loaded secrets
- `critical_secrets` parameter emits warnings for missing critical secrets
- `local` provider skips all loading silently

## MetadataStore

### Interface (`auth/metadata.py`)

```python
class MetadataStore(ABC):
    async def get_store_id(self, api_key_id: str) -> Optional[str]: ...
    async def get_metadata(self, api_key_id: str) -> Optional[Dict[str, Any]]: ...
```

### Implementations

**DynamoDBMetadataStore** (`auth/metadata.py`)
- Uses `boto3.resource("dynamodb").Table(table_name)`
- Table schema: partition key `api_key_id` (S), attributes `store_id`, `name`, `created_at`
- Runs sync `get_item` via `asyncio.to_thread()` for async compatibility

**CosmosDBMetadataStore** (`auth/cosmos_metadata.py`)
- Uses `azure.cosmos.aio.CosmosClient` with `DefaultAzureCredential` (AAD/RBAC auth)
- Container partition key: `/api_key_id`
- Lazy client initialization on first call
- 404 errors (CosmosResourceNotFoundError) return `None`, other errors propagate

**FirestoreMetadataStore** (`auth/firestore_metadata.py`)
- Uses `google.cloud.firestore_v1.async_client.AsyncClient`
- Collection: configurable (default `api-key-metadata`)
- Document ID: `api_key_id`
- Lazy client initialization on first call
- NotFound errors return `None`, other errors propagate

**InMemoryMetadataStore** (`auth/metadata.py`)
- Dict-backed store with `add(api_key_id, store_id, **extra)` method
- For local development and testing

**CachedMetadataStore** (`auth/metadata.py`)
- Decorator/wrapper around any `MetadataStore`
- Uses `time.monotonic()` for TTL expiry
- Separate cache keys for `store_id:` and `metadata:` lookups
- Only caches non-None results

### MetadataStoreFactory

```python
MetadataStoreFactory.create(
    backend="dynamodb",     # "dynamodb" | "cosmosdb" | "firestore" | "memory"
    table_name="...",       # DynamoDB table name
    cache_ttl=300,          # 0 disables caching
    cosmos_endpoint="...",  # Cosmos DB endpoint
    cosmos_database="...",  # Cosmos DB database
    cosmos_container="...", # Cosmos DB container
) -> MetadataStore
```

The factory wraps the chosen backend with `CachedMetadataStore` when `cache_ttl > 0`.

## Auth Flow

End-to-end request authentication:

1. **Client** sends request with raw API key to the API Gateway (AWS REST API / Azure APIM)
2. **API Gateway** validates the API key and injects `X-Api-Key-Id` header (the key's identifier, not the raw key) into the upstream request
3. **FastAPI endpoint** declares `auth: ApimAuth` dependency
4. **`get_auth_context()`** runs:
   a. Reads `TAPROOT_CLOUD_PROVIDER` from `TaprootSettings`
   b. `AuthContextFactory.get_provider(cloud)` returns the cloud-specific provider
   c. Provider extracts `api_key_id` from request headers (raises HTTP 401 if missing)
   d. `get_metadata_store()` returns/creates the singleton `MetadataStore` (type from `TAPROOT_METADATA_BACKEND`)
   e. `store.get_metadata(api_key_id)` looks up the key (with TTL caching)
   f. Returns `AuthContext(api_key_id, store_id, project_id, provider, metadata)`
5. **Endpoint handler** uses `auth.store_id`, `auth.project_id`, `auth.is_admin` for authorization

The metadata store singleton is created once per process. Call `reset_metadata_store()` in tests to clear it.

## Configuration Reference

### All Environment Variables

| Env Var | Module | Default | Description |
|---------|--------|---------|-------------|
| `TAPROOT_CLOUD_PROVIDER` | config | `"local"` | Cloud provider selection |
| `TAPROOT_METADATA_BACKEND` | config | `"memory"` | Metadata store type (`dynamodb`, `cosmosdb`, `firestore`, `memory`) |
| `TAPROOT_METADATA_TABLE_NAME` | config | `"taproot-api-key-metadata"` | DynamoDB table name |
| `TAPROOT_METADATA_CACHE_TTL` | config | `300` | Cache TTL seconds |
| `TAPROOT_COSMOS_ENDPOINT` | config | `""` | Cosmos DB endpoint |
| `TAPROOT_COSMOS_DATABASE` | config | `"taproot"` | Cosmos DB database |
| `TAPROOT_COSMOS_CONTAINER` | config | `"api-key-metadata"` | Cosmos DB container |
| `TAPROOT_SECRETS_ENABLED` | secrets | `"false"` | Enable secret manager loading |
| `AWS_REGION` | secrets | `"us-east-1"` | AWS region for Secrets Manager |
| `GCP_PROJECT_ID` | secrets | -- | GCP project for Secret Manager |
| `AZURE_KEY_VAULT_URL` | secrets | -- | Azure Key Vault URL |

## Integration -- How Services Use taproot-common

### All Python Services

Every service imports `ApimAuth` as a FastAPI dependency on protected endpoints:

```python
from taproot_common import ApimAuth

@router.post("/resource")
async def create_resource(auth: ApimAuth, ...):
    # auth.api_key_id, auth.store_id, auth.project_id, auth.is_admin
```

### Retrieval-S
- Uses `ApimAuth` for per-store authorization (scopes queries to `auth.store_id`)
- Uses `X-API-Key` raw header validation (legacy path) alongside `X-Api-Key-Id`

### Evals-S
- Uses `ApimAuth` for `X-Api-Key-Id` based auth
- Metadata store resolves project context for test execution

### Guardrail-S
- Uses `ApimAuth` for per-project authorization via `auth.project_id`
- Uses `auth.is_admin` for admin-only endpoints (`require_admin` pattern)
- Rate limiting keyed on `auth.project_id`
- Backend selection: `TAPROOT_METADATA_BACKEND=dynamodb` (AWS) or `cosmosdb` (Azure)

### Prompt-S Management
- Uses `ApimAuth` for `X-Api-Key-Id` auth
- Per-project authorization: non-admin keys restricted to their `project_id`
- Supports trusted proxy identity forwarding (`X-Trusted-Proxy-Secret` + `X-Actor-Identity`)

### Front-S Backend
- Does NOT use `ApimAuth` directly (uses JWT-based auth for users)
- When proxying to downstream services, injects `X-Api-Key-Id` header with `ADMIN_API_KEY_ID`
- Uses `TaprootSettings` indirectly through shared config patterns

### Secret Loading Pattern (all services)

```python
# In service startup (main.py or settings.py)
from taproot_common.secrets import load_secrets_to_env, SecretNames

SECRETS = {
    SecretNames.DB_PASSWORD: "DATABASE_PASSWORD",
    SecretNames.OPENAI_API_KEY: "OPENAI_API_KEY",
}
load_secrets_to_env(SECRETS)
# Then initialize Pydantic settings (env vars are now populated)
```

## Installation

taproot-common is consumed as a **git dependency** from GitHub:

```toml
# In a service's pyproject.toml
dependencies = [
    "taproot-common @ git+https://github.com/Prohan21/taproot-common.git@main",
]
```

Lock files pin to specific commit hashes. To update across a service:

```bash
cd <service-dir>
uv lock --upgrade-package taproot-common
```

### Optional Extras

```bash
# AWS support (DynamoDB metadata store)
pip install taproot-common[aws]     # installs boto3>=1.33.0

# Azure support (Cosmos DB metadata store)
pip install taproot-common[azure]   # installs azure-cosmos>=4.7.0, azure-identity>=1.17.0

# Development
pip install taproot-common[dev]     # installs pytest, pytest-asyncio, httpx, boto3
```

### Local Development

```bash
cd taproot-common
uv sync --extra dev     # Install with dev dependencies
```

## Testing

### Test Structure

```
tests/
  __init__.py
  test_auth.py              # 20 tests: providers, metadata stores, middleware integration
  test_cosmos_metadata.py   # 9 tests: CosmosDB store with mocked Azure client
```

### Running Tests

```bash
cd taproot-common
uv run pytest tests/ -v --tb=short
```

### Test Configuration

- `asyncio_mode = "auto"` in `pyproject.toml` (no need for explicit `@pytest.mark.asyncio` on most tests, though tests still use it)
- Test paths: `tests/`

### Test Categories

**Provider tests** (`TestAWSProvider`, `TestGCPProvider`, `TestAzureProvider`, `TestLocalProvider`):
- Header extraction, missing header errors, empty header handling
- GCP base64 decoding, fallback to `sub` claim

**Factory tests** (`TestAuthContextFactory`):
- Provider selection by name, case insensitivity, unknown fallback to local

**Metadata store tests** (`TestInMemoryMetadataStore`, `TestCachedMetadataStore`, `TestMetadataStoreFactory`):
- CRUD operations, cache hit/miss/expiry, factory backend selection

**Cosmos DB tests** (`TestCosmosDBMetadataStore`, `TestMetadataStoreFactoryCosmosDB`):
- Mocked Cosmos client, not-found handling, lazy initialization, factory integration
- Uses a helper `_make_not_found_error()` that creates real `CosmosResourceNotFoundError` when azure-cosmos is installed, otherwise patches `_is_not_found`

**Middleware integration tests** (`TestMiddlewareIntegration`):
- Full FastAPI TestClient round-trip with `ApimAuth` dependency
- Tests local provider with/without header, AWS provider missing header (401), AWS provider with header
- Uses `reset_metadata_store()` in setup/teardown and sets env vars per test

### Key Testing Patterns

- Singleton metadata store must be reset between tests via `reset_metadata_store()`
- Environment variables (`TAPROOT_CLOUD_PROVIDER`, `TAPROOT_METADATA_BACKEND`) control behavior and must be set/unset in test setup/teardown
- CosmosDB tests inject mock container via `store._container_client = mock_container` to bypass real Azure auth

## Build System

- **Build backend**: hatchling
- **Package layout**: `src/taproot_common/` (configured in `[tool.hatch.build.targets.wheel]`)
- **Python**: `>=3.11`
- **Core dependencies**: `fastapi>=0.104.0`, `pydantic-settings>=2.1.0`
