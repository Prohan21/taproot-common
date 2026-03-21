# CLAUDE.md - taproot-common

## Library Overview

taproot-common is the shared authentication middleware and utilities library used by all Taproot platform microservices. It provides:

- **API key authentication** via APIM-injected headers (`ApimAuth` FastAPI dependency)
- **Metadata store** for resolving API key IDs to tenant/project context (5 backends)
- **Multi-cloud secret loading** from AWS Secrets Manager, Azure Key Vault, GCP Secret Manager
- **Standardized error handlers** for consistent JSON error responses across all services
- **Structured logging** with service-name context and noisy logger suppression
- **TTL-based caching** for metadata lookups (default 300s)

All Taproot backend services (Retrieval-S, Evals-S, Guardrail-S, Front-S, Prompt-S, ToolBox-S) depend on this library.

## Development Rules

1. **Deployment Rule**: This is a library, not a deployable service. Changes are consumed by downstream services via `uv lock --upgrade-package taproot-common`. There is no direct deployment step. After pushing changes to `main`, each consuming service must update its lock file independently.

2. **Multi-Cloud Rule**: This library IS the multi-cloud abstraction layer for the entire Taproot platform. All four providers (AWS, Azure, GCP, Local) must be maintained in lockstep. Never add cloud-specific logic to a single provider without considering the others. Every `AuthContextProvider` and `MetadataStore` implementation must follow the same interface contract.

3. **LLM Agnostic Rule**: N/A -- this library has no LLM usage.

4. **Terraform Rule**: N/A -- this library has no Terraform configuration.

5. **Live Testing Rule**: When making changes to auth providers or metadata stores, test against a live environment. Reference `deployment_env.txt` at the root of a consuming service (e.g., `Retrieval-S/deployment_env.txt`) for connection details.

6. **No Assumptions Rule**: Ask, don't assume. This library is a dependency of every backend service. Changes have platform-wide impact.

7. **Continuous Improvement Rule**: Keep this CLAUDE.md current when adding features, changing interfaces, or modifying configuration.

## Feature List

- [x] AWS auth context provider (`X-Api-Key-Id` header extraction)
- [x] Azure auth context provider (`X-Api-Key-Id` header extraction)
- [x] GCP auth context provider (SHA-256 hashing of `x-api-key` + legacy base64 `X-Endpoint-API-UserInfo` fallback)
- [x] Local auth context provider (default `local-dev-key`, no errors on missing header)
- [x] DynamoDB metadata store (AWS, via `boto3` with `asyncio.to_thread`)
- [x] CosmosDB metadata store (Azure, async `azure.cosmos.aio`, lazy-initialized)
- [x] Firestore metadata store (GCP, async `google.cloud.firestore_v1`, lazy-initialized)
- [x] In-memory metadata store (local dev and testing)
- [x] CachedMetadataStore TTL wrapper (wraps any backend, `time.monotonic()` expiry)
- [x] Multi-cloud secret loading (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager)
- [x] Standardized FastAPI error handlers (HTTP, validation, unhandled)
- [x] Structured logging (structlog, JSON in prod / colored console in dev) with noisy logger suppression
- [x] Request context binding: `bind_request_context()` / `clear_request_context()` helpers for per-request structlog context
- [x] Audit module: `AuditEvent`, `IAuditPublisher`, `publish_audit_event()`, `init_audit_pool()`
- [x] Pydantic `BaseSettings` configuration with `TAPROOT_` prefix
- [x] Factory pattern for providers and metadata stores

## Architecture

```
taproot-common/
  pyproject.toml                       # Build config (hatchling), Python >=3.11
  uv.lock                             # Pinned dependency lock file
  src/taproot_common/
    __init__.py                        # Public API exports
    config.py                          # TaprootSettings (Pydantic BaseSettings)
    errors.py                          # install_error_handlers() for FastAPI
    logging.py                         # configure_logging() with structlog; bind_request_context(); clear_request_context()
    secrets.py                         # Multi-cloud secret loading + SecretNames
    audit/
      __init__.py                      # AuditEvent, IAuditPublisher, publish_audit_event(), init_audit_pool()
    auth/
      __init__.py                      # Re-exports ApimAuth, AuthContext, CloudProvider
      models.py                        # AuthContext dataclass, CloudProvider enum
      provider.py                      # 4 cloud-specific providers + AuthContextFactory
      middleware.py                    # FastAPI dependency (get_auth_context, ApimAuth)
      metadata.py                      # MetadataStore ABC, DynamoDB, InMemory, Cached, Factory
      cosmos_metadata.py               # CosmosDBMetadataStore (Azure, optional)
      firestore_metadata.py            # FirestoreMetadataStore (GCP, optional)
  tests/
    test_auth.py                       # Provider, metadata store, middleware tests (~20 tests)
    test_cosmos_metadata.py            # CosmosDB store tests with mocked Azure client (~9 tests)
    test_firestore_metadata.py         # Firestore store tests with mocked GCP client (~8 tests)
```

### Design Patterns

- **Adapter/Factory pattern**: `AuthContextProvider` ABC with 4 cloud-specific implementations, selected via `AuthContextFactory.get_provider(cloud_name)`. `MetadataStore` ABC with 5 implementations (4 backends + caching wrapper), selected via `MetadataStoreFactory.create(backend)`.
- **Singleton metadata store**: Created once per process in `get_metadata_store()`, cached in module-level global. Reset in tests via `reset_metadata_store()`.
- **Lazy client initialization**: CosmosDB and Firestore clients created on first metadata lookup (not at import/startup time).
- **TTL caching decorator**: `CachedMetadataStore` wraps any backend with `time.monotonic()`-based expiry. Only caches non-None results.
- **Configuration-driven selection**: Backend chosen at runtime via `TAPROOT_CLOUD_PROVIDER` and `TAPROOT_METADATA_BACKEND` env vars.

### Auth Flow (End-to-End)

1. Client sends request with raw API key to the API Gateway (AWS REST API / Azure APIM / GCP Cloud Endpoints)
2. API Gateway validates the key and injects `X-Api-Key-Id` header (or `x-api-key` on GCP) into the upstream request
3. FastAPI endpoint declares `auth: ApimAuth` dependency
4. `get_auth_context()` runs:
   - Reads `TAPROOT_CLOUD_PROVIDER` from `TaprootSettings` (cached via `@lru_cache`)
   - `AuthContextFactory.get_provider(cloud)` returns the cloud-specific provider
   - Provider extracts `api_key_id` from request headers (raises HTTP 401 if missing)
   - `get_metadata_store()` returns/creates the singleton `MetadataStore`
   - `store.get_metadata(api_key_id)` looks up the key (with optional TTL caching)
   - Returns `AuthContext(api_key_id, store_id, project_id, provider, metadata)`
5. Endpoint handler uses `auth.store_id`, `auth.project_id`, `auth.is_admin` for authorization

## Auth Providers

Four cloud-specific providers in `src/taproot_common/auth/provider.py`, selected via `AuthContextFactory.get_provider(cloud_name)`:

| Provider | Cloud | Header | Behavior |
|----------|-------|--------|----------|
| `AWSAuthContextProvider` | `aws` | `X-Api-Key-Id` | Raises `MissingHeaderError` if absent or empty |
| `AzureAuthContextProvider` | `azure` | `X-Api-Key-Id` | Raises `MissingHeaderError` if absent or empty |
| `GCPAuthContextProvider` | `gcp` | `x-api-key` (primary) / `X-Endpoint-API-UserInfo` (legacy) | Primary: SHA-256 hashes raw key to produce deterministic 64-char hex ID. Legacy fallback: base64-decodes JSON, extracts `api_key_id` or `sub` claim |
| `LocalAuthContextProvider` | `local` | `X-Api-Key-Id` (optional) | Returns header value if present, otherwise returns `"local-dev-key"`. Never raises errors |

**Base class**: `AuthContextProvider(ABC)` with `provider: CloudProvider` attribute and `extract_key_id(headers: Dict[str, str]) -> str` abstract method.

**Factory**: `AuthContextFactory.get_provider(cloud: str) -> AuthContextProvider` -- case-insensitive lookup, unknown names fall back to `LocalAuthContextProvider`. Returns a new instance per call (not cached).

**GCP SHA-256 detail**: GCP API Gateway does not inject a key identifier like AWS/Azure. Instead, the raw API key is sent in `x-api-key`, and the provider computes `hashlib.sha256(key.encode()).hexdigest()` to derive a deterministic, one-way identifier. The same hash must be stored in Firestore as the document ID.

## Metadata Stores

### Interface

```python
class MetadataStore(ABC):
    async def get_store_id(self, api_key_id: str) -> Optional[str]: ...
    async def get_metadata(self, api_key_id: str) -> Optional[Dict[str, Any]]: ...
```

### Implementations

**DynamoDBMetadataStore** (`auth/metadata.py`)
- Uses `boto3.resource("dynamodb").Table(table_name)`
- Table partition key: `api_key_id` (String). Attributes: `store_id`, `name`, `created_at`
- Runs sync `get_item` via `asyncio.to_thread()` for async compatibility
- Requires `[aws]` optional extra

**CosmosDBMetadataStore** (`auth/cosmos_metadata.py`)
- Uses `azure.cosmos.aio.CosmosClient` with `DefaultAzureCredential` (AAD/RBAC auth)
- Container partition key: `/api_key_id`
- Lazy client initialization on first call via `_get_container()`
- 404 errors (`CosmosResourceNotFoundError`) return `None`, other errors propagate
- Requires `[azure]` optional extra

**FirestoreMetadataStore** (`auth/firestore_metadata.py`)
- Uses `google.cloud.firestore_v1.AsyncClient` with Application Default Credentials
- Collection name configurable (default: `api-key-metadata`). Document ID = `api_key_id`
- Lazy client initialization on first call via `_get_collection()`
- Checks `doc.exists` (Firestore-specific pattern). Not-found returns `None`
- Requires `[gcp]` optional extra

**InMemoryMetadataStore** (`auth/metadata.py`)
- Dict-backed store with `add(api_key_id, store_id, **extra)` method
- For local development and testing only

**CachedMetadataStore** (`auth/metadata.py`)
- Decorator/wrapper around any `MetadataStore` implementation
- Uses `time.monotonic()` for TTL expiry (immune to clock skew)
- Separate cache keys: `store_id:{api_key_id}` and `metadata:{api_key_id}`
- Only caches non-None results (misses are never cached)
- Default TTL: 300 seconds (configurable via `TAPROOT_METADATA_CACHE_TTL`)

### MetadataStoreFactory

```python
MetadataStoreFactory.create(
    backend="dynamodb",             # "dynamodb" | "cosmosdb" | "firestore" | "memory"
    table_name="...",               # DynamoDB table name
    cache_ttl=300,                  # 0 disables caching
    cosmos_endpoint="...",          # Cosmos DB endpoint
    cosmos_database="...",          # Cosmos DB database
    cosmos_container="...",         # Cosmos DB container
    firestore_project_id="...",     # GCP project ID
    firestore_database="...",       # Firestore database
    firestore_collection="...",     # Firestore collection
) -> MetadataStore
```

The factory wraps the chosen backend with `CachedMetadataStore` when `cache_ttl > 0`. CosmosDB and Firestore implementations are lazy-imported to avoid requiring cloud SDKs when not in use.

## Secret Management

Multi-cloud secret loading in `src/taproot_common/secrets.py`. Services call `load_secrets_to_env(mappings)` at startup before Pydantic settings initialization.

### Cloud-Specific Loaders

| Loader | Cloud SDK | Auth | Notes |
|--------|-----------|------|-------|
| `load_secret_from_aws(name)` | `boto3` Secrets Manager | IAM role / env creds | JSON auto-extraction for single-value dicts. Region from `AWS_REGION` / `AWS_DEFAULT_REGION` (default `us-east-1`) |
| `load_secret_from_azure(name)` | `azure-keyvault-secrets` | `DefaultAzureCredential` | Vault URL from `AZURE_KEY_VAULT_URL`. Secret names use hyphens (no underscores) |
| `load_secret_from_gcp(name)` | `google-cloud-secret-manager` | Application Default Credentials | Project from `GCP_PROJECT_ID` / `GOOGLE_CLOUD_PROJECT`. Accesses `versions/latest` |

### Unified Loading

- `load_secret(secret_name)` -- Routes to cloud-specific loader based on `TAPROOT_CLOUD_PROVIDER`. Returns `None` for `local` provider.
- `load_secrets_to_env(mappings, critical_secrets=None)` -- Iterates over `{secret_name: env_var}` mappings. Skips secrets already in environment. Sets `os.environ[env_var]` for loaded secrets. Emits warnings for missing critical secrets. Returns count of loaded secrets.
- `is_secrets_enabled()` -- Checks `TAPROOT_SECRETS_ENABLED` (also backward-compat `RETRIEVAL_SECRETS_ENABLED`, `FRONTS_SECRETS_ENABLED`). Truthy: `"true"`, `"1"`, `"yes"`.
- `get_cloud_provider()` -- Checks `TAPROOT_CLOUD_PROVIDER`, then legacy `RETRIEVAL_CLOUD_PROVIDER`, `FRONTS_CLOUD_PROVIDER`. Defaults to `"local"`.

### SecretNames Constants

```python
class SecretNames:
    DB_PASSWORD = "taproot-db-password"
    OPENAI_API_KEY = "taproot-openai-api-key"
    ANTHROPIC_API_KEY = "taproot-anthropic-api-key"
    AZURE_OPENAI_API_KEY = "taproot-azure-openai-api-key"
    COHERE_API_KEY = "taproot-cohere-api-key"
    GOOGLE_API_KEY = "taproot-google-api-key"
    AWS_ACCESS_KEY_ID = "taproot-aws-access-key-id"
    AWS_SECRET_ACCESS_KEY = "taproot-aws-secret-access-key"
    RETRIEVAL_API_KEY = "taproot-retrieval-api-key"
    RETRIEVAL_AZURE_BLOB_KEY = "taproot-retrieval-azure-blob-key"
    RETRIEVAL_SERVICE_BUS_CONN = "taproot-retrieval-service-bus-conn"
    RETRIEVAL_SHAREPOINT_SECRET = "taproot-retrieval-sharepoint-secret"
    FRONTS_AZURE_CLIENT_SECRET = "taproot-fronts-azure-client-secret"
    FRONTS_OKTA_CLIENT_SECRET = "taproot-fronts-okta-client-secret"
```

### Usage Pattern

```python
from taproot_common.secrets import load_secrets_to_env, SecretNames

SECRETS = {
    SecretNames.DB_PASSWORD: "DATABASE_PASSWORD",
    SecretNames.OPENAI_API_KEY: "OPENAI_API_KEY",
}
load_secrets_to_env(SECRETS, critical_secrets={SecretNames.DB_PASSWORD})
# Then initialize Pydantic settings (env vars are now populated)
```

## Error Handling

`install_error_handlers(app: FastAPI)` in `src/taproot_common/errors.py` registers three exception handlers:

| Handler | Exception | Status | Response |
|---------|-----------|--------|----------|
| HTTP | `StarletteHTTPException` | Preserved from exception | `{detail, message, request_id, path, method}` |
| Validation | `RequestValidationError` | 422 | `{detail: "Validation error", message, errors: [{field, message, type}], request_id, path, method}` |
| Generic | `Exception` | 500 | `{detail: "Internal server error", message, request_id, path, method}`. Logs full traceback via `logger.exception()` |

**Request ID extraction** (`_request_id`): Checks `request.state.correlation_id`, then `X-Correlation-ID` header, then `X-Request-ID` header. Appended to messages when available.

**Validation error summary** (`_summarize_validation_errors`): Takes first 3 errors, formats as `"field: message"` joined by `"; "`.

## Logging

`configure_logging(service_name: str, log_level: str = "INFO")` in `src/taproot_common/logging.py`:

- **Backend**: structlog (JSON renderer in production, colored console in development). Controlled by `LOG_FORMAT` env var (`json` or `console`).
- **Handler**: `StreamHandler(sys.stdout)` (stdout, not stderr)
- **Root logger**: Sets level, clears existing handlers, adds single structlog handler
- **Noisy logger suppression**: Sets `WARNING` level for: `urllib3`, `botocore`, `boto3`, `s3transfer`, `aiobotocore`
- **Log level parsing**: `getattr(logging, log_level.upper(), logging.INFO)` -- defaults to INFO for invalid strings

### Request Context Binding

Two helpers manage per-request structlog context (via `structlog.contextvars`):

- **`bind_request_context(correlation_id, api_key_id, agent_id, actor_identity)`** -- Binds these fields into the structlog context for the duration of a request. Called by the APIM auth middleware after extracting the auth context.
- **`clear_request_context()`** -- Clears all bound context variables. Called in a `finally` block after request completion.

Once bound, every log line emitted anywhere in the request (service layer, adapters, domain) automatically includes `correlation_id`, `api_key_id`, `agent_id`, and `actor_identity` without explicit passing.

### Actor Identity

The `actor_identity` field carries the real user email forwarded from Front-S via the `X-Actor-Identity` header. This enables human-readable attribution in audit trails and log queries even though service-to-service auth uses API key IDs.

## Audit Logging

The `audit/` module provides a lightweight, fire-and-forget audit publishing mechanism.

### Key Exports

```python
from taproot_common.audit import (
    AuditEvent,           # Frozen dataclass: event_type, entity_type, entity_id, project_id, actor_identity, metadata
    IAuditPublisher,      # ABC with publish(event: AuditEvent) -> None
    publish_audit_event,  # Fire-and-forget helper (wraps asyncio.create_task)
    init_audit_pool,      # Called at startup to set the global publisher
)
```

### Usage Pattern

```python
from taproot_common.audit import publish_audit_event, AuditEvent

# In a service handler -- fire-and-forget, does not block the response
publish_audit_event(AuditEvent(
    event_type="store.created",
    entity_type="STORE",
    entity_id=store.id,
    project_id=auth.project_id,
    actor_identity=request.headers.get("X-Actor-Identity"),
    metadata={"store_name": store.name},
))
```

`publish_audit_event()` wraps the publish coroutine in `asyncio.create_task()`, so the calling handler returns immediately. The task is logged on failure but never raises into the request path.

### Structured Log Events

All modules use `logger = logging.getLogger(__name__)` with contextual `extra={}` dicts. Key event names:

- `auth.provider.extract.start`, `auth.provider.extract.success`, `auth.provider.extract.missing_header`
- `auth.context.start`, `auth.context.key_extracted`, `auth.context.metadata_loaded`, `auth.context.failed`
- `auth.metadata.cache_hit`, `auth.metadata.cache_miss`, `auth.metadata.cache_expired`
- `auth.metadata.dynamodb.lookup`, `auth.metadata.dynamodb.found`, `auth.metadata.dynamodb.not_found`
- Similar patterns for `cosmos` and `firestore` prefixes

## Configuration

### TaprootSettings (Pydantic BaseSettings)

All fields set via environment variables with `TAPROOT_` prefix:

| Env Var | Field | Default | Description |
|---------|-------|---------|-------------|
| `TAPROOT_CLOUD_PROVIDER` | `cloud_provider` | `"local"` | Cloud provider: `aws`, `azure`, `gcp`, `local` |
| `TAPROOT_METADATA_BACKEND` | `metadata_backend` | `"memory"` | Store backend: `dynamodb`, `cosmosdb`, `firestore`, `memory` |
| `TAPROOT_METADATA_TABLE_NAME` | `metadata_table_name` | `"taproot-api-key-metadata"` | DynamoDB table name |
| `TAPROOT_METADATA_CACHE_TTL` | `metadata_cache_ttl` | `300` | Cache TTL seconds (0 disables) |
| `TAPROOT_COSMOS_ENDPOINT` | `cosmos_endpoint` | `""` | Azure Cosmos DB endpoint URL |
| `TAPROOT_COSMOS_DATABASE` | `cosmos_database` | `"taproot"` | Cosmos DB database name |
| `TAPROOT_COSMOS_CONTAINER` | `cosmos_container` | `"api-key-metadata"` | Cosmos DB container name |
| `TAPROOT_FIRESTORE_PROJECT_ID` | `firestore_project_id` | `""` | GCP project ID |
| `TAPROOT_FIRESTORE_DATABASE` | `firestore_database` | `"(default)"` | Firestore database name |
| `TAPROOT_FIRESTORE_COLLECTION` | `firestore_collection` | `"api-key-metadata"` | Firestore collection name |

### Secret Loading Environment Variables

| Env Var | Module | Default | Description |
|---------|--------|---------|-------------|
| `TAPROOT_SECRETS_ENABLED` | secrets | `"false"` | Enable secret manager loading |
| `RETRIEVAL_SECRETS_ENABLED` | secrets | -- | Backward compat (checked if `TAPROOT_SECRETS_ENABLED` unset) |
| `FRONTS_SECRETS_ENABLED` | secrets | -- | Backward compat (checked if `TAPROOT_SECRETS_ENABLED` unset) |
| `RETRIEVAL_CLOUD_PROVIDER` | secrets | -- | Backward compat for provider detection |
| `FRONTS_CLOUD_PROVIDER` | secrets | -- | Backward compat for provider detection |
| `AWS_REGION` / `AWS_DEFAULT_REGION` | secrets | `"us-east-1"` | Region for AWS Secrets Manager |
| `GCP_PROJECT_ID` / `GOOGLE_CLOUD_PROJECT` | secrets | -- | Project for GCP Secret Manager |
| `AZURE_KEY_VAULT_URL` | secrets | -- | Vault URL for Azure Key Vault |

### Request Headers (Read by Providers)

| Header | Provider | Description |
|--------|----------|-------------|
| `X-Api-Key-Id` | AWS, Azure, Local | API key identifier injected by APIM |
| `x-api-key` | GCP (primary) | Raw API key, SHA-256 hashed by provider |
| `X-Endpoint-API-UserInfo` | GCP (legacy fallback) | Base64-encoded JSON with `api_key_id` or `sub` |
| `X-Correlation-ID` / `X-Request-ID` | Error handlers | Request tracing ID for error responses |

## Consumption Pattern

### Git Dependency

taproot-common is consumed as a git dependency from GitHub, not published to PyPI:

```toml
# In a service's pyproject.toml
dependencies = [
    "taproot-common @ git+https://github.com/Prohan21/taproot-common.git@main",
]
```

### Lock File Pinning

Each service's `uv.lock` pins to a specific commit hash:

```
[[package]]
name = "taproot-common"
version = "0.1.0"
source = { git = "https://github.com/Prohan21/taproot-common.git", rev = "<COMMIT_HASH>" }
```

### Update Workflow

After pushing changes to `taproot-common` on `main`, update each consuming service:

```bash
cd <service-dir>
uv lock --upgrade-package taproot-common
# Commit the updated uv.lock
```

### Optional Extras

Cloud-specific SDKs are installed via optional extras. Services include the extras they need:

```bash
# AWS (DynamoDB metadata store, Secrets Manager)
pip install taproot-common[aws]     # boto3>=1.33.0

# Azure (Cosmos DB metadata store, Key Vault)
pip install taproot-common[azure]   # azure-cosmos>=4.7.0, azure-identity>=1.17.0

# GCP (Firestore metadata store, Secret Manager)
pip install taproot-common[gcp]     # google-cloud-firestore>=2.14.0, google-cloud-secret-manager>=2.16.0

# Development
pip install taproot-common[dev]     # pytest, pytest-asyncio, httpx, boto3
```

### Local Development

```bash
cd taproot-common
uv sync --extra dev     # Install with dev dependencies
```

## Testing

### Running Tests

```bash
cd taproot-common
uv run pytest tests/ -v --tb=short
```

### Test Structure

| File | Tests | Coverage |
|------|-------|----------|
| `tests/test_auth.py` | ~20 tests | Providers (AWS, Azure, GCP, Local), factory, InMemory store, Cached store, middleware integration |
| `tests/test_cosmos_metadata.py` | ~9 tests | CosmosDB store with mocked Azure client, factory integration |
| `tests/test_firestore_metadata.py` | ~8 tests | Firestore store with mocked GCP client, factory integration |

### Test Configuration

- `asyncio_mode = "auto"` in `pyproject.toml`
- `testpaths = ["tests"]`
- Uses `httpx.AsyncClient` with `ASGITransport` for middleware integration tests

### Key Testing Patterns

**Singleton reset**: The module-level metadata store singleton must be reset between tests:
```python
from taproot_common.auth.middleware import reset_metadata_store
# Call in setup AND teardown of tests that modify TAPROOT_* env vars
reset_metadata_store()
```

**Environment variable isolation**: Tests set `TAPROOT_CLOUD_PROVIDER` and `TAPROOT_METADATA_BACKEND` per test case and must clean up in teardown.

**Mock injection for cloud stores**: CosmosDB and Firestore tests inject mock clients directly:
```python
store = CosmosDBMetadataStore(endpoint="...", database="...", container="...")
store._container_client = mock_container  # Bypass real Azure/GCP auth
```

**Not-found error helpers**: Test files include `_make_not_found_error()` helpers that create real cloud exceptions when the SDK is installed, or monkey-patch the `_is_not_found()` helper when it is not.

### Test Categories

- **Provider tests**: Header extraction, missing/empty header errors, GCP SHA-256 + base64 decoding
- **Factory tests**: Provider selection by name, case insensitivity, unknown fallback to local
- **Metadata store tests**: CRUD operations, cache hit/miss/expiry, factory backend selection
- **Middleware integration tests**: Full FastAPI round-trip with `ApimAuth` dependency (local with/without header, AWS missing header -> 401, AWS with header)

## Public API

### Top-Level Exports (`taproot_common`)

```python
from taproot_common import (
    ApimAuth,           # Annotated[AuthContext, Depends(get_auth_context)] -- FastAPI dependency
    AuthContext,        # Dataclass: api_key_id, store_id, project_id, provider, metadata, is_admin
    TaprootSettings,    # Pydantic BaseSettings with TAPROOT_ prefix
    SecretNames,        # Constants for standard secret names
    is_secrets_enabled, # Check if TAPROOT_SECRETS_ENABLED is truthy
    load_secret,        # Load single secret from configured cloud provider
    load_secrets_to_env,# Load multiple secrets into environment variables
)
```

### Auth Submodule Exports

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
from taproot_common.auth.cosmos_metadata import CosmosDBMetadataStore   # Azure
from taproot_common.auth.firestore_metadata import FirestoreMetadataStore  # GCP
from taproot_common.auth.provider import (
    AuthContextProvider,        # ABC for header extraction
    AuthContextFactory,         # Factory: get_provider(cloud) -> AuthContextProvider
    AWSAuthContextProvider,     # Reads X-Api-Key-Id header
    AzureAuthContextProvider,   # Reads X-Api-Key-Id header
    GCPAuthContextProvider,     # SHA-256 of x-api-key or base64 X-Endpoint-API-UserInfo
    LocalAuthContextProvider,   # Returns header or "local-dev-key" default
    MissingHeaderError,         # Raised when expected header is absent
)
from taproot_common.auth.models import AuthContext, CloudProvider
```

### Utility Exports

```python
from taproot_common.errors import install_error_handlers
from taproot_common.logging import configure_logging
```

### Key Types

**CloudProvider** (enum):
- `CloudProvider.AWS` = `"aws"`
- `CloudProvider.AZURE` = `"azure"`
- `CloudProvider.GCP` = `"gcp"`
- `CloudProvider.LOCAL` = `"local"`

**AuthContext** (dataclass, mutable):
- `api_key_id: str` -- API key identifier from the gateway
- `store_id: Optional[str]` -- Store/tenant ID from metadata lookup
- `project_id: Optional[str]` -- Project slug from metadata
- `provider: CloudProvider` -- Which cloud supplied the identity
- `metadata: Dict[str, Any]` -- Full metadata dict from the store
- `is_admin: bool` (property) -- Checks `metadata.get("is_admin")`, handles `bool`, `str` (`"true"/"1"/"yes"`), and other truthy values

## Build System

- **Build backend**: hatchling
- **Package layout**: `src/taproot_common/` (configured in `[tool.hatch.build.targets.wheel]`)
- **Python**: `>=3.11`
- **Core dependencies**: `fastapi>=0.104.0`, `pydantic-settings>=2.1.0`

## Service Integration Quick Reference

### All Backend Services (Retrieval-S, Evals-S, Guardrail-S, Prompt-S, ToolBox-S)

```python
from taproot_common import ApimAuth

@router.post("/resource")
async def create_resource(auth: ApimAuth, ...):
    # auth.api_key_id, auth.store_id, auth.project_id, auth.is_admin
    pass
```

### Front-S Backend

Does NOT use `ApimAuth` directly (uses JWT-based auth for users). When proxying to downstream services, injects `X-Api-Key-Id` header with `ADMIN_API_KEY_ID`.

### Error and Logging Setup (All Services)

```python
from taproot_common.errors import install_error_handlers
from taproot_common.logging import configure_logging

configure_logging("my-service", log_level="INFO")
install_error_handlers(app)
```
