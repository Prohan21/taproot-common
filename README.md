# taproot-common

Shared trust, auth, metadata, logging, secrets, audit, and System of Record utilities for Taproot services.

Changes here affect the whole platform. Keep interfaces stable unless a platform-wide change is intended.

## Core Responsibilities

- APIM-based API key auth via `ApimAuth`.
- Metadata store abstractions across AWS, Azure, GCP, and local backends.
- Multi-cloud secret loading.
- Structured logging and request-context binding.
- Shared FastAPI error handling.
- Audit and System of Record activity helpers.

## Development

```bash
uv sync --extra dev
uv run pytest tests/ -v --tb=short
uv run ruff check src/ tests/
uv run mypy src/
```

## Secret Handling Rule

Production runtime must never receive secret payloads or secret manager identifiers through environment variables. Services must derive canonical names like `taproot-<env>-<service>-<purpose>`, read secrets directly from the cloud secret manager once at startup using workload identity, and keep values in memory/settings/client objects. Do not write loaded secrets back to `os.environ`.

Forbidden in production runtime env:
- secret payloads: passwords, API keys, tokens, JWT secrets, provider keys
- secret identifiers: `*_SECRET_ARN`, `*_SECRET_URI`, `*_SECRET_RESOURCE`, `*_SECRET_NAME`
- platform injection: ECS `secrets`, Kubernetes `secretKeyRef`, Azure Container Apps `secret_name`, Cloud Run `secret_key_ref`

Only isolated, approval-gated bootstrap/rotation/operator jobs may handle secret identifiers or payloads.
