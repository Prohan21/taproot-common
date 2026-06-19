# AGENTS.md

This file provides guidance to Codex when working in `taproot-common/`. It is adapted from the local `CLAUDE.md`.

## Library Overview

`taproot-common` is the shared backend library used across Taproot services. It provides:
- APIM-based API key auth via `ApimAuth`
- Metadata store abstractions across AWS, Azure, GCP, and local backends
- Multi-cloud secret loading
- Shared FastAPI error handlers
- Structured logging and request-context binding
- Audit publishing helpers

## Secret Handling Rule

Production runtime must never receive secret payloads or secret manager identifiers through environment variables. Services must derive canonical names like `taproot-<env>-<service>-<purpose>`, read secrets directly from the cloud secret manager once at startup using workload identity, and keep values in memory/settings/client objects. Do not write loaded secrets back to `os.environ`.

Forbidden in production runtime env:
- secret payloads: passwords, API keys, tokens, JWT secrets, provider keys
- secret identifiers: `*_SECRET_ARN`, `*_SECRET_URI`, `*_SECRET_RESOURCE`, `*_SECRET_NAME`
- platform injection: ECS `secrets`, Kubernetes `secretKeyRef`, Azure Container Apps `secret_name`, Cloud Run `secret_key_ref`

Only isolated, approval-gated bootstrap/rotation/operator jobs may handle secret identifiers or payloads.

## Commands

```bash
uv sync --extra dev
uv run pytest tests/ -v --tb=short
uv run ruff check src/ tests/
uv run ruff format --check src/ tests/
uv run mypy src/
```

## Architecture

Key areas:
- `src/taproot_common/config.py` for shared settings
- `src/taproot_common/errors.py` for FastAPI error handlers
- `src/taproot_common/logging.py` for structlog setup and request context helpers
- `src/taproot_common/secrets.py` for secret-manager loading
- `src/taproot_common/audit/` for audit event publishing
- `src/taproot_common/auth/` for auth providers, middleware, and metadata stores

Important behaviors:
- This library is the multi-cloud abstraction layer for backend auth and metadata.
- Provider and metadata-store implementations must stay behaviorally aligned across AWS, Azure, GCP, and local.
- Metadata-store creation uses a process singleton with optional TTL caching.
- GCP auth uses SHA-256 of the raw API key when key IDs are not injected.

## Editing Guidance

- Treat changes here as platform-wide changes; preserve public contracts unless explicitly changing them.
- Keep provider-specific logic behind the existing factory and interface patterns.
- When changing auth or metadata logic, update tests and consider downstream service impact.
- This library is consumed by downstream services through lockfile updates, not direct deployment.
