# taproot-common

Shared authentication and utilities for Taproot microservices.

## Secret Handling Rule

Production runtime must never receive secret payloads or secret manager identifiers through environment variables. Services must derive canonical names like `taproot-<env>-<service>-<purpose>`, read secrets directly from the cloud secret manager once at startup using workload identity, and keep values in memory/settings/client objects. Do not write loaded secrets back to `os.environ`.

Forbidden in production runtime env:
- secret payloads: passwords, API keys, tokens, JWT secrets, provider keys
- secret identifiers: `*_SECRET_ARN`, `*_SECRET_URI`, `*_SECRET_RESOURCE`, `*_SECRET_NAME`
- platform injection: ECS `secrets`, Kubernetes `secretKeyRef`, Azure Container Apps `secret_name`, Cloud Run `secret_key_ref`

Only isolated, approval-gated bootstrap/rotation/operator jobs may handle secret identifiers or payloads.
