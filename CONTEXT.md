# taproot-common Context

`taproot-common` is the shared backend library used across Taproot services.

## Responsibilities

- Provide APIM-based API key auth through `ApimAuth`.
- Provide metadata store abstractions across AWS, Azure, GCP, and local backends.
- Provide multi-cloud secret loading.
- Provide shared FastAPI error handlers and exception primitives.
- Provide structured logging, request-context binding, and audit publishing helpers.
- Provide reusable TAP-38 activity abstractions for activity records, interaction identity, actor chains, retention policy primitives, evidence links, snapshots, diffs, and activity database storage adapters.

## Boundaries

`src/taproot_common/auth/` owns auth providers, middleware, and metadata stores. `src/taproot_common/audit/` owns legacy audit event publishing primitives. The TAP-38 activity Module owns reusable activity records, interaction identity, actor chain, retention policy, reconstruction, evidence-link, and activity storage adapter primitives. `config.py` owns shared settings. `errors.py` and `exceptions.py` own shared error behavior. `logging.py` owns structlog setup and request context helpers. `secrets.py` owns secret-manager loading. `trust/` owns trusted-service/proxy helpers.

This library is consumed by multiple services, so changes here are platform-wide even when they look small.

## Critical Behaviors

- Keep provider and metadata-store implementations behaviorally aligned across AWS, Azure, GCP, and local.
- Keep provider-specific logic behind existing factory and interface patterns.
- Preserve metadata-store singleton and optional TTL caching semantics.
- Preserve GCP auth behavior that uses SHA-256 of the raw API key when key IDs are not injected.
- Preserve request-context binding and clearing behavior so structured logs remain request-scoped.
- Preserve public contracts unless an explicit cross-service change is intended.
- Treat activity abstractions as platform-wide public contracts. Keep service-specific lifecycle decisions out of `taproot-common`; services should pass domain facts to the shared activity Interface rather than importing activity database details.

## Verification

Use local pytest, ruff, and mypy checks in `taproot-common/`. When changing auth, metadata, logging, errors, secrets, or audit behavior, update library tests and consider downstream service impact. Validate against the live AWS environment when the change affects deployed service behavior.
