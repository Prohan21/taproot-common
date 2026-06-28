# AGENTS.md

Follow `taproot-common/AGENTS.md` first. This file adds source-local guidance for `src/taproot_common/`.

## Source Map

- `activity/` owns TAP-38 System of Record models, context, recorder, storage, and schema metadata.
- `trust/` owns internal bearer/delegated actor token helpers and header policy.
- `auth/` owns APIM auth, auth providers, middleware, and metadata stores.
- `fastapi/`, `errors.py`, `logging.py`, `config.py`, and `secrets.py` provide shared backend runtime plumbing.

## Local Invariants

- Keep shared code provider-neutral; AWS, Azure, GCP, and local behavior must stay aligned behind interfaces.
- Do not let public caller/actor headers become auth or audit authority.
- Do not create/drop System of Record SQL from Python runtime code; executable schema changes belong in Alembic migrations.
- Safe activity evidence must reject raw payloads by default.
