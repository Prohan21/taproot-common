# AGENTS.md

Follow `taproot-common/AGENTS.md` and `taproot-common/src/taproot_common/AGENTS.md` first. This file adds auth-local guidance.

## Auth Invariants

- AWS and Azure auth rely on gateway/APIM-injected API key IDs such as `X-Api-Key-Id`.
- GCP derives the key ID with SHA-256 of the raw `x-api-key` when the gateway cannot inject a key ID.
- DynamoDB, CosmosDB, Firestore, and memory metadata stores must remain behaviorally aligned.
- Preserve the metadata-store singleton and TTL cache semantics.
- Public caller, actor, and correlation headers are not auth or audit authority.

## Testing Guidance

- Reset the metadata-store singleton in tests that mutate env vars or backend selection.
- Update auth tests whenever provider behavior, header handling, or metadata lookup semantics change.
