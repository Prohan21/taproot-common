# AGENTS.md

Follow `taproot-common/AGENTS.md` first. This file adds test-local guidance.

## Testing Guidance

- Reset auth metadata singletons around tests that mutate environment variables or provider/backend selection.
- Preserve System of Record migration preflight tests, especially fail-closed behavior for mismatched revisions or missing tables/columns.
- Activity tests should cover project/system scope, raw payload rejection, idempotency conflicts, critical persistence failure, and async failure visibility.

## Targeted Commands

```bash
uv run pytest tests/test_activity_*.py -v --tb=short
uv run pytest tests/test_auth.py tests/test_trust.py -v --tb=short
```
