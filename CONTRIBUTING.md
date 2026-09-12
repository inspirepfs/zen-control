# Contributing to ZEN Control

Thanks for taking an interest in ZEN Control.

## Development principles

Changes should preserve these contracts:

- RouterOS authority is explicit and bounded.
- Read-only analysis must not create a hidden write path.
- Critical writes use fresh validation where required and retain post-write proof.
- Missing/degraded evidence is not coerced into healthy/zero state.
- Desired policy is not historical enforcement proof.
- Aggregate groups remain logical expansion only.
- Kid Control device rows/schedules are not edited or deleted by migration.

## Local checks

```bash
python3 -m py_compile app/*.py telemetry/ingest/*.py
python3 scripts/ux_validate.py
python3 scripts/public_release_audit.py
python3 -m unittest discover -s tests -v
docker compose --env-file .env.example config >/dev/null
```

Add focused hostile/regression tests for changes to authentication, authority, migration, policy resolution, evidence semantics and failure recovery.

## Pull requests

Keep a pull request coherent around one engineering objective. Explain:

- the user/operational problem;
- authority/evidence boundaries touched;
- failure and rollback behaviour;
- tests added/changed;
- whether deployment configuration changes;
- whether a RouterOS mutation surface is added or widened.

Do not include household-specific data, secrets or copied runtime databases.
