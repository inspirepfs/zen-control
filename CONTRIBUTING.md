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
python3 -m unittest discover -s tests -t . -v
docker compose --env-file .env.example config >/dev/null
```

Add focused hostile/regression tests for changes to authentication, authority, migration, policy resolution, evidence semantics and failure recovery.

## Release patch workflow

`python3 scripts/release_patch.py` automates the qualified host release path: exact `-p0` patch dry-run/application, validation, bounded Compose rebuild, health proof, Git stage/commit/push, GitHub Actions watch, and optional annotated tag push.

The safe default rebuild target is `mikrotik-control`; use repeated `--rebuild-service` options or `--rebuild-all` only when a release actually changes other services. Relative patch names are resolved from the repository and then `../`, matching the normal host layout. Tagging is fail-closed behind a successful watched GitHub Actions run unless an explicit `--allow-tag-without-ci` exception is supplied.

Typical release:

```bash
python3 scripts/release_patch.py \
  --patch zen-control-v0.54.0-example.patch \
  --message "Release v0.54.0 example" \
  --expect-version 0.54.0 \
  --tag v0.54.0
```

When a patch has already been applied intentionally, resume from the dirty release tree instead of applying it again:

```bash
python3 scripts/release_patch.py \
  --resume \
  --message "Fix v0.54.0 clean-runner CI qualification"
```

Use `--dry-run` to print the planned commands without modifying source, Git or containers. Run `python3 scripts/release_patch.py --help` for all workflow switches.

## Pull requests

Keep a pull request coherent around one engineering objective. Explain:

- the user/operational problem;
- authority/evidence boundaries touched;
- failure and rollback behaviour;
- tests added/changed;
- whether deployment configuration changes;
- whether a RouterOS mutation surface is added or widened.

Do not include household-specific data, secrets or copied runtime databases.
