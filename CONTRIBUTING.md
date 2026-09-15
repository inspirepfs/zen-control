# Contributing to ZEN Control

Thanks for taking an interest in ZEN Control. Contributions are welcome, but changes that affect RouterOS authority, authentication, upgrade safety or evidence semantics need stronger proof than ordinary presentation changes.

## Development principles

Changes must preserve these contracts:

- RouterOS authority is explicit, bounded and serialized.
- Read-only analysis/background work must not create a hidden write path.
- Critical writes retain fresh authority/security proof, a fresh relevant reread and post-write verification.
- Missing/degraded evidence is not coerced into healthy/zero state.
- Desired policy/checkpoints are not historical enforcement proof.
- Aggregate policy groups remain logical expansion only.
- Kid Control device rows/schedules are not edited or deleted by migration.
- Public documentation must distinguish application version `0.59.0` from `v0.59.0.x` maintenance tags.

## Development setup

Use a Python virtual environment and the same dependency contract as the container:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Use synthetic/non-household values in development fixtures. Do not copy a live `.env`, database or RouterOS export into the repository.

## Local quality gates

Run at least:

```bash
python3 scripts/env_validate.py --no-local
python3 -m py_compile app/*.py telemetry/ingest/*.py
python3 scripts/ux_validate.py
python3 scripts/public_release_audit.py
python3 -m unittest discover -s tests -t . -v
docker compose --env-file .env.example config >/dev/null
```

Add focused hostile/regression tests for changes to authentication, authority, migration, policy resolution, evidence semantics, persistence/upgrade, dependency compatibility and failure recovery.

### Runtime smoke after framework/dependency changes

Changes to FastAPI, Starlette, Jinja, middleware, template wrappers, form parsing or container dependencies must also exercise the **rebuilt runtime**, not only source-level unit tests. At minimum verify:

```text
/health/live       returns 200
/health/runtime    returns 200
/login             renders successfully
an authenticated dashboard route renders successfully
```

The v0.59.0.4 → v0.59.0.5 incident is the reason this is explicit: health endpoints remained green while the old Starlette `TemplateResponse(name, context)` call shape caused server-rendered HTML to fail with HTTP 500.

GitHub Quality now enforces this automatically with `scripts/runtime_acceptance.py` in the `runtime-container-smoke` job. The CI smoke uses synthetic credentials and an unreachable loopback RouterOS endpoint, proves `/health/live`, `/health/runtime`, `/login` and an authenticated dashboard render, and intentionally does not treat RouterOS readiness as part of this HTML/runtime compatibility gate.

## Documentation expectations

A user-visible or operator-visible change should update the relevant public document in the same change. Prefer stable operational language over development-slice shorthand. New environment variables must be reflected in `.env.example` and the environment contract; RouterOS assumptions belong in `routeros/`; release/process changes belong in `docs/PUBLIC_RELEASE.md`.

## Release patch workflow

`scripts/release_patch.py` automates the qualified host release path and fail-closes on environment-contract drift before compilation. It performs exact `-p0` patch dry-run/application, validation, verified pre-rebuild SQLite backup plus offline restore/upgrade smoke when `mikrotik-control` is affected, affected-service Compose rebuild, app/runtime/topology health proof, Git stage/commit/push, GitHub Actions watch and optional annotated tag push.

The safe default is automatic affected-service detection from the release delta. Repeated `--rebuild-service` options add explicit services and `--rebuild-all` deliberately expands deployment to the whole Compose project. Tagging is fail-closed behind successful watched GitHub Actions unless an explicit exception is supplied.

Current maintenance-release example:

```bash
python3 scripts/release_patch.py \
  --patch ../zen-control-v0.59.0.6-documentation-hardening.patch \
  --message "Release v0.59.0.6 documentation hardening" \
  --expect-version 0.59.0 \
  --tag v0.59.0.6
```

Notice that `--expect-version` checks the **application version**, while `--tag` identifies the maintenance release.

When a patch has already been applied intentionally, use the supported resume path rather than trying to apply it a second time. Use `--dry-run` to print planned commands without modifying source, Git or containers. Run `python3 scripts/release_patch.py --help` for current switches.

## Pull requests

Keep a pull request coherent around one engineering objective. Explain:

- the user/operational problem;
- authority/evidence boundaries touched;
- failure and rollback behaviour;
- tests added/changed;
- runtime/container smoke performed when relevant;
- documentation updated;
- whether deployment configuration changes;
- whether a RouterOS mutation surface is added or widened.

Do not include household-specific data, secrets or copied runtime databases.

## Public-release hygiene

Before public release work also run:

```bash
python3 scripts/public_release_audit.py --history --deployment-markers
```

Historical deployment identity warnings require review; current-tree deployment identity or secret findings are not acceptable release state.

## License

By submitting a contribution, you agree that it may be distributed under the project's **GNU AGPL v3.0 or later (`AGPL-3.0-or-later`)** license unless an explicit, accepted exception says otherwise.
