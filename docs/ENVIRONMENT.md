# Environment configuration contract

ZEN treats environment configuration as a release contract rather than an informal collection of variables.

The canonical public host-variable catalogue is `.env.example`. Its variable names must match the host-side `${...}` interpolation used by `docker-compose.yml`. Runtime-only variables injected inside containers remain internal and are explicitly tracked by the validator instead of being copied into `.env.example`.

Run the static contract check with:

```bash
python3 scripts/env_validate.py --no-local
```

On a deployment host, run:

```bash
python3 scripts/env_validate.py
```

If `.env` exists, the second form validates it as well. Output contains variable names and contract state only; values from `.env` are never printed.

## Contract classes

ZEN uses these configuration classes:

- **required** — Compose or the deployment topology cannot start correctly without a value;
- **required-secret** — required, with a value that must never be committed or surfaced;
- **optional** — has a bounded application/Compose default or enables optional tuning;
- **optional-secret** — a secret used only by an optional subsystem;
- **conditional** — required only when its owning feature is enabled;
- **conditional-secret** — a secret required only for an enabled optional feature;
- **internal** — container/runtime wiring with a safe bounded default or a hard-coded Compose value; not a host `.env` setting;
- **deprecated** — retained temporarily for compatibility and reported explicitly by the validator. There are no deprecated entries in v0.58.0.

The older `SUMMARY_*` variables remain **active**, not deprecated: they belong to Parent Summary delivery and are separate from the v0.55 external Notification Delivery adapters.

## Conditional validation

The deployment validator currently fail-closes these relationships:

- `ZEN_SMTP_ENABLED=1` requires `ZEN_SMTP_HOST`, `ZEN_SMTP_FROM` and `ZEN_SMTP_TO`;
- SMTP implicit SSL and STARTTLS cannot both be enabled;
- `ZEN_WEBHOOK_ALLOW_HTTP=1` requires a webhook signing secret, because HTTP is supported only for the local signed simulator path;
- `ZEN_SECURE_COOKIES=1` requires an explicit `ZEN_ALLOWED_HOSTS` entry covering `ZEN_LOCAL_HOST` plus `127.0.0.1` so release health checks cannot be locked out;
- local HTTPS with `ZEN_SECURE_COOKIES=0` is accepted as an upgrade-safe configuration but is reported as incomplete commissioning;
- `ZEN_REMOTE_ACCESS_ENABLED=1` requires the public host, explicit allowed hosts covering that public host, the Cloudflare tunnel-token file reference, secure cookies and confirmed Cloudflare Access protection.

Subsystems whose enablement lives in `policy.db` rather than `.env` still validate their environment requirements at their owning runtime boundary.

## Drift prevention

`env_validate.py` checks four surfaces together:

1. `.env.example` has no duplicate names and no real-looking secret defaults;
2. every host-side Compose interpolation is documented by `.env.example`, and every `.env.example` variable is consumed by Compose;
3. every source environment reference is either part of the host contract or explicitly classified as internal;
4. when `.env` exists, it has no undocumented variables, contains all required values and satisfies enabled-feature conditional rules.

The check runs in both `scripts/release_patch.py` and the GitHub `Quality` workflow. A newly introduced environment variable therefore cannot silently bypass the documented configuration contract.

## Secrets

`.env.example` must contain blank values or obvious placeholders for secrets. Real deployment secrets belong in the untracked `.env` or the existing file-backed secret mechanism where documented.

Never paste live passwords, API tokens, signing secrets, VAPID private keys or tunnel tokens into `.env.example`, source files, test fixtures, issue reports or support bundles.
