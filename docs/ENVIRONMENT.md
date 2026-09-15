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

## Safe configuration workflow

1. Copy `.env.example` to `.env`; never edit `.env.example` with deployment values.
2. Replace all required placeholders and generate independent random authentication/encryption secrets.
3. Run `python3 scripts/env_validate.py` before `docker compose config`.
4. Review the rendered Compose configuration for topology only; do not paste it into public issues because secret interpolation may be present.
5. Recreate affected services after changing environment values. A running container does not automatically receive changes made to the host `.env`.
6. Preserve long-lived encryption/signing material across backup/restore where the owning subsystem requires it.

A good operational rule is: **configuration names may be documented; deployment values are private unless explicitly designed as public identity.**

## Configuration groups

The public `.env.example` is the canonical variable list. The most important groups are:

| Group | Examples | Notes |
| --- | --- | --- |
| Parent authentication | `ADMIN_USER`, `ADMIN_PASSWORD`, `SESSION_SECRET` | `ADMIN_PASSWORD` and `SESSION_SECRET` are secrets. |
| TOTP encryption | `OTP_ENCRYPTION_KEY`, `OTP_ISSUER` | Keep the encryption key stable after enrolment and across database restore. |
| RouterOS API | `MIKROTIK_HOST`, `MIKROTIK_PORT`, `MIKROTIK_USER`, `MIKROTIK_PASSWORD` | Use a dedicated API account and trusted management path. |
| Telemetry/PostgreSQL | `TELEMETRY_DB_*`, `PIHOLE_PASSWORD` | Treat retained telemetry as household-sensitive data. |
| Local HTTPS | `ZEN_LOCAL_HOST`, `ZEN_LAN_BIND_IP`, `ZEN_LAN_CIDRS`, `CADDY_CF_API_TOKEN` | DNS API token is secret and is isolated to Caddy. |
| Remote access | `ZEN_REMOTE_ACCESS_ENABLED`, `ZEN_PUBLIC_HOST`, `CLOUDFLARE_TUNNEL_TOKEN_FILE` | Remote mode also requires Access protection, secure cookies and allowed-host coverage. |
| Notifications | `ZEN_SMTP_*`, `ZEN_WEBHOOK_*`, `ZEN_PUSH_*` | Secrets remain environment/file backed; destination metadata may live in SQLite where documented. |
| Performance/reconciler tuning | `ZEN_PERF_*`, `ZEN_ROUTER_OBSERVE_WORKERS` | Tuning never grants extra RouterOS write concurrency. |

## Contract classes

ZEN uses these configuration classes:

- **required** — Compose or the deployment topology cannot start correctly without a value;
- **required-secret** — required, with a value that must never be committed or surfaced;
- **optional** — has a bounded application/Compose default or enables optional tuning;
- **optional-secret** — a secret used only by an optional subsystem;
- **conditional** — required only when its owning feature is enabled;
- **conditional-secret** — a secret required only for an enabled optional feature;
- **internal** — container/runtime wiring with a safe bounded default or a hard-coded Compose value; not a host `.env` setting;
- **deprecated** — retained temporarily for compatibility and reported explicitly by the validator. There are no deprecated entries in v0.59.0.

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

## Change and restart semantics

Host-side Compose interpolation happens when the service is created. After changing `.env`, validate again and recreate the affected service(s), for example:

```bash
python3 scripts/env_validate.py
docker compose config >/dev/null
docker compose up -d --force-recreate mikrotik-control
```

Use the release helper for qualified software upgrades because it also performs backup/restore smoke and topology/runtime proof. Manual recreation is appropriate for deliberate local configuration changes when you understand the affected service.

## Secrets

`.env.example` must contain blank values or obvious placeholders for secrets. Real deployment secrets belong in the untracked `.env` or the existing file-backed secret mechanism where documented.

Never paste live passwords, API tokens, signing secrets, VAPID private keys or tunnel tokens into `.env.example`, source files, test fixtures, issue reports or support bundles.

## Rotation notes

- Rotate `ADMIN_PASSWORD`, RouterOS API passwords, database passwords and external-delivery credentials if exposure is suspected.
- Changing `SESSION_SECRET` invalidates existing sessions.
- Changing `OTP_ENCRYPTION_KEY` without a controlled re-enrolment/migration makes existing encrypted authenticator material unreadable.
- Treat a leaked Cloudflare API/tunnel token as compromised even if it is later removed from a file or Git history.
- After credential rotation, recreate the owning service and prove the associated health path before considering the rotation complete.
