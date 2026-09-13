# Installation and Commissioning

This document describes the supported Docker Compose deployment at a high level. ZEN is not yet a one-click appliance; RouterOS authority must be understood and prepared deliberately.

## 1. Host prerequisites

Use a Linux host with:

- Docker Engine and Docker Compose v2;
- a stable LAN address;
- outbound Internet access for image pulls/certificate issuance;
- network reachability to the MikroTik RouterOS API;
- enough storage for PostgreSQL telemetry retention.

## 2. Clone and configure

```bash
git clone https://github.com/inspirepfs/zen-control.git
cd zen-control
cp .env.example .env
```

Replace every placeholder in `.env`. Never commit this file.

Important settings include:

- `ADMIN_USER`, `ADMIN_PASSWORD`
- `SESSION_SECRET`
- `OTP_ENCRYPTION_KEY`
- `MIKROTIK_HOST`, `MIKROTIK_PORT`, `MIKROTIK_USER`, `MIKROTIK_PASSWORD`
- `TELEMETRY_DB_PASSWORD`
- `PIHOLE_PASSWORD`
- `ZEN_LAN_BIND_IP`, `ZEN_LAN_CIDRS`
- `ZEN_LOCAL_HOST`, `CADDY_CF_API_TOKEN` when local HTTPS is enabled
- `ZEN_ROUTER_OBSERVE_WORKERS` for bounded automatic-reconciler read-side planning concurrency (`4` by default, clamped to `1`–`8`)

Generate application secrets with a cryptographically secure generator, for example:

```bash
python3 -c 'import secrets; print(secrets.token_urlsafe(48))'
```

Keep `OTP_ENCRYPTION_KEY` stable after authenticators are enrolled.

### Optional notification delivery

Outbound SMTP connection details and credentials are environment-only. Configure them in `.env`; they are injected into the application by `docker-compose.yml` and are never stored in `policy.db`:

```text
ZEN_SMTP_ENABLED=0
ZEN_SMTP_HOST=
ZEN_SMTP_PORT=587
ZEN_SMTP_USERNAME=
ZEN_SMTP_PASSWORD=
ZEN_SMTP_FROM=
ZEN_SMTP_FROM_NAME=ZEN Control
ZEN_SMTP_TO=
ZEN_SMTP_STARTTLS=1
ZEN_SMTP_SSL=0
ZEN_SMTP_TIMEOUT_SECONDS=10
```

Webhook destination metadata is configured in ZEN, while the HMAC signing secret remains environment-only:

```text
ZEN_WEBHOOK_SIGNING_SECRET=
ZEN_WEBHOOK_TIMEOUT_SECONDS=10
ZEN_WEBHOOK_MAX_ATTEMPTS=5
ZEN_WEBHOOK_ALLOW_HTTP=0
```

Production webhooks should use HTTPS. `ZEN_WEBHOOK_ALLOW_HTTP=1` exists only for controlled local simulation.

For end-to-end testing without external infrastructure, start the optional local sinks:

```bash
docker compose --profile test-tools up -d --build
```

A typical local simulation uses Mailpit at `mailpit:1025` with TLS disabled and configures the ZEN webhook destination as `http://webhook-sink:8092/webhook`. The host-only inspection UIs are `http://127.0.0.1:8025` for Mailpit and `http://127.0.0.1:8092` for the webhook sink. The webhook sink can deliberately return `429`, `500` or `410` by adding `?status=429`, `?status=500` or `?status=410` to the endpoint. Restore `ZEN_WEBHOOK_ALLOW_HTTP=0` after local simulation.

`ZEN_ROUTER_OBSERVE_WORKERS` controls only parallel observation/planning in the automatic reconciler. Increasing it does not parallelize RouterOS mutation: all app-owned writes still pass through the single serialized mutation lane and are preceded by fresh authority/security proof.

## 3. RouterOS preparation

Read [../routeros/README.md](../routeros/README.md) before enabling ZEN writes. Start with the supplied read-only inspection helpers and compare the router with the authority contract expected by the application.

Do not paste credentials into RouterOS scripts or the repository.

## 4. Validate Compose

```bash
docker compose config >/dev/null
```

Then start the stack:

```bash
docker compose up -d --build
```

Inspect status and application logs:

```bash
docker compose ps
docker compose logs --tail=100 mikrotik-control
```

## 5. Local HTTPS and PWA commissioning

The bundled Caddy image includes the Cloudflare DNS provider. Configure the non-secret local identity and the DNS API credential in `.env`:

```text
ZEN_LOCAL_HOST=zen.example.com
ZEN_LAN_BIND_IP=192.168.1.10
CADDY_CF_API_TOKEN=<DNS API token>
```

Your LAN DNS should resolve `ZEN_LOCAL_HOST` directly to `ZEN_LAN_BIND_IP`. The DNS API token is passed only to Caddy; ZEN receives the local hostname and bind IP for sanitized commissioning status, never the token.

Validate Caddy independently:

```bash
docker compose run --rm --no-deps zen-local-https \
  caddy validate --config /etc/caddy/Caddyfile
```

Before enabling Secure cookies, make sure the Host allowlist includes the local HTTPS hostname and the loopback health-check identity, for example:

```text
ZEN_ALLOWED_HOSTS=zen.example.com,localhost,127.0.0.1
```

Then enable Secure cookies and recreate ZEN:

```text
ZEN_SECURE_COOKIES=1
```

```bash
python3 scripts/env_validate.py
docker compose up -d --force-recreate mikrotik-control zen-local-https
```

Run the host-side local TLS/PWA prerequisite proof using the real local hostname. Normal certificate-chain and hostname validation remain enabled; there is no insecure TLS bypass:

```bash
python3 scripts/transport_acceptance.py \
  --local-url https://zen.example.com/ \
  --expect-version 0.57.0 \
  --require-hsts
```

A local PASS proves the HTTPS health route, browser-security headers, HSTS, root-scope service worker and manifest prerequisites. It does **not** manufacture browser evidence. Open the HTTPS URL on the target Android/Chromium device and verify the PWA reports `READY`/`INSTALLED`, then enable browser push and send a push test from Notifications.

## 6. Optional Cloudflare remote access

Remote access is optional and remains disabled by default. Create the Cloudflare Access application **before** publishing the Tunnel route. The route should point to:

```text
http://mikrotik-control:8080
```

Store the remotely-managed tunnel token outside the source tree. The pinned cloudflared container runs as UID/GID `65532:65532`; a host token file can therefore be owned `root:65532` with mode `0640`.

When remote access is deliberately enabled, the Host allowlist must cover both the local hostname and `ZEN_PUBLIC_HOST`; `ZEN_SECURE_COOKIES=1` and `ZEN_CLOUDFLARE_ACCESS_PROTECTED=1` are mandatory.

Start the connector profile explicitly:

```bash
docker compose --profile remote-access up -d cloudflared
```

Prove the unauthenticated public edge is intercepted by Cloudflare Access:

```bash
python3 scripts/https_acceptance.py https://zen-public.example.net/
```

Or combine local and public proof in one report:

```bash
python3 scripts/transport_acceptance.py \
  --local-url https://zen.example.com/ \
  --public-url https://zen-public.example.net/ \
  --expect-version 0.57.0 \
  --require-hsts
```

The public probe deliberately never logs in and accepts no credentials. An authenticated remote ZEN/PWA journey remains a manual commissioning check after the Access challenge is proven.

## 7. First application commissioning

Before relying on automatic enforcement:

1. Enrol parent TOTP and save recovery codes securely.
2. Review Settings → Security and verify RouterOS authority.
3. Confirm automatic reconciliation mode deliberately.
4. Add/manage devices and verify static DHCP identity.
5. Exercise a read-only policy explanation/Device 360 path.
6. Perform one explicitly approved guarded write and confirm post-write state.
7. Review Operational Diagnostics and Release Readiness.

## Backup and recovery

The normal `scripts/release_patch.py` workflow now creates and validates an external SQLite backup before any release that rebuilds `mikrotik-control`, then runs an offline restore/upgrade smoke before container recreation. Backups default to `../zen-backups` and can be redirected with `--backup-dir`; `--skip-policy-backup` is an explicit emergency override and should not be used for routine releases. Keep authentication secrets and tunnel credentials outside source control. A restored `policy.db` without the matching `OTP_ENCRYPTION_KEY` cannot decrypt enrolled authenticator secrets.
