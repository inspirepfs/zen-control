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

Generate application secrets with a cryptographically secure generator, for example:

```bash
python3 -c 'import secrets; print(secrets.token_urlsafe(48))'
```

Keep `OTP_ENCRYPTION_KEY` stable after authenticators are enrolled.

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

## 5. Local HTTPS

The bundled Caddy image includes the Cloudflare DNS provider. Configure:

```text
ZEN_LOCAL_HOST=zen.example.com
ZEN_LAN_BIND_IP=192.168.1.10
CADDY_CF_API_TOKEN=<DNS API token>
```

Your LAN DNS should resolve `ZEN_LOCAL_HOST` directly to `ZEN_LAN_BIND_IP`.

Validate Caddy independently:

```bash
docker compose run --rm --no-deps zen-local-https \
  caddy validate --config /etc/caddy/Caddyfile
```

## 6. Optional Cloudflare remote access

Remote access is disabled by default. Create the Cloudflare Access application **before** publishing the Tunnel route. The route should point to:

```text
http://mikrotik-control:8080
```

Store the remotely-managed tunnel token outside the source tree. The pinned cloudflared container runs as UID/GID `65532:65532`; a host token file can therefore be owned `root:65532` with mode `0640`.

Enable the relevant `.env` settings only after Access and the Tunnel route are protected.

Start the connector profile explicitly:

```bash
docker compose --profile remote-access up -d cloudflared
```

Use `scripts/https_acceptance.py` from an external client to prove unauthenticated requests are intercepted by Cloudflare Access.

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

Back up the Docker volumes and application configuration before major upgrades. Keep authentication secrets and tunnel credentials outside source control. A restored `policy.db` without the matching `OTP_ENCRYPTION_KEY` cannot decrypt enrolled authenticator secrets.
