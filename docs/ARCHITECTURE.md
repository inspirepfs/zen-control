# ZEN Control Architecture

## Design goals

ZEN Control separates policy intent, RouterOS enforcement authority and retained observation. The application can compute and explain desired state without implying that a missing telemetry sample or historical checkpoint proves live network execution.

The guiding concurrency rule is:

> Parallelise observation and computation where it is safe; serialize authority changes.

## Components

### Control application

`app/` is a FastAPI application with Jinja-rendered UI, parent authentication, policy resolution, simulation, diagnostics and the RouterOS adapter.

SQLite (`policy.db`) stores policy/configuration plus durable operational state such as audit, incidents, migration records and configuration checkpoints.

### RouterOS

RouterOS remains the enforcement point. ZEN reads current router state and performs bounded writes only through validated adapter paths. Critical/static firewall authority is not silently repaired by the application.

The restricted-web path uses explicitly named authority anchors and app-managed namespaces. Custom service contracts are deterministic and must be approved before they can acquire write authority.

### Telemetry

MikroTik exports IPFIX to GoFlow2. The telemetry ingest process combines flow evidence with Pi-hole DNS evidence and stores retained activity in PostgreSQL.

The application publishes a sanitized live service-classifier catalogue into a shared volume. This allows custom service metadata to participate in reporting without giving the telemetry worker RouterOS authority.

### HTTPS and remote access

Local HTTPS is provided by Caddy using DNS-01 certificate issuance. Remote access is optional and uses Cloudflare Access plus an outbound Cloudflare Tunnel. Neither path changes RouterOS policy authority.

## Authority boundaries

The most important boundaries are:

1. Read-only analysis must not become a hidden write path.
2. RouterOS changes require fresh authority validation where the contract says they do.
3. Post-write validation is evidence, not an optimization target to remove.
4. Aggregate policy groups expand to concrete services and never receive aggregate RouterOS rules.
5. Kid Control migration may toggle the exact validated legacy profile `disabled` field but does not edit/delete legacy device rows or schedules.
6. A failed migration restores legacy authority before local migration-owned state is unwound.

## Evidence model

Desired policy, live RouterOS state and retained network evidence are separate evidence classes.

Examples:

- `BLOCK REQUESTED` can exist without an enforceable RouterOS contract.
- `NO CONTRACT` is not the same as `ALLOW`.
- `UNAVAILABLE` telemetry is not zero activity.
- A desired-policy checkpoint does not prove historical enforcement for every instant in the interval.
- DNS/IPFIX observations do not prove foreground application use, browser history, intent or user identity.

## Current persistence model

v0.53.1 uses:

- SQLite for policy/configuration and durable control-plane state.
- PostgreSQL 17 for retained telemetry/history.
- named Docker volumes for Pi-hole, Caddy and telemetry state.

The next architecture slice is planned to add revisioned configuration state, optimistic concurrency, a transactional outbox and durable background-job primitives while retaining one logical enforcement writer.
