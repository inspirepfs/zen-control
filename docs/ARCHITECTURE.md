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

## Current persistence and background-work model

v0.54.1 uses:

- SQLite for policy/configuration and durable control-plane state;
- a monotonic configuration revision journal for revision-aware writes;
- a transactional SQLite outbox for `config.changed` events;
- durable background jobs with idempotency keys, bounded attempts, leases and scope locks;
- durable worker metrics for operational evidence;
- bounded `prepared_views` rows for current derived read models;
- PostgreSQL 17 for retained telemetry/history;
- named Docker volumes for Pi-hole, Caddy and telemetry state.

Prepared views are not authority and are not trusted merely because a row exists. Consumers require the current configuration revision and a bounded freshness window; stale, expired or mismatched rows fall back to the live read path. Periodic jobs prepare Dashboard/Activity/Classification/Services/History telemetry and per-device Device 360 activity evidence. Device 360 still reads RouterOS authority synchronously and only reuses prepared telemetry evidence.

The background worker receives no RouterOS adapter. RouterOS mutation remains serialized through the existing reconciliation/authority paths. Terminal background-job/outbox bookkeeping is pruned only under bounded retention rules that preserve active work and a recent evidence floor.

### Parallel observation and serialized mutation

v0.54.2 separates observation concurrency from mutation authority. The automatic reconciler may fan out independent per-device read/plan work through a bounded thread pool, but those results are advisory evidence only. Before ENFORCE writes, the reconciler owns the single RouterOS mutation lane, re-proves the security posture and performs a fresh serial plan read for each candidate. A plan that became stale can therefore cause a skipped/delayed write, never an unauthorized write.

All public app-owned RouterOS mutators are guarded at the adapter boundary by the same re-entrant mutation lane. Multi-step manual routes hold that lane across the complete action, while nested adapter methods reuse the same ownership. Kid Control authority transfer keeps a strict lock order of reconciler cycle lock then RouterOS mutation lane so automatic enforcement and cutover/rollback cannot deadlock or interleave. Read-only RouterOS methods and the durable background analytics worker do not acquire mutation authority.
### Deployment topology and runtime health

v0.54.3 extends the same evidence-first model to deployment. The release helper derives affected Compose services from the source delta, snapshots the live topology before any recreate, and requires that previously-running services return after the targeted rebuild. Successful one-shot services remain valid as completed rather than being misclassified as stopped. Bind-mounted configuration targets are force-recreated when affected so a changed file cannot remain attached to a stale process.

Application liveness is not sufficient on its own. `/health/runtime` reports a deliberately minimal non-secret contract for the embedded background worker, reconciler, incident monitor and summary-delivery worker, plus configured ephemeral observation concurrency and mutation-lane availability. Release publication stops before Git staging if either runtime worker health or the preserved Compose topology fails to recover. PostgreSQL init-script changes are excluded from automatic recreate because an existing persistent volume requires an explicit migration rather than a container restart.

### Formal performance acceptance

v0.54.4 closes the performance programme with a fail-closed acceptance contract layered over the existing v0.30/v0.30.1/v0.39 instrumentation. Request classes retain every valid sample for percentile calculation and report min/p50/p95/p99/max. Failed requests are not converted into healthy latency, missing RouterOS connection evidence remains PENDING, and any valid RouterOS request that opens more than one transport fails the coherent-session budget.

Operational telemetry is deliberately read-only. Prepared-view consumers count eligible hits and live fallbacks; the background read worker exposes in-memory cycle timing without querying durable state just to render the performance page; the reconciler exposes its last bounded parallel-observation utilisation; and the RouterOS adapter exposes only mutation-lane acquisition/contention/wait counters. None of these surfaces can authorize a RouterOS write. The authority order remains: serialized mutation lane → fresh security proof → fresh relevant reread → calculate → write → verify.
