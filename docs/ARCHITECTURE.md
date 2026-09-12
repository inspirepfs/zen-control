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

### Final release-readiness closure

v0.54.5 binds the application release gate to the architecture actually running after v0.54.4. The gate remains exactly eight current checks and reaches final readiness only at **PASS 8 / PENDING 0 / FAIL 0**. Runtime readiness combines normal database/RouterOS/reconciler readiness with the minimal v0.54.3 embedded-worker and mutation-lane health contract. Live performance consumes the complete `zen_formal_performance_acceptance_v1` result, so request latency alone cannot satisfy release readiness when prepared-view, background-worker, parallel-observation, mutation-lane or canonical-threshold evidence is missing or failing.

The portable `zen_release_readiness_v2` artifact carries bounded blocker attribution and rejects contradictory state/counts through `scripts/release_acceptance.py`. Source-qualified closure history remains separate from live evidence. HTTPS/public-edge commissioning and notification expansion remain outside the eight application checks and cannot manufacture application readiness. No RouterOS write authority, background write authority or mutation concurrency is added by this closure.
## v0.54.5.3 — Navigation tail-latency closure

Normal navigation now completes the read/write separation introduced by v0.54.5.1–v0.54.5.2.1. Dashboard favourite cards consume the same revision-bound desired-policy projection already produced during reconciler observation instead of re-running effective-policy resolution for every managed device. Settings → Operations consumes a revision-bound managed-state inventory seeded at startup and refreshed by the reconciler outside the browser request path. An explicit inventory API remains the operator-owned live verification path.

The shared `index.html` template is compiled during startup so one-time Jinja parsing is not charged to the first user navigation request. Performance classification also distinguishes local RouterOS observability bookkeeping from transport-requiring RouterOS calls, preserving the exact one-connection gate without manufacturing missing-connection evidence from in-process status checks.

These optimisations are query-side only. Advisory policy and inventory evidence never enters mutation authority; writes retain serialized mutation lane → fresh security proof → fresh RouterOS reread → calculation → write → verification.

## v0.54.5.2.1 — Prepared read-path and fan-out closure

Normal Dashboard, Activity and Managed Devices navigation is a query-side concern, not a RouterOS authority boundary. These surfaces consume revision-bound prepared evidence produced by the durable analytics worker and by the reconciler's already-fresh observation phase. A same-revision `ready` row may be served after its freshness TTL only as explicitly **STALE** evidence within a bounded grace window while a refresh is requested; evidence beyond that grace becomes MISSING/PREPARING, and a configuration-revision mismatch is never served.

Activity preparation executes related PostgreSQL queries inside one coherent read session. Periodic prepared jobs are coalesced so only the latest pending kind/scope remains queued; running leased work is never cancelled. Normal navigation no longer falls back to synchronous heavy analytics when the model is missing—it reports PREPARING/MISSING and leaves generation to the background worker.

This optimisation does not widen authority. Prepared RouterOS observations are advisory display evidence only. Mutation paths never consume them and retain the established sequence: serialized mutation lane → fresh security proof → fresh RouterOS reread → calculation → write → post-write verification.

## v0.54.5.1 — Request-path decoupling and durable reconciliation intent

Declarative policy apply is now a command/worker boundary rather than a synchronous RouterOS HTTP transaction. The request validates CSRF/role, durably records a reconciliation intent against the current configuration revision, wakes the reconciler and returns. `AutoReconciler` is the only consumer that can convert that intent into RouterOS mutation authority. It owns the existing reconciliation cycle lock and serialized mutation lane, freshly re-proves security posture, freshly re-reads desired/live state, applies the minimal drift and verifies convergence. A desired-state revision change during the operation marks the request superseded and queues the latest revision for another fresh pass.

The read side is similarly explicit. Dashboard security/service-contract evidence may be served from revision-bound prepared RouterOS observations with FRESH/STALE/MISSING metadata so normal navigation does not block on multi-second authority probes. These observations are advisory only. Mutation, authority transfer, recovery and other write-sensitive paths continue to use fresh RouterOS evidence.

Performance reporting separates **ACK latency** (HTTP request through durable local queueing) from **convergence latency** (queue creation through verified RouterOS convergence), including queue-wait and worker-processing percentiles. This prevents moving work to a worker from falsely appearing to make RouterOS itself instantaneous.
