## v0.55.4.2 — Notification Delivery Navigation Hotfix

- Fixes the Notifications subsection navigation so the existing **Delivery** surface is actually exposed in the generated sub-navigation between Intelligence and History.
- Keeps the v0.55.4 external-delivery routes, SMTP/webhook adapters, simulator profile, persistence and authority boundaries unchanged; this is a presentation/navigation repair only.
- Adds a regression contract that requires the backend section allow-list, generated JavaScript sub-navigation, delivery section markup and delivery routes to agree on the `delivery` subsection.

Authority boundary: no RouterOS, policy, worker-authority, database-schema or delivery-semantics change.

## v0.55.4.1 — Environment Configuration Contract & Drift Prevention

- Adds `scripts/env_validate.py` as the fail-closed environment contract for `.env.example`, Compose host interpolation, source environment references and the deployment host `.env`; validator output never prints local values or secrets.
- Classifies user-facing configuration as required, optional, conditional and secret-bearing while explicitly tracking runtime-only internal variables and reserving a controlled deprecated-variable path.
- Adds conditional host validation for enabled SMTP delivery, signed HTTP webhook simulation and remote-access security posture, including mutual exclusion of SMTP implicit SSL and STARTTLS.
- Confirms the older `SUMMARY_*` variables remain active Parent Summary delivery configuration rather than dead legacy settings.
- Wires environment validation into both `scripts/release_patch.py` and the GitHub `Quality` workflow so future code/Compose/example drift blocks release automatically.
- Adds environment contract documentation plus regression coverage for duplicate keys, source-reference discovery, secret-safe output, local undocumented variables and conditional feature configuration.

Authority boundary: environment validation is deployment/configuration evidence only. It does not read or mutate RouterOS, policy state, notification source evidence or external delivery authority.

## v0.55.4 — External Delivery Adapters & Delivery Simulation

- Adds durable external notification fan-out for SMTP email and HMAC-SHA256 signed webhooks, downstream of the existing notification evidence, intelligence and attention-policy layers.
- Keeps all SMTP configuration—including host, credentials, sender and recipients—environment-only. SMTP secrets are never persisted to `policy.db` or returned through UI/API status.
- Stores only ordinary webhook destination metadata in ZEN while keeping the HMAC signing secret environment-only. Production webhooks require HTTPS; HTTP requires explicit `ZEN_WEBHOOK_ALLOW_HTTP=1` test opt-in.
- Adds durable pending/sending/sent/failed/suppressed/cancelled delivery truth, bounded retry/backoff, restart recovery, stable idempotency keys, per-channel delivery statistics and median delivery latency.
- Reuses the v0.55.1 attention-policy decision before external delivery is queued, so quiet hours, severity thresholds, source/device/event filters and cooldowns suppress email/webhook exactly as they suppress browser push without deleting notification evidence.
- Cancels unsent external deliveries when the notification is read, acknowledged, dismissed or source-resolved; an intelligence escalation supersedes a normal pending delivery and receives its own delivery identity.
- Signs webhook JSON over `timestamp + "." + raw_body` and sends `X-ZEN-Event`, `X-ZEN-Delivery-ID`, `X-ZEN-Timestamp`, `X-ZEN-Signature` and `Idempotency-Key` headers. Retryable HTTP 408/425/429/5xx responses back off durably; HTTP 410 retires the configured destination.
- Adds a first-class Notification Delivery UI with sanitized channel readiness, test-send actions, per-channel counters and durable delivery history. No SMTP password, recipient list or webhook secret is exposed.
- Adds optional `test-tools` Compose services: Mailpit for real SMTP capture and a small local signed-webhook sink with an inspection UI plus controllable 429/500/410 responses for failure-path qualification. The normal stack remains unchanged unless the profile is requested.

Authority boundary: external delivery can only transmit already-authorised notification attention. It has no RouterOS adapter, cannot mutate policy or source evidence, and cannot turn delivery success/failure into enforcement authority.

## v0.55.3.1 — Notification Intelligence Upgrade Migration Hotfix

- Fixes startup failure when upgrading an existing pre-v0.55.3 `notifications` table: the `correlation_key` index is now created only after the additive intelligence-column migration and correlation-key backfill complete.
- Adds a production-shaped v0.55.2 → v0.55.3.1 SQLite upgrade regression test covering column creation, severity/correlation backfill, index creation and notification timeline baseline adoption.
- No notification, policy, RouterOS authority or delivery semantics are changed; this is an upgrade-ordering hotfix only.

## v0.55.3 — Notification Intelligence & Escalation

- Adds durable notification lifecycle timelines covering creation, repeats, read/acknowledge/dismiss transitions, source resolution, reopen and automatic attention escalation. Existing notifications receive one migration baseline event without inventing prior history.
- Adds stable correlation keys that group related notifications by exact device/subject across source families, with active-group counts, source/event provenance and grouped event volume.
- Separates source severity from attention severity. Automatic escalation can raise an unresolved WARNING notification to CRITICAL attention while retaining the source's actual WARNING severity and leaving source resolution with the owning subsystem.
- Adds bounded automatic escalation rules for unresolved warning age and repeated-event count. Acknowledged/dismissed/resolved notifications are never automatically escalated; escalation is evaluated by the existing read-side background worker and has no RouterOS dependency.
- Adds a first-class Notification Intelligence view with configurable escalation thresholds, correlation groups, digest candidates, noisy-source/subject analytics, escalation/reopen metrics and a recent lifecycle timeline.
- Adds “Why am I seeing this?” provenance to inbox notifications, showing source truth, source/attention severity, current attention-policy decision, correlation identity, escalation reason and a bounded next-step hint.
- Adds digest preview logic that groups recent non-critical attention eligible under current notification preferences. v0.55.3 previews candidates only; it does not send digests or bypass v0.55.1 noise policy.
- Adds authenticated intelligence/explanation APIs and gives intelligence escalations their own durable push-delivery identity so a CRITICAL escalation can supersede a cancelled normal pending delivery without violating delivery idempotency.

Authority boundary: notification intelligence is derived attention metadata only. It cannot change policy, clear incidents, repair background work or mutate RouterOS. Source evidence, source severity and source resolution remain independently durable and authoritative.

## v0.55.2 — PWA / Browser Push Delivery

- Adds standard encrypted Web Push delivery for the existing Notification Centre, using the browser/PWA Push API and service worker rather than a ZEN-specific cloud notification provider.
- Generates and persists a local P-256 VAPID identity beside `policy.db`; the private key stays on the ZEN host while authenticated browsers receive only the public application-server key needed to subscribe.
- Adds durable per-account browser push subscriptions without exposing endpoint URLs or browser encryption keys through normal API/UI status surfaces. Stale provider subscriptions returning HTTP 404/410 are automatically disabled.
- Adds a durable push-delivery outbox with pending/sending/sent/failed/suppressed/cancelled truth, bounded retries/backoff, restart recovery, test delivery and aggregate delivery/subscription statistics.
- Evaluates the complete v0.55.1 attention policy before push is queued. Quiet hours, minimum severity, cooldown, disabled event families and source/device filters therefore suppress both the bell and remote push without deleting the underlying notification evidence.
- Cancels unsent push when the notification is read, acknowledged, dismissed or source-resolved, preventing stale attention from arriving after a parent has already handled it.
- Extends the PWA service worker with transient push display and same-origin click-through into the owning ZEN context. Dynamic/private responses remain network-only and the service worker still stores no household data for offline use.
- Adds Notification Preferences controls to enable/disable this browser and send a test push, plus worker/subscription/delivery evidence. Browser push correctly reports HTTPS REQUIRED when ZEN is opened over insecure HTTP.

Authority boundary: the push worker has no RouterOS adapter. It can only deliver already-authorised notification attention to registered browser endpoints; it cannot create, resolve or enforce policy/incident state. Standard Web Push necessarily uses the browser vendor's encrypted push endpoint, but requires no separate ZEN SaaS account.

## v0.55.1 — Notification Preferences & Noise Control

- Adds first-class Notification Preferences with a global attention enable switch, minimum severity threshold, quiet hours, configurable timezone, critical quiet-hours bypass and bounded repeat/reopen cooldown.
- Adds per-event enable/disable for Security, Reconciler, Operations, Bypass, Telemetry, Quota and Background Job notification families, while retaining every source incident/job as the owning durable truth.
- Adds source-family muting and exact device/subject filters. Per-device quota sources collapse to the stable `quota` family so one policy can control all quota incidents while device-specific subject filters remain available.
- Keeps muted events durable and inspectable instead of deleting or pretending they never happened. Bell/unread counts expose actionable attention separately from total unread and muted unread evidence.
- Makes quiet-hours evaluation dynamic so attention resumes automatically when the window ends without needing a new source event. Critical events can bypass quiet hours and always bypass reopen cooldown.
- Adds reopen cooldown evidence through `attention_eligible_at`: a source that clears and quickly reappears stays unresolved and visible but does not immediately re-alert unless severity becomes critical.
- Extends `zen_notifications_v1` with current preference/event-catalog evidence and adds an authenticated Preferences UI. Preference writes are local attention configuration and deliberately do not increment the policy/config revision or create RouterOS write authority.
- Removes the obsolete release-readiness statement that notification expansion is still behind a human gate; Notification Centre is now implemented while HTTPS/public-edge commissioning remains independently deferred.

Authority boundary: notification preferences can only change whether durable notification evidence attracts attention. They cannot suppress the owning incident/background job, alter policy resolution, authorise RouterOS mutation or manufacture health/readiness evidence.

## v0.55.0 — Notification Centre foundation & operational event integration

- Adds a durable `notifications` store with stable deduplication keys, severity, source/event provenance, subject/source references, unread/read/acknowledged/dismissed attention state, independent source-resolution state, occurrence counts and retained history.
- Adds a first-class Notification Centre with a persistent header bell/unread count, inbox/history views, source-context links, read/acknowledge/dismiss actions, mark-all-read, critical/unread badges and compact responsive styling.
- Projects the existing durable Incident Monitor lifecycle into notifications without duplicating every scan. Open/reopen/severity-change events attract attention; incident acknowledgement and source resolution propagate to the linked notification while the incident remains the owning operational truth.
- Emits a deduplicated notification only when a background job reaches terminal failure. A later successful job for the same kind/scope resolves that notification automatically, including prepared-view failures, without adding another polling worker.
- Adds `zen_notifications_v1` authenticated API evidence and notification statistics for records, generated events, deduplicated repeats, unread/unresolved/critical counts, acknowledgement samples and median acknowledgement time.
- Preserves authority boundaries: notifications are read-side attention/evidence only. Reading, acknowledging or dismissing a notification never authorises or performs RouterOS mutation and never clears the source condition.

## v0.54.5.3 — Navigation tail-latency closure

- Removes Dashboard's per-device effective-policy recomputation from the normal navigation path. Favourite cards now reuse the revision-bound desired-policy projection already published by the reconciler; missing advisory plan evidence is shown as unknown rather than triggering synchronous policy resolution.
- Precompiles the large shared `index.html` Jinja template during application startup so one-time template parsing cannot contaminate the first measured Dashboard navigation request.
- Moves Settings → Operations managed-state inventory off the browser request path. Startup seeds a revision-bound advisory inventory and the reconciler refreshes it in the background with a bounded two-minute throttle; stale/missing evidence remains explicit.
- Keeps `/api/operations/inventory` as an explicit fresh RouterOS read and republishes the result for subsequent fast Operations navigation. No cached inventory is used for mutation authority.
- Corrects formal RouterOS connection evidence so local in-process observability spans (`routeros.mutation_status` / coherent-session bookkeeping) are not misclassified as network reads. Actual RouterOS operations still require exactly one measured transport connection per request.
- Leaves the canonical navigation budget unchanged at p95 ≤ 1000 ms; the slice closes measured tail latency rather than relaxing or gaming the gate.

Authority boundary: all new cached data is display-only. RouterOS-changing operations still acquire the serialized mutation lane, re-prove security posture, fresh-read relevant RouterOS state, calculate, write and verify.

## v0.54.5.2.1 — Prepared-view serialization recovery & telemetry-health closure

- Fixes a deterministic prepared-view publication failure where PostgreSQL aggregate `Decimal` values in `activity:24h` and `services:24h` could not cross the SQLite JSON persistence boundary, causing repeated worker retries and permanently missing read models.
- Normalizes derived JSON scalars centrally at the bounded persistence boundary while preserving integer values as integers, fractional decimals as JSON numbers, and ISO formatting for date/time values.
- Distinguishes telemetry-source health from prepared-model availability: Activity can now report **TELEMETRY ONLINE** while its read model is PREPARING/FAILED instead of falsely declaring the source offline. Missing prepared evidence is still never rendered as zero activity.
- Adds explicit prepared-job state attribution (`PREPARING`, `FAILED`, generation/retry reasons) on read-model misses without reintroducing synchronous heavy analytics fallback.
- Extends background runtime health with bounded durable prepared-job evidence. A live worker thread no longer makes runtime health green while the latest prepared job for a scope is failed or retrying after an error; old superseded failures do not poison health after a newer success.
- Keeps RouterOS authority unchanged: prepared data remains read-only derived evidence and is never consulted by the serialized mutation path.

Recovery boundary: telemetry ingestion health, prepared-model generation health and RouterOS mutation authority are separate contracts. A failure in one must not be mislabeled as another or converted into invented/zero evidence.

## v0.54.5.2 — Prepared-view hit-rate & read-path fan-out closure

- Removes the remaining synchronous live analytics fallback from ordinary Dashboard and Activity navigation. Missing prepared evidence is shown as explicit PREPARING/MISSING state and wakes the background worker instead of blocking the browser on multi-second PostgreSQL fan-out.
- Allows last-known-good prepared evidence to remain usable only when it is from the current configuration revision and status is `ready`; stale evidence stays visibly STALE, while revision-mismatched evidence is never served.
- Adds explicit prepared-view miss reasons (`not_found`, `revision_mismatch`, `status_not_ready`, `expired`, `too_old`, `stale_grace_exceeded`) and separates a true live fallback counter from a simple prepared-view miss. Same-revision stale evidence has a bounded grace window; it cannot remain a performance "hit" indefinitely.
- Reuses one coherent PostgreSQL connection for each background analytics bundle, preserving individual SQL timing evidence while eliminating repeated connection/authentication overhead across related static queries.
- Coalesces obsolete pending prepared-view jobs per kind/scope while never deleting running leased work, preventing slow analytics generation from accumulating stale two-minute refresh buckets.
- Publishes the automatic reconciler's already-fresh managed-device observation and conservative service-contract evidence as revision-bound advisory read models. Normal Dashboard/Managed Devices/Activity rendering consumes those models rather than repeating the same multi-second RouterOS reads.
- Keeps all prepared RouterOS evidence observational only. Reconciliation and every authority-changing path continue to acquire the serialized mutation lane, re-prove security posture, fresh-read RouterOS state, calculate, write and verify without consulting the advisory cache.
- Tightens formal acceptance so prepared-view effectiveness requires at least five warmed lookups and at least a 90% fresh-or-explicit-stale-same-revision hit rate; low hit rates are FAIL rather than hidden behind successful fallback work.
- Improves UI evidence labels for Dashboard, Activity and Managed Devices so FRESH / STALE / MISSING advisory state is visible and cannot be confused with verified live enforcement.

Read-path boundary: a fast browser response is allowed to show stale/missing advisory evidence, but it is never allowed to use stale evidence as RouterOS write authority or silently convert missing data into healthy/zero state.

## v0.54.5.1 — RouterOS request-path decoupling & reconciliation closure

- Converts manual **Apply desired policy** and **Reconcile all** from synchronous RouterOS HTTP work into durable reconciliation requests that ACK after local queue persistence.
- Adds a durable `reconciliation_requests` journal with restart recovery, same-target pending-request supersession, requested/applied revision evidence and explicit terminal states.
- Keeps RouterOS writes exclusively in `AutoReconciler`: requested work acquires the existing cycle lock and serialized mutation lane, re-proves security posture live, re-reads policy/RouterOS state through `reconcile_device`, verifies convergence, and re-queues the latest revision if desired state changes mid-run.
- Separates user-visible ACK latency from queue wait, worker processing and total verified convergence latency; `/api/performance` and the Performance page surface the distinction.
- Removes multi-second security-posture and custom-service-contract probes from ordinary Dashboard navigation. Dashboard consumes revision-bound prepared RouterOS observations with explicit FRESH / STALE / MISSING semantics; authority-changing paths never consume prepared observations.
- Publishes fresh security observations from the reconciler and fresh service-contract observations from explicit live Service Intelligence/API reads.
- Tightens formal performance evidence so an alive but `degraded`/`error` background worker, or a cycle reporting failed jobs, is **FAIL** rather than timing-only PASS; the worker performance snapshot now exposes `last_error` for diagnosis.
- Adds hostile coverage for queue coalescing, restart recovery, OFF-mode explicit reconciliation, serialized authority ownership, dashboard non-blocking reads and degraded-worker truthfulness.

## v0.54.5 — Final release-readiness closure

- Upgrades the portable readiness contract to `zen_release_readiness_v2` and fixes the final application gate at exactly eight current checks. Final readiness requires `PASS 8 / PENDING 0 / FAIL 0`; contradictory counts/state are rejected by the CLI.
- Makes Runtime Readiness consume both normal operations readiness and the v0.54.3 minimal embedded-runtime contract, so dead background/reconciler/incident/summary workers or an unavailable serialized mutation lane cannot be hidden behind an HTTP-ready process.
- Makes Live Performance consume `zen_formal_performance_acceptance_v1`, including v0.54.4 threshold integrity, request-class budgets, prepared-view evidence, background-worker timing, parallel-observation utilisation and mutation-lane evidence. Request-only PASS can no longer manufacture release readiness.
- Carries bounded attribution for non-passing formal performance evidence into the release artifact without exporting individual request paths or household data.
- Extends the source-qualified closure matrix through v0.53.1 and v0.54.0-v0.54.4 while keeping live evidence distinct from source qualification.
- Hardens `scripts/release_acceptance.py` to validate schema, exact check count, state/count consistency and `final_ready` before accepting the artifact.
- Leaves HTTPS/public-edge publication work and notification expansion as explicit separate gates; no RouterOS authority or mutation-concurrency semantics change.

# Changelog

All notable ZEN Control release slices are recorded here. ZEN is developed as evidence-led, bounded slices; historical entries describe the authority and evidence contracts that were current for that release.

## v0.54.4 — Formal performance acceptance

- Promotes the existing v0.30/v0.30.1/v0.39 performance instrumentation into a fail-closed formal acceptance contract while preserving all RouterOS authority boundaries.
- Adds valid/invalid sample accounting and min/p50/p95/p99/max latency evidence. Failed requests cannot count toward a healthy class and retained outliers are never discarded to manufacture a PASS.
- Closes a RouterOS connection-budget defect: missing `routeros.connect` evidence is now PENDING rather than zero, and the gate fails if any valid RouterOS request opens more than one coherent transport.
- Adds a recommended 20-sample deliberate acceptance run while retaining the documented absolute minimum of five valid samples per class.
- Adds prepared-view hit/miss/live-fallback counters, in-memory background-worker cycle timing, parallel-observation utilisation and serialized mutation-lane wait/contention evidence to `/api/performance` and the Performance UI.
- Keeps operational performance evidence observational only; it cannot grant mutation authority or bypass fresh RouterOS security/read/post-write validation.
- Extends `scripts/perf_acceptance.py` with strict v0.54.4 contract validation, optional authenticated live fetch, sanitized JSON report output and distinct PASS/PENDING/FAIL/INVALID exit behaviour.
- Wires all performance acceptance thresholds plus the recommended sample count through Compose; host `.env` values now actually reach the application container.

Acceptance boundary: missing evidence remains missing, `PENDING != PASS`, and thresholds/outliers must not be manipulated to manufacture release readiness.

## v0.54.3 — Deployment topology & runtime-health closure

- Makes the host release workflow topology-aware. It now derives affected Compose services from the actual release delta, including app/build-context changes and service-specific Compose block changes, instead of assuming only `mikrotik-control` changed.
- Preserves the pre-release live Compose topology across targeted rebuilds. Any service that was running before the release must return to running state; successful one-shot services remain successful; explicitly affected/new services are required to reach their expected state.
- Adds fail-closed handling for `telemetry/postgres` source changes. PostgreSQL init scripts are not treated as live migrations, so the release workflow refuses to imply a schema update by merely recreating a container.
- Recreates affected services with `--force-recreate` so bind-mounted configuration changes (for example GoFlow2 mappings or Caddy configuration) cannot be missed by an otherwise unchanged container definition.
- Adds `/health/runtime` with the minimal `zen_runtime_health_v1` contract. It exposes only non-secret process health: the background worker, reconciler, incident monitor and summary-delivery worker must all be alive; configured ephemeral observation concurrency and mutation-lane availability are reported without exposing device/configuration data.
- Extends release qualification so app liveness, embedded-worker runtime health and preserved Compose topology must all pass before staging, commit, push, CI watch or tag creation.
- Keeps command-line overrides for explicit service additions, full-stack rebuilds and intentional health-gate skips, while auto-detection is the default.

Deployment boundary: container `UP` alone is not release success. ZEN now proves the application, its embedded workers and the live service topology survived the deployment before source publication can continue.

## v0.54.2 — Parallel observation / serialized enforcement

- Adds a bounded `ParallelObserver` for deterministic concurrent read/plan fan-out. Automatic reconciliation can now overlap independent device policy observations without granting those observations write authority.
- Adds `ZEN_ROUTER_OBSERVE_WORKERS` with a bounded 1–8 worker range; the default is four observation workers. Per-device observation failures remain isolated and visible in cycle evidence.
- Makes parallel plans advisory only. ENFORCE re-proves RouterOS security posture after observation and re-reads each candidate serially before any mutation, so a stale parallel plan can never authorize a write.
- Adds a process-wide re-entrant RouterOS mutation lane at the adapter boundary. All app-owned public RouterOS mutators pass through the same lane, including global/device mode, bandwidth, service contracts, schedules, temporary access, Kid Control authority and restricted-device membership.
- Adds route-level mutation ownership around multi-step manual actions so several RouterOS changes and their validations form one non-interleavable logical mutation.
- Preserves authority-transfer lock ordering: Kid Control cutover/rollback own the reconciler cycle lock first and then the mutation lane, avoiding cycle/mutation lock inversion.
- Exposes observation worker utilization, plan failures, read-plan duration and mutation-lane state in Cycle diagnostics while keeping read-only background analytics free of RouterOS dependencies.
- Wires `ZEN_ROUTER_OBSERVE_WORKERS` through the public `.env.example` and Compose runtime with a safe default of four workers; tuning affects observation only, never mutation concurrency.
- Adds hostile race coverage for competing writers, nested mutation ownership, parallel observation overlap, stale-plan rejection and authority degradation between observation and mutation.

Authority boundary: observation may run in parallel; RouterOS mutation does not. There remains one logical app-owned mutation lane, and fresh authority/read validation immediately precedes enforcement.

## v0.54.1 — Background analytics & prepared views

- Adds durable `prepared_views` rows as bounded current read models rather than an unbounded cache/history table. Each row records source configuration revision, capture/expiry time, payload size and generation.
- Adds revision-aware and age-aware prepared-view reads. A view derived from an older configuration revision is never silently served after policy/service configuration changes.
- Adds periodic idempotent background refresh jobs for Dashboard telemetry, Activity overview, service intelligence inputs, Classification Intelligence, default 7-day history and per-device Device 360 activity evidence.
- Keeps RouterOS out of the background analytics worker. Device 360 prepares only telemetry/activity evidence; live policy/enforcement evidence continues to use the synchronous fresh RouterOS read path.
- Uses prepared views on the main Dashboard/Activity paths and the common Activity, Services, Classification, 7-day History and Device 360 read surfaces, with live-query fallback when prepared evidence is missing, expired or stale.
- Adds bounded terminal job/outbox maintenance. Active/running work is never pruned and a floor of recent durable bookkeeping is retained.
- Extends background status with prepared-view inventory and adds the read-only `/api/background/prepared-views` endpoint.
- Surfaces prepared-view age/revision evidence in the UI so faster reads do not hide evidence freshness.

Authority boundary: v0.54.1 adds no RouterOS write path. Prepared views are derived read-side evidence only; the reconciler remains the normal enforcement writer and authority-changing operations remain serialized.

## v0.54.0 — Revisioned state & background-work foundation

- Adds a durable configuration revision journal with a singleton monotonic revision, actor/reason/scope evidence and a read-only revision API.
- Adds optimistic-concurrency support through revision-aware configuration transactions. Stale callers fail before mutation instead of silently overwriting newer state.
- Adds a transactional `config.changed` outbox written in the same SQLite transaction as revision-aware configuration updates.
- Adds durable background jobs with idempotency keys, bounded attempts, worker leases, expired-lease recovery and per-scope locks.
- Adds durable worker metrics and a read-only `/api/background/status` surface.
- Adds the first background computation, `analytics.config-summary`, which reads local configuration only and has no RouterOS adapter or enforcement authority.
- Starts/stops the read-side worker with the application and seeds an upgrade-safe revision baseline on startup.
- Threads configuration revisions through the main settings forms so stale settings pages are rejected rather than overwriting a newer configuration revision.
- Keeps the existing reconciler as the single normal RouterOS enforcement writer; background workers do not gain RouterOS write authority.
- Hardens `scripts/release_patch.py` so `--resume` understands dirty trees, committed-but-unpublished HEADs and already-published clean HEADs, and fails early on tag-target mismatches instead of trying to manufacture an empty commit.

## v0.53.1 — Commissioning and public-repository closure


### CI/public-audit host compatibility hotfix

- Public-source auditing now enumerates Git tracked files plus non-ignored untracked files when run inside a working tree. Local ignored runtime material such as `.env` therefore cannot create a false publication failure, while an accidentally tracked secret file remains auditable and blocking.
- Source bundles without Git metadata retain the conservative filesystem scan fallback.

- Formalises the live Kid Control migration workbench Stage-button visibility repair.
- Separates legacy-profile disabled state from translation warnings, so an expected retained/disabled rollback profile does not produce a false REVIEW signal after successful authority transfer.
- Makes the post-cutover authority state explicit: ZEN policy active, legacy Kid Control disabled and retained, verified migration devices counted, rollback available.
- Keeps staging records as provenance after cutover and removes misleading language that could imply the materialised ZEN policy is still non-active.
- Restructures the repository for public review with a product-first README, architecture/install/security/contribution documentation, read-only RouterOS inspection helpers, and an executable public-source audit.
- Adds no RouterOS authority, Kid Control deletion, notification expansion, or performance-architecture changes.
- CI qualification explicitly packages the test tree and discovers it from the repository top level, preventing third-party `tests` packages from shadowing ZEN test helpers on clean runners.
- Adds `scripts/release_patch.py` as a fail-closed host release orchestrator for exact patch application, validation, bounded rebuild/health proof, Git publication, commit-scoped GitHub Actions watching and post-CI annotated tagging.

## v0.53.0 — Controlled MikroTik Kid Control authority transfer

v0.53.0 converts the v0.52 staged migration proposal into a guarded, reversible authority transfer. Cutover re-reads the live legacy configuration, requires the staged policy fingerprint to remain unchanged, requires a clean translation and a unique static DHCP-backed MAC/IP identity for every configured device, and requires automatic reconciliation to be in **ENFORCE** mode so recurring schedule changes continue to reach RouterOS.

The transfer is fail-closed and ordered: ZEN materialises or safely reuses equivalent local policy, adopts each validated device into `Restricted_Devices` without modifying DHCP, proves current ZEN enforcement, records durable PREPARED evidence, and only then toggles the exact legacy Kid Control profile's `disabled` flag. `/ip/kid-control/device` remains read-only and ZEN never deletes or edits legacy Kid Control schedules or membership.

Cutover and rollback both require an explicit fresh authenticator/recovery code. The automatic reconciliation worker shares an authority-transfer lock so it cannot race the transition. Rollback restores legacy authority first, then restores pre-cutover ZEN device state, removes only migration-created `Restricted_Devices` rows, and restores only local policy objects changed by the migration. The original MikroTik Kid Control configuration remains retained for rollback.

The migration workbench at `/migration/kid-control` now exposes readiness gates, per-device static-lease proof, current authority state, durable authority-event evidence, explicit **Transfer authority to ZEN**, and **Roll back to legacy Kid Control** controls. No bulk legacy cleanup is performed in this release.

## v0.52.0 — MikroTik Kid Control migration & staged adoption

v0.52.0 introduces a deliberately read-only migration bridge for legacy MikroTik Kid Control. ZEN reads `/ip/kid-control` and `/ip/kid-control/device` plus DHCP/ARP identity evidence, translates configured legacy policy into a deterministic replacement proposal, and can persist that proposal as local **staging data only**. Dynamic Kid Control discovery rows, activity domains, rates and byte counters are excluded from migration intent.

The migration workbench is available at `/migration/kid-control`. A fresh preview shows configured profiles, schedule translation, configured device → profile assignments, MAC-based identity evidence and warnings. Staging re-reads RouterOS and requires the policy fingerprint to still match the reviewed preview. A changed legacy configuration therefore invalidates the preview instead of silently staging a different policy.

Authority remains intentionally split:

- `/ip/kid-control` and `/ip/kid-control/device` are **read-only migration sources**.
- Router writes from the migration feature: **0**.
- Legacy Kid Control disable/delete/edit operations: **none**.
- Staging does not create active ZEN profiles, schedules or device assignments.
- There is no activate/cutover endpoint in v0.52.0.
- MAC address is the stable migration identity; current IPv4 is observational evidence and must be freshly re-matched during a later explicit cutover slice.

For the household baseline used to qualify this slice, one `Kids` profile with daily `07:00-23:30` access translates to a BLOCKED base profile plus NORMAL at `07:00` and BLOCKED at `23:30` across all seven days. Four explicitly configured devices are candidates; dynamic Kid Control discovery rows are ignored. Empty `rate-limit` and `tur-*` values produce no invented bandwidth policy. Non-empty values are preserved as review-required evidence rather than guessed into ZEN semantics.

### Remote-access commissioning correction retained in v0.52

Live v0.51 commissioning proved that the pinned `cloudflared` image runs as UID/GID `65532:65532`. A file-backed Compose secret preserves host file ownership, so a `root:root` mode `0600` tunnel-token file is unreadable by the non-root connector. Keep the credential outside the source tree but make it group-readable only by cloudflared:

```bash
sudo chown root:65532 /etc/zen-control/cloudflare-tunnel-token
sudo chmod 0640 /etc/zen-control/cloudflare-tunnel-token
```

Expected host ownership is `root:65532` with mode `0640`; do not make the token world-readable and do not place it in the Compose command line.

## v0.51.0 — Secure transport & remote access

v0.51.0 is a post-core transport/security slice. It does not change policy precedence, RouterOS write authority, reconciliation, telemetry classification or performance budgets. Remote access is disabled by default so applying the patch does not alter an existing LAN-only deployment.

ZEN now has an explicit secure-transport contract: remote mode requires a public hostname, Secure session cookies, an explicit Host allowlist that covers the public hostname, and operator confirmation that Cloudflare Access plus Tunnel **Protect with Access** are configured. The application reports this as `ready_for_live_validation`; that is configuration readiness only, never proof that the Internet path has been commissioned. Response hardening adds `nosniff`, frame denial, same-origin referrer policy, a restrictive camera/microphone/geolocation Permissions Policy, and HSTS when remote Secure-cookie mode is enabled. No CSP is introduced in this slice because ZEN still has existing inline UI code that must be migrated before a strict CSP can be enabled safely.

The single `docker-compose.yml` gains an opt-in `remote-access` profile using pinned `cloudflare/cloudflared:2026.9.0`. The connector publishes no host port, runs read-only with all Linux capabilities dropped and `no-new-privileges`, and reads a remotely-managed Tunnel token from a Compose secret/token file rather than exposing the token in command-line arguments.

### Cloudflare commissioning order

1. **Create the Access application before the published Tunnel route.** Protect the complete ZEN hostname and use an explicit Allow policy only for the identities that should reach ZEN; Access remains the outer gate and does not replace ZEN login/TOTP.
2. Create a remotely managed Tunnel for ZEN. Add a published application hostname such as `zen.example.net` whose service URL is **`http://mikrotik-control:8080`**. `cloudflared` and ZEN share the Compose network; no inbound router port-forward is required.
3. On that published hostname, enable **Protect with Access** and supply the Access team name and application AUD tag in Cloudflare. This makes `cloudflared` validate `Cf-Access-Jwt-Assertion` before proxying the request to ZEN.
4. Store the Tunnel token outside the project tree, for example `/etc/zen-control/cloudflare-tunnel-token`, readable only by root and the cloudflared runtime group (`root:65532`, mode `0640`), and set `CLOUDFLARE_TUNNEL_TOKEN_FILE` to that path. Never paste the token into this README, Compose command, source, test output or a support bundle.
5. Configure ZEN after the Access application/route exists:

```dotenv
ZEN_REMOTE_ACCESS_ENABLED=1
ZEN_SECURE_COOKIES=1
ZEN_PUBLIC_HOST=zen.example.net
ZEN_ALLOWED_HOSTS=zen.example.net
ZEN_CLOUDFLARE_ACCESS_PROTECTED=1
ZEN_HSTS_MAX_AGE=31536000
CLOUDFLARE_TUNNEL_TOKEN_FILE=/etc/zen-control/cloudflare-tunnel-token
```

When `ZEN_SECURE_COOKIES=1`, authenticated browser sessions must use the HTTPS hostname. Direct LAN HTTP can still be useful for liveness/emergency diagnostics, but browsers must not be expected to maintain an authenticated Secure-cookie session over plain HTTP.

Start only the opt-in connector after the Cloudflare side is protected:

```bash
docker compose --profile remote-access up -d cloudflared
docker compose --profile remote-access ps
docker compose logs --tail=100 cloudflared
```

Then inspect `/api/security/transport` and run the unauthenticated edge probe from a machine that resolves the public hostname:

```bash
python3 scripts/https_acceptance.py https://zen.example.net/
```

A PASS means the unauthenticated public request was intercepted by Cloudflare Access rather than reaching ZEN anonymously. It does **not** prove authenticated ZEN behaviour. Finish commissioning by authenticating through Access, then ZEN, then exercise shared-display unlock, a read-only Device 360/explainability path, and one explicitly approved guarded write. RouterOS must never be exposed directly. Final performance evidence is collected only after this access path is stable.

## v0.50.3 — Diagnostic warning attribution & pre-HTTPS gate

v0.50.3 closes a release-evidence attribution gap exposed during live commissioning: Release Readiness could correctly remain PENDING for a diagnostic warning while exporting only aggregate counts, leaving the portable acceptance artifact unable to identify which diagnostic check required review. The dependency gate now carries bounded diagnostic key, label, state and sanitized summary for warning/critical/offline findings, and the readiness UI renders those findings directly with a link back to Operational diagnostics.

This is evidence transparency, not evidence laundering. Warning attribution does not downgrade, acknowledge or suppress any diagnostic state: a warning still keeps the release PENDING, and critical/offline evidence still FAILS the dependency gate. Diagnostic facts are not copied into release evidence, finding text is bounded, and missing detail remains explicitly incomplete rather than being inferred healthy. Performance thresholds, RouterOS authority, reconciliation and enforcement behavior are unchanged.

## v0.50.2 — Parent unlock & time-extension hardening

v0.50.2 hardens shared-display parent access without weakening TOTP replay protection. Authenticator values remain single-use: re-entering the same 30-second TOTP value is intentionally rejected, while later authenticator windows remain valid. The unlock error now explains that boundary instead of presenting a bare "invalid or already-used" result.

A guarded **More time** flow appears during the final minute of an active shared-display parent window. It requires a fresh TOTP or one-use recovery code, is server-side limited to the final 90 seconds, cannot extend a locked display, cannot be stacked early, and adds one configured unlock period while retaining the current page context. The route is CSRF-, role-, rate-limit- and process-bound like normal parent unlock. No RouterOS authority, policy precedence, reconciliation, telemetry, or performance acceptance behaviour changes.

## v0.50.1 — Conflict & Shadow hostile closure

v0.50.1 is release-candidate hardening, not feature expansion. It closes the outstanding Policy Conflict & Shadow hostile corpus against the same saved-configuration semantics used by the live resolver. The analyser remains local, static and read-only: it performs no RouterOS calls, creates no RouterOS authority, and does not change reconciliation or enforcement precedence. Live performance acceptance remains intentionally deferred until the post-hardening code freeze.

The hostile sweep closed five evidence/quality defects. Orphan schedule and date-exception targets no longer generate impossible shadow claims against live targets; missing profile block/quota service keys and malformed service schedules are surfaced as critical configuration conflicts; built-in aggregate groups no longer receive a special exemption when a concrete member is missing; and an explicit device mode override equal to its profile mode is now REDUNDANT rather than falsely described as a SHADOW.

Schedule-template ambiguity is now closed at both ends. Policy Quality detects contradictory same-weekday/same-time template entries in already-stored data, while new template writes reject conflicting modes before persistence. Configuration import performs the same template/identity/dependency preflight before destructive table replacement, including duplicate template identity/name and date exceptions that reference a missing schedule template. A malformed backup therefore cannot fail only after current configuration has already been deleted. Identical duplicate template outcomes remain valid but are reported as REDUNDANT configuration noise rather than ambiguity.

## v0.50.0 — Core closure / release readiness

v0.50 is the final core closure sweep; there is no feature expansion in this slice. It adds an evidence-honest release-readiness contract and dashboard that consolidates current runtime readiness, dependency diagnostics, live performance acceptance, a non-destructive configuration backup/restore/reopen smoke, durable controlled-restart evidence, PWA safety invariants and shared-display commissioning. PASS is reserved for affirmative current evidence; missing live samples or commissioning remain PENDING and disproven requirements are FAIL.

The sweep also hardens the existing readiness boundary: RouterOS health must explicitly report `connected=true`, and a reconciler probe failure degrades `/health/ready` instead of escaping as an application error. Startup audit evidence now records the application release so a controlled stop followed by the current-version startup can be proven from durable history.

HTTPS/secure remote access remains a post-core commissioning phase, and notification expansion remains behind its existing human gate. Neither is silently counted as complete and neither is allowed to inflate the v0.50 core readiness result.

Release evidence is available from `/release-readiness` and `/api/release-readiness`. The JSON export can be checked offline with `python3 scripts/release_acceptance.py <export.json>`; the command exits successfully only for an actual PASS unless `--allow-pending` is explicitly requested.

## v0.49.1 — Classification evidence contract reconciliation hotfix

v0.49.1 reconciles deployments that were built from the original v0.46 starter bundle and then advanced with the v0.47–v0.49 delta patches without first applying the finalized v0.46 closure patch. That starter already contained partial v0.46 code, but its classification coverage helper did not yet expose the per-source `traffic_evidence_status` / `dns_evidence_status` contract expected by v0.49 historical interval correlation. The resulting version skew caused `policy_interval_usage()` to raise `KeyError: traffic_evidence_status`.

The hotfix restores the complete qualified v0.46 evidence contract across Activity, Classification Intelligence, connected-overview/help/UI surfaces and the missing closure tests. Negative retained counters remain `INCONSISTENT` instead of being sanitized into plausible ratios; one unavailable source cannot hide inconsistent evidence from the other; zero denominators remain `NO EVIDENCE`; valid-empty live catalogues remain healthy while fallback/stale consumer states stay explicitly degraded. No RouterOS authority or write behavior is changed.

## v0.49.0 — Historical policy correlation & retained-evidence closure

v0.49 closes historical policy correlation around physical-device identity, time ordering and degraded retained evidence. New desired-policy checkpoints are bound to a generated **management identity epoch** that is created when local device management begins and retired when the device leaves management. Reusing the same IP therefore starts a new identity even when the new device resolves to exactly the same desired policy. Legacy pre-v0.49 policy history is deliberately left IP-scoped and unbound: ZEN cannot prove which physical device owned an old address, so it will not manufacture continuity during upgrade.

Policy-history timestamps are canonicalized and queried as UTC instants rather than comparing mixed-offset ISO text. Correlation interval ordering now uses physical instants, preserving correct transition order through Europe/London DST fallback and correct 23-hour/25-hour day durations. The retained interval limit is raised to 800 state intervals so a legitimately busy 30-day history does not fail at the previous 100-transition ceiling.

Historical naming is retained with each new checkpoint. A display-name change can create a name-only checkpoint while preserving the same policy state hash, so the timeline can show what the device was known as without counting a rename as a policy transition. Identity metadata is operational evidence and is not exported as configuration identity.

Retained IPFIX and DNS evidence are now independently degraded inside policy correlation, matching the wider Activity evidence contract. Zero denominators are **NO EVIDENCE**, failed source queries are **UNAVAILABLE**, one healthy source survives failure of the other, and classification percentages are withheld when accounting is inconsistent. Current traffic-ingest heartbeat state is shown separately as current collection evidence and never rewrites already-retained historical rows. The structured correlation contract now also states explicitly that its policy evidence is a desired-policy checkpoint and that historical RouterOS execution proof is **not recorded**.

## v0.48.0 — Aggregate policy-group lifecycle closure

v0.48 closes the aggregate policy-group lifecycle across creation, profile blocks, group quotas, service schedules, reusable service collections, policy templates, display-name changes, membership changes, dependency-gated deletion and configuration backup/restore. Stable machine keys remain the durable identity across every reference surface; display names can change without rewriting those references, and membership changes immediately resolve through the current live group catalogue into concrete service intent. Explainability and simulation continue to consume that same catalogue/parity contract.

Backup/restore now preflights aggregate-group identity and every supported service/group reference before destructive table replacement. A malformed group member, missing referenced group, incomplete built-in catalogue, duplicate identity or invalid/overlong stable key fails before current configuration is touched. Stable keys are never truncated during import, and profile/template/collection references are no longer silently filtered into a different desired policy. The complete absence of the group section remains the explicit compatibility path for pre-v0.35 exports and resets built-ins to product defaults.

Aggregate groups remain logical expansion only and **never become RouterOS authority**. Router policy plans contain concrete supported member services only, reporting-only members remain visible as unsupported requested intent, and the RouterOS write boundary continues to reject any unknown/group-level service key rather than minting `MC_Block_<group>` or equivalent authority.

## v0.47.0 — Operational diagnostics & dependency-chaos closure

v0.47 hardens the read-only Operational Diagnostics surface so a failing dependency cannot collapse the diagnostic capture or make another subsystem look healthy by association. Every local/background snapshot is failure-isolated, RouterOS session construction and entry failures degrade only RouterOS-owned checks, and raw exception text is never copied into the support report. PostgreSQL telemetry, the traffic-ingest process, Pi-hole DNS source, IPFIX source and classifier consumer now have independent evidence states. A stale traffic-ingest heartbeat explicitly invalidates its last DNS/IPFIX source claims instead of carrying old `AVAILABLE` evidence forward.

The traffic-ingest container publishes a bounded `zen_telemetry_ingest_status_v1` heartbeat through the existing read-only `telemetry-state` volume. It contains only heartbeat age, DNS/IPFIX source availability and flow-queue depth: no client addresses, domains, credentials or exception strings. DNS availability requires both a reachable Pi-hole DNS listener and successful read-only access to Pi-hole FTL data, so a stopped container cannot look healthy merely because its named volume remains mounted; IPFIX availability is updated from the live flow-pipe reader. The existing classifier-consumer heartbeat is surfaced separately, with `stale_live` and bootstrap `fallback` represented as warnings rather than healthy live-catalogue evidence.

## v0.46.0 — Classification intelligence & degraded-evidence closure

v0.46 closes evidence and accounting gaps across Activity classification surfaces. Zero observed traffic bytes or DNS queries are now `NO EVIDENCE`, not a fabricated `0%` classification measurement; missing IPFIX and DNS sources remain independently `UNAVAILABLE`, so one failed evidence source no longer erases a healthy one. Coverage percentages are withheld when classified + unclassified evidence does not reconcile to the observed denominator, malformed negative counters are treated as `INCONSISTENT`, and the Activity/dashboard summaries preserve the same component evidence states instead of coercing `None` back to `0.0%`. A healthy source can therefore remain measured while its peer is unavailable, without that availability failure being mislabeled as an accounting mismatch.

The bounded unknown-DNS candidate list now exposes a percentage only while its captured rows reconcile to the captured unknown-query denominator. If late-arriving/changing retained evidence makes the bounded list exceed that denominator, ZEN keeps the raw diagnostic ratio, marks the snapshot `INCONSISTENT`, and withholds candidate shares rather than displaying an impossible measured percentage. Candidate review remains read-only: current catalogue changes may move retained unknown DNS between unmatched/current-signature review states, but historical telemetry is never rewritten or silently promoted.

The traffic-ingest classifier publishes a sanitized heartbeat (`zen_classifier_consumer_status_v1`) into its existing state volume. ZEN Control mounts only that volume read-only and surfaces whether the actual consumer is `live`, `stale_live`, bootstrap `fallback`, stale or unavailable, together with service/signature counts and age. A fresh `live` heartbeat remains healthy even for a valid-empty live catalogue; `stale_live`, bootstrap fallback, stale and unavailable consumer states are explicitly degraded. The heartbeat contains no device identities, domains, DNS queries or traffic volumes.

## v0.45.0 — Explainability, simulation & Device 360 parity closure

v0.45 closes parity gaps between the effective-policy resolver and the three parent-facing interpretation surfaces. Simulation now treats reporting-only/unsupported service requests and quota-policy changes as real desired-policy changes even when current RouterOS-enforceable mode/services do not change. Explainability uses the live aggregate-group catalogue for provenance, carries unsupported aggregate members as `BLOCK REQUESTED`, and distinguishes `NO CONTRACT` reporting-only state from approved-but-malformed `DEGRADED`, live RouterOS `UNAVAILABLE`, and wholly `UNKNOWN` evidence. Device 360 consumes the exact explanation contract rather than making a second policy decision and reports those service-contract states separately. The surfaces remain read-only and do not infer enforcement from missing evidence.

# ZEN Control

ZEN Control is a household internet-policy and activity dashboard for MikroTik RouterOS. It keeps RouterOS as the enforcement authority while providing parent-friendly device policy, schedules, service controls, temporary access, rewards, quotas, security posture, incidents and telemetry-backed activity reporting.

## v0.44.0 — Service intelligence & custom-service lifecycle closure

v0.44 closes the service-intelligence lifecycle around the dynamically published telemetry catalogue and custom-service identity. The telemetry classifier now treats a valid live catalogue as authoritative even when it contains zero DNS signatures. Built-in fallback classification is bootstrap-only: after a valid live catalogue has been observed, a missing, malformed or unsupported replacement retains the last known-good live classifier and reports `stale_live` rather than silently reverting to built-in defaults. Atomic catalogue replacement is detected using file identity/size/mtime rather than mtime alone, so rapid `os.replace()` publications are not missed on filesystems with coarse timestamps.

Custom-service deletion is now dependency-gated across profile blocks, policy templates, service schedules, reusable service collections and aggregate policy-group membership. The service UI surfaces the dependency count before deletion. Retained PostgreSQL activity remains untouched; after metadata deletion, historical service rows can still appear as observed/untracked network evidence. An approved custom service whose stored metadata can no longer build its deterministic RouterOS contract is omitted from runtime write authority and reported as DEGRADED rather than taking down the whole service catalogue or being mislabeled reporting-only.

The existing v0.23 safety contract remains unchanged: custom services are reporting-only until explicit preview/approval, install/remove operations fresh-read RouterOS, partial/conflicting MC contracts fail closed, and aggregate groups never acquire their own RouterOS authority.

## v0.43.0 — Quotas, rewards & temporary-access closure

v0.43 closes the quota/reward/temporary-access lifecycle gap. Reward redemption is now crash-safe across the SQLite→RouterOS boundary: a redemption reference is written into the RouterOS temporary scheduler only after NORMAL has been freshly verified, startup recovery completes proven grants, refunds only proven non-grants, and leaves uncertain reservations debited rather than creating free access. A second redemption is refused while the first remains pending recovery, and the device UI surfaces that held state explicitly.

Extending an already-active temporary override now updates its existing RouterOS scheduler/script in place instead of removing the previous fail-safe first. If the extension update fails, the old expiry safety net remains present. New overrides still create bounded app-owned scheduler/script resources and retain fresh post-write validation. Reward minutes may only be spent when the effective device policy is SLOW or BLOCKED; NORMAL policy has no device-mode restriction for reward access to lift.

Quota state remains recomputed from current retained telemetry on every resolution: late-arriving usage can trigger enforcement on the next cycle, a new local calendar day releases the previous day's quota without sticky state, and telemetry loss never reuses a previously exhausted result. This preserves the deliberate fail-open quota evidence contract while RouterOS policy itself remains authoritative.

## v0.42.0 — Authentication, shared-display & device lifecycle closure

v0.42 closes the next core lifecycle gap and incorporates a focused shared-display UX cleanup. Context help on the main application is now reached from a subsection-aware **Help** top-navigation item immediately after Settings instead of consuming page space with a persistent context strip. Shared-display lock state is also kept entirely in the top authentication cluster: locked mode shows the OTP/recovery unlock control; unlocked mode shows the exact remaining timer and **Lock now** action, with no page-wide lock/unlock banner.

Authentication privilege is now explicitly process-bound. The short parent unlock and the 90-second fresh step-up window do not survive an application restart even when the signed browser session remains valid. Legacy signed sessions without server-side `auth_generation` metadata are no longer grandfathered into current authority and must sign in again. Existing TOTP replay protection, one-use recovery codes, independent authenticator revocation and session-generation revocation remain unchanged.

Managed-device removal now retires live IP-keyed local policy, device-targeted schedules/date exceptions and reward state after RouterOS removal succeeds. Historical telemetry, audit and policy-state history remain retained. This prevents a different physical device later reusing the same IP from inheriting the previous device's alias/profile/mode or per-device automation. Retained historical network evidence is still IP-keyed and therefore does not prove continuous physical-device identity across an IP reuse boundary.

## v0.41.0 — RouterOS authority & security hostile closure

This release closes the next core-safety gap by moving the RouterOS enforcement write gate into the adapter write boundary itself and adding hostile failure-injection coverage. Critical policy writes now require proven enforcement authority even when invoked outside the normal UI/reconciler callers; successful authority proof is reused only inside one coherent RouterOS session and is never cached across requests.

Hostile coverage exercises missing, duplicated, disabled and misordered critical rules, duplicate `RW99`, app-managed custom rules after `RW99`, RouterOS write-RPC failure, contradictory post-write state, and mid-service-transition interruption. Security posture remains strictly read-only and never silently repairs manually owned critical authority. Multi-service changes establish all newly requested blocks before releasing obsolete blocks so partial failures remain restrictive.

The explicit `/web-policy` recovery control remains intentionally separate: it may toggle the existing manually provisioned restricted-web jump but does not create or repair missing authority.

## v0.40.0 — Policy & time-boundary closure

ZEN policy wall-clock handling is explicit across schedules, date-exception templates, simulation, Activity day windows and quota reset windows. Ambiguous DST fallback times use the first physical occurrence; nonexistent spring-forward times execute at the first valid local instant after the gap. Absolute comparisons are performed in UTC so fold semantics cannot be lost. Next-policy actions expose any DST adjustment.

Date-exception resolution now consumes the resolver's explicit profile context, so unsaved profile simulations and live resolution use the same schedule/exception target. Schedule-template times are validated as real 24-hour `HH:MM` values. Activity and quota windows follow calendar days in the configured policy timezone, including 23-hour and 25-hour DST days.

This slice adds closure coverage for midnight/day rollover, DST gap/fold behaviour, restart-style stateless recalculation, date-exception/simulation parity, template validation and quota/activity day boundaries. It adds no RouterOS authority or write path.

## Performance Closure (v0.39)

v0.39 turns the v0.30 measurement and v0.30.1 optimization work into an explicit closure gate. It does not relax RouterOS safety semantics.

### Managed-device observational snapshot

Dashboard and **Devices -> Managed** now acquire device mode, concrete-service membership and app-managed bandwidth from one fresh, read-only RouterOS observational snapshot per request. The snapshot collapses the previous per-device/per-service N+1 query pattern while retaining the same evidence rules:

- no values are cached across HTTP requests;
- the per-device block primitive is validated once for the snapshot;
- concrete service contracts are validated once per service, or reuse the already-fresh Dashboard service-health result from the same coherent RouterOS session;
- service source-list membership is read once per concrete service rather than once per service per device;
- queue state is read once and indexed in memory;
- malformed authority is surfaced as an error rather than repaired;
- write, pre-write and post-write validation routes do **not** use the observational snapshot;
- temporary-access reads retain their existing cleanup path for expired app-owned scheduler/script artefacts.

### Responsiveness acceptance

`/performance` now evaluates retained live requests against current-scope p95 budgets. A class remains `PENDING` until it has at least five representative requests by default:

- main navigation: p95 <= 1000 ms;
- local configuration writes: p95 <= 750 ms;
- RouterOS-changing actions including fresh validation: p95 <= 2000 ms;
- RouterOS read/drill-down pages: p95 <= 1500 ms;
- RouterOS-requiring requests: p95 <= 1 connection/request.

The defaults are deliberately configurable through `ZEN_PERF_ACCEPTANCE_MIN_SAMPLES` and the `ZEN_PERF_BUDGET_*` environment variables. Budgets are acceptance targets, not authority shortcuts: a slow but necessary fresh validation read must be optimized rather than removed.

Root navigation timings are now separated by bounded information-architecture labels such as `GET /?view=devices&section=managed` instead of every main view being aggregated into `GET /`.

After collecting a representative `/api/performance` snapshot, run:

```bash
python3 scripts/perf_acceptance.py zen-performance.json
```

Exit status is `0` only when all acceptance classes pass (`--allow-pending` can be used while commissioning). Continue to use `scripts/perf_analyse.py` for component/query ranking and `scripts/perf_runtime_snapshot.sh` for host/container evidence.

## Context & Help Documentation (v0.38)

v0.38 adds a static, read-only Help Center at `/help` plus `/api/help` (`zen_help_catalog_v1`). The main application derives one compact context-help strip from the current top-level view and subsection; standalone tools such as Device 360, Policy Explainability, Policy Simulation, Policy Quality, Classification, Historical Policy Correlation, Diagnostics and Performance link to their exact help topic. The Help Center provides search/filtering, related feature links and a concise glossary rather than embedding long manuals into working pages.

Help content documents ZEN's evidence boundaries as product behaviour: Activity is network evidence rather than browser history or proof of intent; desired policy is distinct from live RouterOS state and does not prove historical execution; `UNKNOWN`/`UNAVAILABLE` is not silently converted to NORMAL or zero usage; reporting-only custom services are not claimed as enforced; and aggregate policy groups expand only to concrete services rather than creating aggregate RouterOS authority. The help API contains no household data or credentials and has no write path, RouterOS access or policy-store dependency.

The recurring UX validator now checks contextual-help coverage, the glossary/evidence topics, responsive help layout, current help asset versioning and the PWA cache boundary. Only `help.css` is included in the versioned presentation shell; `/help` HTML and `/api/help` remain network-only like other authenticated dynamic responses.

## v0.37.0 — Progressive Web App / Android tablet

ZEN Control v0.37 is installable as a Progressive Web App, particularly for the shared Android/Kitchen Display use case. The manifest uses a stable root scope and standalone display mode, with shortcuts to Managed devices and Activity. The application exposes the service worker at `/service-worker.js` and reports its server-side contract at `/api/pwa/status`.

Android/Chromium requires a secure origin for full PWA installation: use HTTPS for a tablet connecting over the LAN (localhost/loopback are development exceptions). If ZEN is opened from a plain `http://192.168.x.x:8080` URL, the Parent Access install panel reports `HTTPS REQUIRED` rather than pretending installation is available.

The PWA is deliberately **online-first**. Only static presentation assets, icons, the manifest and a sanitized offline screen are cached. Authenticated HTML, API responses, household policy/device/activity data, login state and configuration exports are never stored by the service worker. POST/PUT-style mutations are never queued for background replay, and Background Sync/Push are not enabled. If ZEN Control is unreachable, the installed app shows the sanitized offline screen and RouterOS continues enforcing its current state. Parent unlock/shared-display protection remains server-side and therefore has identical authority in browser and standalone modes.

When a new application shell is installed by the service worker, ZEN shows an explicit update-ready banner and reloads only after the user accepts the update. Old versioned shell caches are deleted on activation.

## UX Validation & Consistency Hardening (v0.36)

v0.36 is a dedicated recurring UX-validation slice rather than a feature expansion. It standardizes standalone operational pages around explicit owner-return actions, current ZEN Control browser titles, responsive shared layout chrome and consistent compact action bars. Configuration Import Preview and Policy Summary now use the same standalone page structure as newer drill-downs instead of looking like legacy orphan screens. User-facing device terminology is normalized to **Managed devices** while RouterOS-specific diagnostics can still name restricted-address-list entries explicitly.

The shared-display parent unlock/lock forms now preserve the current top-level view and subsection, so unlocking from Policies, Activity or Settings returns to the work in progress instead of redirecting to Dashboard. Main and subsection navigation now expose `aria-current`, use scroll snapping, and automatically bring the active tab into view on horizontally constrained tablet/mobile navigation. Button links use touch-safe aligned hit areas, visible keyboard focus and explicit back-link treatment, with reduced-motion preferences respected.

The recurring UX pass is now executable rather than purely manual:

```bash
python3 scripts/ux_validate.py
```

The dependency-free validator checks every template for responsive viewport metadata, current CSS cache-busting, consistent standalone layout chrome, explicit owner/back links, product browser titles, stale branding/device terminology and navigation continuity. It is intentionally a static hygiene gate rather than a browser automation suite, and should run alongside the normal Jinja/unit tests during future every-other-slice UX reviews.

## Aggregate Policy Groups CRUD (v0.35)

v0.35 turns aggregate policy groups into an operator-managed policy primitive rather than a fixed built-in list. **Policies → Tools & sets → Aggregate policy groups** supports create, rename, description/member updates and safe custom-group deletion. Every group has a stable machine key; changing its display name therefore does not break profile, quota, service-schedule, reusable-collection, simulation, explainability, historical-policy or audit references. The built-in `gaming` and `social_media` keys remain non-deletable compatibility anchors, but their display names and concrete-service membership can be edited.

Membership is restricted to concrete services. Nested aggregate groups and missing services are rejected, and deleting a custom service is refused while that service is still a member of an aggregate group. Before deleting a custom group ZEN checks current references across profile blocks, profile quotas, policy templates, concrete service schedules and reusable service collections; referenced groups must be detached first. The editor surfaces those dependency counts and warns before membership changes that can alter desired policy. Configuration backup/restore preserves custom stable keys and restores groups before dependent profiles.

Aggregate groups are **logical expansion only**. A group such as `Streaming` can expand to Netflix, Prime Video and BBC iPlayer in policy, quotas and schedules, but ZEN never creates `MC_Block_Streaming`, a TLS learner, detector list or any other aggregate RouterOS firewall authority. Enforcement continues to resolve exclusively to concrete service contracts. Reusable service collections remain a separate authoring convenience and do not become live aggregate policy groups.

v0.35 also fixes the Activity → Policy correlation device selector. Managed devices now use the normal identity hierarchy and display `DEVICE NAME (IP ADDRESS)` when a name is known, with the raw IP used only when no managed name exists. The selector no longer produces misleading labels such as `192.168.1.102 (192.168.1.102)`.

## Operational Diagnostics & UX Validation (v0.34)

v0.34 adds **Settings → Operations → Operational diagnostics** at `/diagnostics` with structured API `/api/operations/diagnostics` (`zen_operational_diagnostics_v1`). The diagnostic capture composes existing authorities rather than inventing a second health system: application process evidence, SQLite integrity, RouterOS reachability, enforcement/security posture, managed-state inventory, custom-service contract health, PostgreSQL telemetry reachability, reconciliation and incident workers, summary-delivery worker state, durable audit/snapshot evidence and the retained v0.30 performance aggregates. RouterOS probes share one coherent API session but each probe still performs its real fresh read.

The downloadable `/local/operations/diagnostics/export` bundle is sanitized by construction. It contains approved health states, counts and timings only; it deliberately omits credentials/tokens, session material, RouterOS host/user values, managed-device IPs, DNS/domain contents, service/member names, raw request paths, audit/incident details and raw network exception text. Exporting a bundle is audited, but diagnostics never create, repair or modify RouterOS authority, policy, queues, schedules or Kid Control. A failed dependency degrades only its own check so operators can still inspect the rest of the system.

v0.34 also performs the scheduled recurring UX validation pass. Settings → Operations now exposes Diagnostics and Performance as compact first-class tools, the Dashboard Operations health row drills directly into Diagnostics, health/recovery endpoint documentation includes the new contract, and Operations action clusters wrap cleanly on tablet/mobile instead of pushing status/actions out of view. Standalone Diagnostics has explicit Back to Operations, Performance, JSON/export and refresh paths so it does not become another navigation dead end.

## Historical Policy Correlation (v0.33)

v0.33 adds a durable historical desired-policy checkpoint stream and a read-only **Activity → History → Policy correlation** workbench at `/activity/policy-history` with structured API `/api/activity/policy-history` (`zen_policy_correlation_v1`). Checkpoints are captured from the same `get_effective_policy()` resolver used by live reconciliation, so history does not introduce a second policy engine. A checkpoint is written only when the effective desired state actually changes; repeated reads of the same state do not grow the table.

The first checkpoint is seeded at v0.33 startup for locally managed devices, after which normal policy resolution/reconciliation continues the history automatically. Retained telemetry from before that first checkpoint is deliberately shown as **UNKNOWN policy evidence**. ZEN does not backfill old desired state from current configuration, audit prose or later snapshots. Future/past what-if simulation also cannot become history: only effective policy resolved for the current time window is eligible for a checkpoint.

The correlation workbench supports Today, Yesterday, 7-day, 30-day and custom retained windows for one managed device. It combines policy intervals with IPFIX/DNS evidence using two bounded PostgreSQL aggregate queries for the whole report rather than per-checkpoint N+1 analytics queries. Each interval shows observed desired mode/source, bandwidth preset, service/group blocks, traffic volume, classification coverage and explicitly blocked DNS counts. Policy-history rows are operational evidence and are not included in configuration export/restore identity.

Historical correlation remains evidence-led: a policy checkpoint proves the **desired policy ZEN observed**, not that RouterOS successfully executed every action for the entire interval. IPFIX/DNS remains network evidence rather than browser history, foreground-app time or proof of user identity. Device 360, per-device Activity and Historical Analytics link into Policy correlation, while the page itself contains no write form or RouterOS authority path.

## Policy Conflict & Shadow Analysis (v0.32)

v0.32 adds a read-only **Policies → Tools & sets → Policy quality** workbench at `/policy/quality` with structured API `/api/policy/quality` (`zen_policy_quality_v1`). It performs static saved-configuration analysis only: opening the workbench does not connect to RouterOS, does not execute reconciliation and does not write policy. The report separates **CONFLICT**, **WARNING**, **SHADOW**, **REDUNDANT** and **UNUSED** findings instead of flattening every precedence relation into an error.

The analyzer highlights equal-precedence contradictory schedules/date exceptions that can make policy ambiguous; more-specific device/profile schedules or exceptions that deterministically override broader rules; device mode overrides that shadow assigned-profile mode; aggregate policy groups combined with redundant explicit member blocks; reporting-only custom services referenced by enforceable profile intent; quota configuration while the quota engine is disabled; profile bandwidth suspended by a non-NORMAL base mode; unused profiles; schedules/exceptions targeting removed profiles or unmanaged devices; and empty/stale reusable service collections. Findings link back to the exact owning editor where possible. The workbench is configuration-quality evidence, not child-behaviour scoring, and contains no risk or confidence score.

v0.32 also performs the planned recurring UX validation pass. Standalone page headers/actions now share wrapping tablet/mobile behaviour, the Performance page returns to the current Settings → Operations route, policy/service-collection and reward actions return to their exact subsections, profiles/schedules/date exceptions/service collections can be deep-focused from contextual links, and Policy Summary / Simulation / Schedules now cross-link directly to Policy Quality. This recurring UX/layout/navigation review should continue approximately every other feature slice so new capability does not accumulate dead ends or stale navigation.

## Classification Intelligence Workbench (v0.31)

v0.31 adds a read-only **Activity → Classification** workbench that turns the existing classification coverage and unknown-domain evidence into an operator review workflow. It compares traffic and DNS attribution with the immediately preceding equivalent window, shows daily coverage trends, current concrete-classifier/signature counts, named-service attribution movement, and ranks up to 80 unknown DNS candidates by retained query volume.

Candidate review is deliberately conservative. A **CURRENT SIGNATURE** candidate means the retained DNS row is unclassified even though the hostname matches a DNS suffix in today's service catalogue; that can indicate a signature was added later, was disabled at ingestion time, or the telemetry consumer had not yet reloaded the catalogue. A **NAME-ONLY HINT** is only a textual review clue and never becomes service attribution. **UNMATCHED** means no current signature or service-name hint was found. There is no risk/confidence score and ZEN never presents these hints as browser history, foreground-app time or proof of intent.

The workbench can link an operator back to an existing service definition or prefill the exact candidate hostname into the existing custom-service editor. Prefill is not save or approval: the operator must still choose the service identity/signature scope and explicitly save it, and RouterOS provisioning continues to require the separate v0.23 preview/approval/fresh-validation workflow. Logical policy groups remain excluded from classifier signatures and never acquire aggregate RouterOS authority.

The deeper 7/30-day queries execute only on `/activity/classification` (and its authenticated API `/api/activity/classification`), not during ordinary Activity overview navigation. This preserves the v0.30.1 view-scoped performance work.

## Performance Implementation (v0.30.1)

v0.30.1 applies the first evidence-led responsiveness changes without weakening RouterOS authority. The root application now renders only the requested **top-level view** and gathers expensive data according to the requested **view/subsection**, instead of rebuilding every Dashboard, Devices, Policies, Schedules, Activity, Incidents, Audit and Settings surface after every navigation or POST redirect. Local-only Settings subsections therefore avoid RouterOS work, while RouterOS-backed sections load only the evidence they own. Dashboard connected-health keeps its useful cross-system summary but uses a reduced telemetry query set instead of eagerly constructing the complete Activity page.

RouterOS-backed synchronous requests/actions now use one **coherent RouterOS transport session** for their sequence of API operations. This removes repeated TCP/API login/disconnect overhead within the same user action, including multi-device page composition and pre-read → write → post-write validation flows. It is deliberately **no RouterOS value cache**: each adapter method still performs its normal fresh resource query, security authority is unchanged, and **post-write fresh validation** remains mandatory. The outer request owns the one real disconnect.

POST forms also show immediate **Applying…** feedback while the guarded server-side action completes. This is presentation only; ZEN does not optimistically claim success before RouterOS/config validation returns. The v0.30 performance evidence page and scripts remain available so production p50/p95, component call counts and cumulative costs can be compared before and after v0.30.1.

## Performance Gathering (v0.30)

v0.30 is intentionally a **measurement release**, not an optimization release. It adds bounded in-memory timing evidence so v0.30.1 can optimize proven bottlenecks instead of guessing. Request timing is exposed through `X-ZEN-Request-Ms` and `Server-Timing` response headers and through the authenticated `/performance` page and `/api/performance` JSON contract (`zen_performance_snapshot_v1`). Static assets, health checks and the performance endpoints themselves are excluded from request sampling so observation does not dominate the dataset.

The collector records route latency distributions; public RouterOS, SQLite/config and PostgreSQL/activity call counts and durations; RouterOS connection time; PostgreSQL query fingerprints and timings; policy/explainability/Device 360 composition; Jinja render time; selected background worker cycles; process RSS/CPU/thread evidence; and the slowest retained requests. Measurements are memory-only, bounded by environment settings and cleared on application restart or an explicit unlocked reset. PostgreSQL query previews are the application's static SQL text only; parameter values are never collected.

For a representative baseline, use ZEN normally first, then open **Settings → Operations → Performance evidence** (or `/performance`). The browser baseline probe performs a warm request followed by repeated authenticated GET measurements of the Dashboard, Parent Summary, historical analytics, Policy Summary and Policy Simulation. Add representative Device 360 or policy-explanation paths for managed devices if useful. The probe compares browser elapsed time with the same request's server-side `X-ZEN-Request-Ms` value.

A synthetic test-suite control is also available:

```bash
python3 scripts/perf_unit_baseline.py --runs 5
```

Collect a complementary Docker/SQLite/PostgreSQL runtime snapshot from the deployment host with:

```bash
bash scripts/perf_runtime_snapshot.sh > zen-runtime-performance.txt
```

The runtime script prints container CPU/memory/I/O, policy database sizes and row counts, PostgreSQL database/table/index activity and connection counts. It deliberately does not print passwords, tokens, DNS query contents or packet payloads.

After saving `/api/performance` JSON from the browser, rank the captured evidence with:

```bash
python3 scripts/perf_analyse.py zen-performance.json --top 20
```

Do not treat one cold request as an optimization target. Collect multiple warm samples during normal use and look for high p95 route time, repeated calls per request, cumulative RouterOS/SQL cost, slow SQL fingerprints and background-worker overlap. v0.30 deliberately changes no caching, batching, query strategy or lazy-loading behaviour; those belong to v0.30.1 after the baseline is reviewed.

## Policy Simulation / What-If Impact (v0.29)

ZEN Control includes a read-only Policy Simulation workbench at `/policy/simulate`. It uses the same effective-policy resolver as reconciliation, but supplies proposed device/profile values in memory rather than saving them. The workbench compares baseline and proposed mode, bandwidth, concrete service blocks, logical policy groups, decision source and next automatic policy event. Device-assignment and existing-profile editors also provide **Preview impact** actions so an operator can inspect unsaved changes before committing them.

Existing profile previews aggregate the impact across every currently assigned managed device, including counts for changed devices, mode changes, bandwidth changes and service/group changes. A workbench simulation can optionally compare the simulated desired state with a fresh RouterOS read; that comparison is explicitly current-state evidence, not a prediction of future RouterOS state. Simulation never writes SQLite, RouterOS firewall rules, address lists, queues, schedules or Kid Control. Future quota consumption is not predicted.
