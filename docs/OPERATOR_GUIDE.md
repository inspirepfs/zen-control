# Operator Guide

This is the day-2 guide for an installed ZEN Control system. Installation belongs in [INSTALL.md](INSTALL.md); RouterOS bootstrap belongs in [../routeros/setup/README.md](../routeros/setup/README.md).

## What "healthy" means

ZEN has several independent health/evidence planes. Do not collapse them into one green/red status.

| Plane | Primary evidence | Healthy means | A failure does **not** automatically mean |
| --- | --- | --- | --- |
| Process | `/health/live` | FastAPI process is alive | RouterOS authority is healthy. |
| Runtime workers | `/health/runtime` | embedded workers/mutation lane runtime are healthy | policy is correct on every device. |
| Readiness | `/health/ready` | DB/RouterOS/security/worker readiness contract passes | retained telemetry is complete. |
| RouterOS authority | Settings → Security, `/api/security/posture` | required static authority is provable | telemetry/reporting is available. |
| Telemetry | Activity/Reports/diagnostics | retained flow/DNS evidence is available | RouterOS enforcement stopped. |
| Delivery | Notifications → Delivery | configured push/SMTP/webhook path is ready | source incidents disappeared. |
| Release readiness | `/api/release-readiness` | current formal acceptance evidence passes | every optional/manual commissioning item is complete. |

## Routine operating checks

Use product surfaces first:

- **Settings → Security** — RouterOS authority and hardening contract.
- **Settings → Operations / Operational Diagnostics** — dependency/runtime state.
- **Release Readiness** — aggregated acceptance evidence.
- **Activity → Reports** — retained traffic/DNS/classification and lifecycle trends.
- **Notifications → Delivery** — browser push, SMTP and webhook delivery state.

Host-side baseline:

```bash
docker compose ps
docker compose logs --tail=100 mikrotik-control
curl -fsS http://127.0.0.1:8080/health/live
curl -fsS http://127.0.0.1:8080/health/runtime
```

For a quick post-change UI smoke, also render `/login` and an authenticated dashboard route. The v0.59.0.4 Starlette incident demonstrated why green health APIs alone are insufficient proof for server-rendered HTML.

## Suggested cadence

### After any configuration or RouterOS change

- rerun `python3 scripts/env_validate.py` when `.env` changed;
- recreate affected containers;
- check Settings → Security and Operational Diagnostics;
- verify the intended policy on one representative managed device;
- inspect recent audit/incident entries for unexpected holds or retries.

### Weekly or after a notable incident

- review database/runtime health and free storage;
- review notification delivery failures and retired webhook/browser subscriptions;
- check telemetry classification quality and missing-evidence states;
- verify backups are leaving the Compose volume and are readable;
- check current ZEN/RouterOS security updates before a planned maintenance window.

## Logs and safe diagnostics

Start with bounded logs:

```bash
docker compose logs --tail=200 mikrotik-control
docker compose logs --tail=200 telemetry-ingest
docker compose logs --tail=200 goflow2
```

Service names may vary with optional profiles; `docker compose ps` is the source of truth.

Do not post `.env`, raw databases, RouterOS exports, tunnel tokens, recovery codes or household telemetry publicly. If sharing logs, inspect them for hostnames, addresses, usernames and notification destinations first.

## Interpreting degraded evidence

ZEN intentionally preserves these distinctions:

- `UNKNOWN` is not zero.
- `UNAVAILABLE` is not healthy.
- reporting-only is not enforced.
- desired policy/checkpoints are not historical RouterOS execution proof.
- missing activity evidence is not proof of no activity.
- `PENDING` is not `PASS`.

A telemetry outage can therefore coexist with healthy RouterOS enforcement. Conversely, a healthy dashboard process does not prove RouterOS authority. Diagnose the failed evidence plane, not the colour of one unrelated health indicator.

## RouterOS security hold / recovery boundary

Static critical firewall authority is operator owned. ZEN will not guess-repair malformed static rules. If Security enters a hold:

1. do not bypass the write gate;
2. run `routeros/inspect.rsc` and `routeros/setup/99-verify.rsc`;
3. compare the live router with [routeros/setup/README.md](../routeros/setup/README.md);
4. identify whether the issue is ordering, a missing/duplicate anchor, FastTrack bypass, list/queue/script drift or API reachability;
5. repair only the proven defect;
6. rerun Settings → Security and Operational Diagnostics before allowing enforcement writes.

Legacy Kid Control may remain disabled but retained as the migration rollback safety net. Do not delete it merely because ZEN is authoritative.

## Telemetry degradation

When activity/reporting degrades, separate the path into RouterOS IPFIX export → GoFlow2 → telemetry ingest → PostgreSQL and Pi-hole DNS evidence. Check each service independently.

Do not "fix" missing telemetry by changing RouterOS policy authority. The telemetry pipeline is read-side evidence and owns no enforcement writes.

## Notification delivery degradation

Notification source truth is separate from delivery. A failed push/SMTP/webhook attempt does not clear the underlying incident or policy evidence. Check Notification Delivery for channel readiness, retries and retired destinations.

For SMTP/webhook troubleshooting, confirm environment configuration without printing credentials. The local `test-tools` profile is useful for simulation but should not be left enabled accidentally on a production host.

## PWA / browser troubleshooting

Known current state:

- local HTTPS/service-worker/manifest prerequisites are qualified;
- Android installation is proven on at least one real device;
- tablet/multi-device installability diagnostics remain open;
- installed-PWA push lifecycle commissioning remains follow-up work.

If a second device has no install option despite using the HTTPS FQDN, confirm it is full Chrome/Chromium rather than an in-app Custom Tab, check whether ZEN is already installed in Android app settings, clear/reset site state when appropriate, and use remote Chromium DevTools to inspect manifest/service-worker/installability errors. ZEN cannot legitimately force a native install prompt if the browser does not emit one.

## Backup and upgrade

Use `scripts/release_patch.py` for qualified software upgrades. When the application service is affected it creates a coherent external SQLite backup, validates the copy and runs an offline restore/upgrade smoke before container recreation.

Do not routinely use `--skip-policy-backup`.

A qualified release should prove, in order:

```text
current database → verified backup → restore/upgrade smoke → deployment
→ liveness/runtime → rendered HTML smoke → topology recovery → CI/tag
```

ZEN also retains an in-volume pre-schema recovery copy before compatibility migration. Keep environment secrets separately: restoring `policy.db` without the same `OTP_ENCRYPTION_KEY` cannot recover encrypted enrolled TOTP material.

## Rollback principles

- Prefer forward fixes for application-only hotfixes once a database schema migration has completed.
- Never restore an older `policy.db` over a newer live database without understanding schema/data consequences.
- If an upgrade cannot start, preserve the failed state and external backup before experimenting.
- RouterOS rollback is separate from application rollback: do not undo firewall authority merely because an HTML/template path failed.
- Kid Control cutover rollback restores legacy authority before unwinding migration-owned ZEN state.

## Public-source hygiene

Before publishing or cutting a maintenance release:

```bash
python3 scripts/public_release_audit.py
python3 scripts/public_release_audit.py --history --deployment-markers
```

The history/marker mode reads only selected non-secret deployment identity values from the ignored `.env`; it never prints their values. A current-tree identity leak is a failure. Historical identity findings are review warnings. High-confidence historical secret findings fail the audit and should trigger rotation/history remediation as appropriate.

See [PUBLIC_RELEASE.md](PUBLIC_RELEASE.md) for the complete maintenance-release checklist.
