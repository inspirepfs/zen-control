# Operator Guide

This is the day-2 guide for an installed ZEN Control system. Installation belongs in [INSTALL.md](INSTALL.md); RouterOS bootstrap belongs in [../routeros/setup/README.md](../routeros/setup/README.md).

## Routine health

Use the product surfaces first:

- **Settings → Security** — RouterOS authority and hardening contract.
- **Settings → Operations / Operational Diagnostics** — dependency/runtime state.
- **Release Readiness** — aggregated acceptance evidence.
- **Activity → Reports** — retained traffic/DNS/classification and lifecycle trends.
- **Notifications → Delivery** — browser push, SMTP and webhook delivery state.

Host-side checks:

```bash
docker compose ps
docker compose logs --tail=100 mikrotik-control
curl -fsS http://127.0.0.1:8080/health/live
curl -fsS http://127.0.0.1:8080/health/runtime
```

A green HTTP health route is not a substitute for RouterOS authority/security proof.

## Upgrades and recovery

Use `scripts/release_patch.py` for qualified upgrades. When the application service is affected it creates a coherent external SQLite backup, validates the copy, and runs an offline restore/upgrade smoke before container recreation.

Do not routinely use `--skip-policy-backup`.

A release should prove, in order:

```text
current database → verified backup → restore/upgrade smoke → deployment
→ application health → runtime worker health → topology recovery
```

ZEN also retains an in-volume pre-schema recovery copy before compatibility migration. Keep environment secrets separately: restoring `policy.db` without the same `OTP_ENCRYPTION_KEY` cannot recover encrypted enrolled TOTP material.

## RouterOS recovery boundary

Static critical firewall authority is operator owned. ZEN will not guess-repair malformed static rules. If Security enters a hold:

1. do not bypass the write gate;
2. run `routeros/inspect.rsc` and `routeros/setup/99-verify.rsc`;
3. compare the live router with `routeros/setup/README.md` and the current source contracts;
4. repair only the proven defect;
5. rerun Security/Diagnostics before allowing enforcement writes.

Legacy Kid Control may remain disabled but retained as the migration rollback safety net. Do not delete it merely because ZEN is authoritative.

## Secrets and public-source hygiene

Before publishing or cutting a public release:

```bash
python3 scripts/public_release_audit.py
python3 scripts/public_release_audit.py --history --deployment-markers
```

The second command reads only selected **non-secret** deployment identity values from the ignored `.env`; it never prints their values. A current-tree identity leak is a failure. Historical identity findings are review warnings. High-confidence historical secret findings fail the audit and should trigger credential rotation/history remediation as appropriate.

## Evidence interpretation

ZEN intentionally preserves these distinctions:

- `UNKNOWN` is not zero.
- `UNAVAILABLE` is not healthy.
- reporting-only is not enforced.
- desired policy/checkpoints are not historical RouterOS execution proof.
- missing activity evidence is not proof of no activity.
- `PENDING` is not `PASS`.

## Deferred Android/PWA validation

The server-side HTTPS, service-worker and manifest prerequisites can be release-qualified independently. **Android PWA install/standalone behaviour and installed-PWA browser-push behaviour remain an explicitly open manual validation gate for the initial public source release.**

This gate is deliberately documented as **OPEN / DEFERRED**, not PASS. Return to it after representative Android/Chromium testing. A later test result may close it without changing RouterOS authority or the initial public-source availability decision.
