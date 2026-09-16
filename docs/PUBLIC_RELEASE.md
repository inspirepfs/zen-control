# Release and Maintenance Checklist

ZEN Control is already public. This document is now the **repeatable maintenance-release gate** rather than an initial-publication plan.

The application/PWA currently reports version `0.59.0`; maintenance releases are tagged `v0.59.0.x`. A tag can contain documentation, dependency, compatibility or release-process fixes without changing the runtime/PWA version.

## Release decision

A public maintenance release is allowed only after the exact source tree and target host pass qualification. Do not turn a warning, unavailable dependency, missing evidence or manual test into a synthetic PASS.

For security-sensitive changes, prefer a narrow forward hotfix over moving/deleting an already-public tag.

## Source and repository gates

- Documentation matches the behaviour being released.
- `.env.example`, Compose interpolation and source environment references pass `env_validate.py`.
- RouterOS setup templates match the current authority/service contracts.
- Deployment-specific hostnames/IPs/secrets are absent from the current tree.
- License remains **GNU Affero General Public License v3.0 or later (`AGPL-3.0-or-later`)**.
- Public Source links continue to point users at this repository.
- Screenshots, if added, are real sanitized captures and contain no household data. Screenshot absence is not a release failure.

## Security and depersonalization gate

Run:

```bash
python3 scripts/public_release_audit.py
python3 scripts/public_release_audit.py --history --deployment-markers
```

The second form reads selected non-secret identity values from local `.env` (`ZEN_LOCAL_HOST`, `ZEN_PUBLIC_HOST`, `ZEN_LAN_BIND_IP`, `MIKROTIK_HOST`) and scans without printing them.

Policy:

- current-tree secret or deployment-marker finding: **FAIL**;
- high-confidence secret in reachable Git history: **FAIL**;
- deployment identity in historical commits: **WARN / explicit review**;
- local `.env` absent: marker portion warns, current static audit still runs.

Credentials known to have been exposed outside the repository should still be rotated. Audit absence is not proof that a credential was never exposed elsewhere.

## Host and quality gate

The candidate should pass:

```bash
python3 scripts/env_validate.py
python3 -m py_compile app/*.py telemetry/ingest/*.py scripts/*.py
python3 scripts/ux_validate.py
python3 scripts/public_release_audit.py --history --deployment-markers
python3 -m unittest discover -s tests -t . -v
docker compose config >/dev/null
```

Use the normal release helper so backup/restore smoke, affected-service deployment, runtime/topology proof, exact Git commit and GitHub Quality evidence are preserved.

## Mandatory rebuilt-runtime smoke

After a release rebuilds `mikrotik-control`, source/unit tests are not enough. Verify the **actual container**:

1. `/health/live` returns HTTP 200;
2. `/health/runtime` returns HTTP 200;
3. `/login` renders successfully;
4. an authenticated dashboard route renders successfully;
5. Settings → Security/Diagnostics remain coherent;
6. the expected dependency versions are present when dependency floors changed.

This gate exists because v0.59.0.4 passed source tests and health routes while Starlette 1.6.0 had removed the legacy `TemplateResponse(name, context)` signature used by ZEN. v0.59.0.5 fixed the rendered-HTML compatibility boundary. Future framework/dependency changes must prove both API health **and actual HTML rendering**.

## Fresh-install / first-run acceptance

GitHub Quality includes an independent `fresh-install-commissioning` job in addition to the ordinary rebuilt-runtime smoke. It must prove that the current release can boot from truly empty throw-away Docker volumes, initialize the current SQLite schema/default catalogue, authenticate and render through the real built container, expose commissioning/support contracts, destroy the data volumes and repeat the same bootstrap a second time.

This gate is **destructive by design**. `scripts/fresh_install_acceptance.py` refuses known production/default project names and requires exact project-name confirmation before `docker compose down -v`. It belongs only on an isolated CI runner or disposable development host. It must never be repurposed as a live-install repair command.

The CI RouterOS target remains unreachable loopback. Fresh commissioning is expected to fail closed: local database/runtime evidence must PASS while RouterOS connectivity and security/authority remain BLOCKED or UNAVAILABLE. A fresh-install test must never manufacture RouterOS readiness or gain mutation authority.

## RouterOS final check

Before relying on a release as an enforcement system:

1. confirm RouterOS is on a vendor security-fixed release; for the September 2026 advisory that means stable `7.24.2+`, long-term `7.23.4+`, or later fixed release;
2. run `routeros/setup/99-verify.rsc`;
3. confirm Settings → Security is enforcement-ready;
4. confirm Operational Diagnostics has no unexplained critical failure;
5. confirm FastTrack cannot bypass `Restricted_Devices`;
6. retain Kid Control rollback state until deliberately retired for that installation.

## PWA/browser commissioning status

Current evidence is intentionally split:

- local HTTPS, certificate/hostname validation, HSTS, manifest and root-scope service-worker prerequisites: **qualified**;
- Android installation: **proven on at least one real device**;
- device-local install/reinstall diagnostics: **implemented**;
- representative tablet/multi-device commissioning closure: **OPEN / follow-up**;
- installed-PWA browser-push lifecycle across representative devices/restarts: **OPEN / follow-up**.

The device-local diagnostics distinguish server/browser prerequisites from the browser's own install decision and deliberately do not manufacture PASS from missing `beforeinstallprompt` evidence. The remaining representative-device/push follow-up items are **non-blocking for source publication** but remain visible commissioning work. Do not mark multi-device commissioning PASS merely because the server or one phone is healthy.

## Maintenance-release sequence

1. Start from a clean tagged/qualified baseline.
2. Apply one coherent patch with exact `-p0 --fuzz=0` semantics.
3. Run focused tests plus the complete quality gate.
4. Run `release_patch.py` so affected services, backup/restore smoke and CI/tagging are handled consistently.
5. Verify the rebuilt runtime, including rendered HTML when the app container changed.
6. Review public-source audit warnings explicitly.
7. Publish a new immutable maintenance tag/release; do not move a previously public tag.
8. Require the automated fresh-install/first-run acceptance to pass on its isolated throw-away Compose project.
9. For a release that changes public behaviour or setup, perform a fresh-clone/read-the-docs smoke from the public repository.

## Release evidence to retain

For significant release/security closure, retain the exact commit/tag, test summary, audit output, container dependency evidence where relevant and any upgrade/backup acceptance evidence. Never retain `.env`, live databases, credentials or household telemetry in a public release artifact.

## Support-bundle release gate

Maintenance releases that change diagnostics/support export must prove that hostile fake credentials, tokens, push endpoints, private hostnames, IP/MAC identifiers, email addresses and raw exception assignments do not survive the public support-bundle boundary. The default bundle must not embed raw Docker/application logs, DNS/activity rows or raw audit/incident details. Missing commissioning evidence remains `UNAVAILABLE`/`BLOCKED`, never PASS.

Before tagging, exercise both the authenticated browser download and the in-container CLI path where `ADMIN_PASSWORD` is available. The support collector remains read-only and must not acquire RouterOS mutation authority.
