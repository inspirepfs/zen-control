# Public Release Checklist

ZEN Control v0.59.0 is the public-release closure line. Product feature development is frozen for the initial public release; remaining work is qualification and publication hygiene.

## Release decision

A public release is allowed only after the current source tree and target host pass the final qualification. Do not turn a warning, unavailable dependency, missing evidence or manual test into a synthetic PASS.

## Closed source/repository gates

- Product-first README and operator/install/architecture documentation are present.
- RouterOS setup bundle is versioned under `routeros/setup/` and mirrors the current authority/service contracts.
- Deployment-specific Pi-hole split DNS is parameterized through `ZEN_LAN_BIND_IP` and `ZEN_LOCAL_HOST`; no household hostname/IP is embedded in Compose.
- Public-source audit checks current Git-visible files and can additionally scan reachable history and local deployment markers.
- License selected: **GNU Affero General Public License v3.0 or later (`AGPL-3.0-or-later`)**.
- Screenshots are intentionally **not part of the initial release**. Do not block publication waiting for screenshots and do not substitute synthetic UI imagery for real product evidence.

## License choice

ZEN Control is a self-hosted, network-facing control plane. AGPL-3.0-or-later is chosen so recipients can use and modify the software while modified versions offered to users over a network remain subject to the Affero source-availability requirement. The repository `LICENSE` notice links to the official GNU license text.

Contributions are accepted under the same project license unless explicitly stated otherwise.

The sign-in page and authenticated navigation expose a **Source** link to `https://github.com/inspirepfs/zen-control` so network users have a direct path to the corresponding public source.

## Security and depersonalization gate

Run both:

```bash
python3 scripts/public_release_audit.py
python3 scripts/public_release_audit.py --history --deployment-markers
```

The second form reads selected non-secret identity values from local `.env` (`ZEN_LOCAL_HOST`, `ZEN_PUBLIC_HOST`, `ZEN_LAN_BIND_IP`, `MIKROTIK_HOST`) and scans without printing them.

Policy:

- current-tree secret or deployment-marker finding: **FAIL**;
- high-confidence secret in reachable Git history: **FAIL**;
- deployment identity in historical commits: **WARN / explicit review** because history rewriting is a separate consequential operation;
- local `.env` absent: warning only for the marker portion; current static audit still runs.

Credentials known to have been exposed outside the repository should still be rotated when practical. The audit does not claim that absence of a match proves a secret never existed.

## Host and quality gate

The final candidate should pass:

```bash
python3 scripts/env_validate.py
python3 -m py_compile app/*.py telemetry/ingest/*.py scripts/*.py
python3 scripts/ux_validate.py
python3 scripts/public_release_audit.py --history --deployment-markers
python3 -m unittest discover -s tests -t . -v
docker compose config >/dev/null
```

Then use the normal release helper so backup/restore smoke, affected-service deployment, health/runtime/topology proof, exact Git commit and GitHub Quality evidence are preserved.

## RouterOS final check

Before relying on the public release as an enforcement system:

1. confirm RouterOS is on a vendor security-fixed release; for the September 2026 MikroTrick advisory that means stable `7.24.2+` or long-term `7.23.4+` (or a later vendor-supported security-fixed release);
2. run `routeros/setup/99-verify.rsc`;
3. confirm Settings → Security is enforcement-ready;
4. confirm Operational Diagnostics has no unexplained critical failure;
5. confirm FastTrack cannot bypass `Restricted_Devices`;
6. retain Kid Control rollback state until you deliberately retire it in your own installation.

## Explicitly open manual gate: Android / installed PWA

**Status: OPEN / DEFERRED — non-blocking for initial public source release.**

Already proven server-side prerequisites include local HTTPS, certificate/hostname validation, security headers, HSTS, root service worker and manifest delivery. The following evidence still requires representative device testing and must not be marked PASS yet:

- Android/Chromium install prompt and installation;
- standalone installed-PWA launch/upgrade behaviour;
- browser notification permission from the installed PWA;
- installed-PWA push receipt across normal lifecycle/restart cases.

Track this after release and close it only with real device evidence.

## Screenshots

No screenshots are required for the initial public release. Add real, deliberately sanitized product captures later after the public release is stable. The old screenshot capture checklist remains useful as privacy guidance, but screenshot absence is not a gate.

## Initial publication sequence

1. Complete v0.59.0 host qualification.
2. Review any audit warnings explicitly.
3. Confirm GitHub Quality for the exact candidate commit.
4. Create/push the release tag through the normal release workflow.
5. Change repository visibility only when the exact released commit is the intended public tree.
6. Perform one fresh-clone smoke test from the public repository.
7. Return later to the documented Android/PWA manual gate.
