# Security Policy

ZEN Control can make bounded changes to a real MikroTik firewall and should be treated as **security-sensitive infrastructure**. It is not a cloud parental-control appliance: the operator owns the router, deployment host, secrets and exposure model.

## Supported security baseline

Security fixes are delivered on the latest published maintenance tag. Operators should run the latest `v0.59.0.x` maintenance release on the current `0.59.0` application line unless a newer documented release supersedes it.

RouterOS must also be on a vendor security-fixed release. For the September 2026 MikroTik advisory covered by the current public documentation, use stable `7.24.2+`, long-term `7.23.4+`, or a later vendor-supported fixed release.

Official advisory: <https://mikrotik.com/supportsec/september-2026-vulnerability/>. MikroTik additionally recommends keeping SSH off untrusted networks and checking the router log/configuration for `Flagged` status or unfamiliar users/scripts after upgrade.

## Threat and trust model

ZEN assumes the Docker host and the management path between ZEN and RouterOS are trusted administrative infrastructure. The project is designed to resist accidental authority widening and application-layer mistakes; it does not claim to make a compromised Docker host or router administrator account safe.

Important trust boundaries:

- Browser/PWA users authenticate to ZEN; optional Cloudflare Access is an outer gate, not a replacement for ZEN authentication.
- RouterOS remains the enforcement authority. ZEN has no arbitrary command console and critical static firewall anchors remain operator owned.
- Telemetry, notifications, reporting and background analytics have no independent RouterOS write authority.
- PostgreSQL activity data and SQLite policy/configuration state are sensitive household data even when they contain no passwords.
- `.env`, tunnel tokens, TOTP/recovery material and delivery credentials are secrets and must stay outside source control/support bundles.

## Deployment responsibilities

Operators should:

- use a dedicated RouterOS API account rather than a router administrator account;
- restrict RouterOS API reachability to the ZEN management host/path;
- never expose ZEN port `8080` directly to the public Internet;
- use HTTPS locally and Cloudflare Access + Tunnel for optional remote access;
- keep the Docker host, RouterOS and container images patched;
- preserve `OTP_ENCRYPTION_KEY` when backing up/restoring `policy.db`;
- retain verified backups before upgrades that rebuild `mikrotik-control`;
- review Settings → Security after RouterOS changes rather than bypassing a write hold.

## Reporting a vulnerability

Please do **not** publish credentials, household data, exploit details or a live deployment address in a public issue.

Use GitHub private vulnerability reporting if it is enabled. If it is not available, open a minimal public issue asking for a private security contact **without including exploit details or deployment data**.

A useful private report includes:

- affected release tag and commit if known;
- affected endpoint, workflow or authority boundary;
- whether RouterOS writes are involved;
- whether authentication/authorization can be bypassed;
- whether household/telemetry/secrets can be exposed;
- preconditions and a minimal reproduction using synthetic data;
- expected vs observed behaviour and any safe mitigation already tested.

## High-priority vulnerability classes

Particularly important reports include:

- unauthenticated or under-authorized RouterOS writes;
- bypass of fresh-auth/TOTP requirements;
- RouterOS mutation paths outside the declared adapter/mutation boundary;
- unsafe Kid Control cutover/rollback ordering;
- leakage of credentials, recovery material or household telemetry;
- service-classifier/reporting state being misrepresented as enforced authority;
- failures that silently convert `UNKNOWN`, `UNAVAILABLE` or `PENDING` into healthy/PASS evidence;
- request parsing/template/framework regressions that make authentication or server-rendered surfaces unavailable;
- dependency vulnerabilities reachable from unauthenticated network input.

## Secret and data handling

Never include `.env`, tunnel tokens, private keys, recovery codes, raw configuration exports, live database files or real household telemetry in an issue or pull request.

The built-in v0.59.0.10 support bundle is designed for public troubleshooting and applies a second defensive redaction boundary over already-sanitized diagnostic contracts. It excludes raw logs, DNS/activity rows, raw audit/incident detail, credentials, sessions and push endpoint/key material; network/identity values that reach the boundary are pseudonymized with process-local keyed markers. Review any artefact before publication, especially after local modifications or plugins that add new diagnostic fields. Raw `docker compose logs` are **not** part of the safe bundle and must be reviewed separately before sharing.

If a credential has been exposed, rotate it even if the repository audit later becomes clean. Deleting a value from the current tree does not revoke it.

## Dependency and build-chain controls

The public repository runs a separate supply-chain Quality job for Python dependency auditing, real application-image vulnerability scanning and CycloneDX SBOM generation. External GitHub Actions are commit-SHA pinned and Dependabot monitors Python, Actions, Dockerfile and Compose dependency surfaces. See [docs/SUPPLY_CHAIN.md](docs/SUPPLY_CHAIN.md) for the exact gate and its stated limits.

A clean scanner result does not turn missing provenance into proof of safety. In particular, version-tag monitoring is not the same as registry-digest pinning, and unfixed vulnerabilities are not treated as harmless merely because the blocking release gate is limited to vulnerabilities with an available fix.

## Public-source secret and depersonalization audit

Before a public release run:

```bash
python3 scripts/public_release_audit.py --history --deployment-markers
```

The marker scan reads selected non-secret deployment identity values from the ignored local `.env` and reports only variable names plus source locations, never the values themselves. Current-tree identity leakage fails the gate; historical identity is surfaced for explicit review. High-confidence secret matches in reachable Git history fail the audit.

The audit is a release control, not proof that no secret has ever existed outside the scanned surfaces.
