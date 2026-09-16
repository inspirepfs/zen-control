# ZEN Control Documentation

ZEN Control is a self-hosted control plane for MikroTik RouterOS. The documentation is deliberately split by **operator journey** rather than mirroring the source-tree layout.

## Recommended reading order

### New installation

1. [Architecture](ARCHITECTURE.md) — understand RouterOS authority, evidence classes, persistence and failure boundaries.
2. [Installation and commissioning](INSTALL.md) — host, networking, Docker Compose, RouterOS preparation, HTTPS and first-run acceptance.
3. [Environment contract](ENVIRONMENT.md) — what belongs in `.env`, which settings are secret/conditional, and when changes require recreation.
4. [RouterOS integration](../routeros/README.md) — operator-owned authority and the read/write boundary.
5. [RouterOS setup bundle](../routeros/setup/README.md) — reviewed templates and safe installation order.

### Day-2 operation

- [Operator guide](OPERATOR_GUIDE.md) — routine health, degraded-state interpretation, commissioning diagnostics, safe support-bundle collection, backup/recovery, upgrade/rollback and incident triage.
- [Release history](../CHANGELOG.md) — maintenance/hotfix history and contract changes.

### Contribution, security and release

- [Contributing](../CONTRIBUTING.md) — development principles, quality gates and pull-request expectations.
- [Security policy](../SECURITY.md) — threat model, deployment responsibilities and vulnerability reporting.
- [Supply-chain security](SUPPLY_CHAIN.md) — immutable CI action pins, dependency automation, vulnerability scanning and SBOM evidence.
- [Release and maintenance checklist](PUBLIC_RELEASE.md) — source audit, runtime smoke, qualification and publication gates.

## Version terminology

The application/PWA runtime currently reports **`0.59.0`**. Qualified maintenance releases are tagged **`v0.59.0.x`**. A maintenance tag may therefore change documentation, dependencies or compatibility code without changing the runtime/PWA version. Always identify a deployed build by both the application version and the Git release tag/commit when troubleshooting.

## Evidence terminology

Across the documentation, these words are intentional:

- **desired** means policy intent computed by ZEN;
- **enforced/live** means supported by current RouterOS evidence;
- **retained activity** means network/DNS evidence kept for reporting;
- **UNKNOWN / UNAVAILABLE / PENDING** are not aliases for zero, healthy or PASS;
- **reporting-only** means evidence/classification exists without an approved enforcement contract.

## Screenshots and PWA status

The public documentation remains text-first. Real sanitized screenshots can be added later; synthetic screenshots are not used as operational evidence.

Android installation is proven on at least one real device. Multi-device/tablet installability diagnostics and installed-PWA push commissioning remain open follow-up items because browser/device installability is not fully controlled by ZEN.
