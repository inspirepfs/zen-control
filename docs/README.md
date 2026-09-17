# ZEN Control Documentation

ZEN Control is a self-hosted control plane for MikroTik RouterOS. Start with the route that matches your role; every major documentation area is linked here or from the [documentation map](reference/documentation-map.md).

## Choose a route

### ZEN fundamentals

- [ZEN system overview](ZEN.md) — component relationships, authority limits, persistence, and implementation entry points.
- [Project overview](../README.md) — concise product orientation and role-based next steps.
- [Architecture](ARCHITECTURE.md) — authority boundaries, data stores, evidence, and failure semantics.
- [Shared glossary](reference/glossary.md) — the meaning of ZEN and RALPH terms used throughout the project.
- [Documentation map](reference/documentation-map.md) — document purpose, audience, ownership, duplication, and planned maintenance work.

### Operator: install and run ZEN

1. [Installation and commissioning](INSTALL.md) — host, networking, Compose, HTTPS, and first-run acceptance.
2. [Environment contract](ENVIRONMENT.md) — settings, secrets, conditional configuration, and recreation requirements.
3. [RouterOS integration](../routeros/README.md) — the operator-owned authority boundary.
4. [RouterOS setup bundle](../routeros/setup/README.md) — reviewed templates and safe installation order.
5. [Operator guide](OPERATOR_GUIDE.md) — health, degraded evidence, diagnostics, recovery, and incidents.

### Developer: change ZEN safely

- [Contributing](../CONTRIBUTING.md) — development principles, local quality gates, and pull-request expectations.
- [Architecture](ARCHITECTURE.md) — contracts a change must preserve.
- [Security policy](../SECURITY.md) — trust model, safe reporting, and sensitive-change concerns.
- [Supply-chain security](SUPPLY_CHAIN.md) — dependency, image, workflow, and SBOM controls.
- [Release and maintenance checklist](PUBLIC_RELEASE.md) — audit, runtime smoke, qualification, and publication gates.

### RALPH: supervised autonomous engineering

- [RALPH documentation tree](ralph/README.md) — RALPH’s place in this repository and the available process documentation.
- [Historical RALPH-Lite operator guide](RALPH-LITE.md) — protected legacy reference retained for context; use the RALPH documentation tree for current lifecycle and command behavior.
- [Shared glossary](reference/glossary.md#ralph-lite-terms) — plan, step, checkpoint, qualification, and block-state definitions.
- [Documentation map](reference/documentation-map.md#maintenance-findings) — documentation work deliberately deferred to later approved steps.

### Future adopter: evaluate ZEN

- [Project overview](../README.md) — what ZEN does and its safety model.
- [Architecture](ARCHITECTURE.md) — trust, authority, persistence, and evidence boundaries.
- [Installation prerequisites](INSTALL.md#before-you-start) — the host, RouterOS, and network commitments.
- [Security policy](../SECURITY.md) — deployment responsibilities and reporting process.
- [Release history](../CHANGELOG.md) — historical changes and maintenance context.

## Reference and supporting material

- [Screenshots and visual-asset guidance](screenshots/README.md) — text-first documentation and sanitized-image expectations.
- [RouterOS inspection script](../routeros/inspect.rsc) and [verification script](../routeros/setup/99-verify.rsc) — operator-run implementation companions; use them only through the RouterOS guides above.
- [Documentation map](reference/documentation-map.md) — also records document ownership and duplicates that need future consolidation or historical marking.

## Version and evidence language

The application/PWA runtime currently reports **`0.59.0`**; qualified maintenance releases are tagged **`v0.59.0.x`**. Identify a deployment by runtime version and Git release tag/commit. See the [glossary](reference/glossary.md) for the intentional distinctions among desired, enforced, retained activity, `UNKNOWN`, `UNAVAILABLE`, `PENDING`, and reporting-only evidence.
