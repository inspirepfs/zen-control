# ADR-XXXX: RALPH extraction boundary

**Status:** Accepted for boundary preparation; physical extraction deferred.

## Context

RALPH-Lite is embedded in ZEN Control and is supported there as supervised engineering infrastructure. The implemented `ZEN_PROFILE` seam routes host values without changing controller, web, gate, auth, CSRF, or qualification behavior.

## Decision

Prepare for a future independent repository with a project-neutral core direction while preserving embedded ZEN behavior. Core owns approval, lifecycle, repair/stop controls, recovery integrity, and audit semantics. ZEN supplies root/state placement, policy, qualification, metadata, security behavior, and guidance.

Host-associated runtime state remains at ZEN's `.ralph/` location. Existing filenames and persisted `zen_*` schema values are compatibility contracts and remain readable; this ADR does not migrate them. ZEN remains the supported host until independent implementation is approved and validated.

## Consequences

- Documentation deliberately duplicates core-topic material in `docs/ralph/` and ZEN-host material in `docs/zen/ralph-integration/` to support future separation without degrading current operations.
- Packaging, installation, configuration format, state migration, a non-ZEN profile, and independent operations are deferred **extraction debt**.
- A physical move must preserve approval hashing, one-step execution, qualification, recovery, and web/gate non-authority boundaries.

Evidence: [dependency ledger](../ralph/extraction/DEPENDENCY_LEDGER.md), [dry run](../ralph/extraction/DRY_RUN.md), and [ZEN integration](../zen/ralph-integration/README.md).
