# RALPH-Lite documentation

RALPH-Lite is ZEN Control's supervised engineering controller. It turns a bounded objective into a proposed plan, requires a human to approve the exact plan digest, then lets controlled implementation and qualification proceed one approved step at a time. It is process infrastructure for this repository: it is neither part of the deployed ZEN stack nor a RouterOS authority.

## What happens automatically

The controller can request a read-only plan proposal, bind its SHA-256 hash, create a Git recovery checkpoint at approval, run one model turn for one approved step, enforce policy, qualify work, retry the same failed step within its repair limit, retain evidence, and perform guarded commit/push after final qualification.

## What requires a human

A human approves the exact plan hash before implementation. A human reviews `BLOCKED_HUMAN` gates, supplies bounded steering or repair direction, confirms only explicitly delegated operator-evidence gates, decides destructive recovery, retires obsolete work, and may reconcile exceptional manual publication. Controller checks, not a model statement, decide whether a step passed.

## What RALPH cannot do

RALPH does not make RouterOS decisions, access live production systems, read or alter credentials, turn unknown evidence into PASS, change an approved plan during execution, weaken tests or qualification, override protected paths, force-push, invent a remote branch, or give a model publication authority.

## Read by question

- [Concepts](concepts.md) — plans, digest-bound approval, gates, evidence, and authority.
- [Architecture](architecture.md) — controller components, persisted records, and trust boundaries.
- [Authority, validation, and recovery](authority-validation-recovery.md) — who may decide what, how qualification is evidenced, and how to recover safely.
- [Extraction readiness](extraction/EXTRACTION_READINESS.md) — current ZEN coupling, host-adoption requirements, and the boundary ledger for a future standalone RALPH.
- [Lifecycle](lifecycle.md) — actual controller statuses, transitions, recovery, and finalization.
- [Reconciliation SITREP](RECONCILIATION_SITREP.md) — documentation maturity, legacy disposition, validation record, and remaining debt for this documentation set.
- [Historical operator guide](../RALPH-LITE.md) — protected legacy reference; use the lifecycle and operator reference pages here for current behavior. It is retained pending controller-authorized reconciliation.
- [Operator reference](operator-reference.md) — complete CLI contracts, local evidence, and restart procedures.
- [Controller policy](../../.ralph/policy.md) — controller-owned contract for an active run; do not edit it during an approved loop.

No section here describes a proposed capability. Any future design material must be labelled **FUTURE**, **PROPOSED**, or **EXTRACTION TARGET**.
