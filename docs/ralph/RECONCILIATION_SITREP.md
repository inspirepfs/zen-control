# RALPH documentation reconciliation SITREP

**Scope:** approved RALPH-Lite plan `3c9a894f19d8183f33e00350e43fe6b4f2898dd160bf461b79d379826d9ba44d`, step 8. This is a repository-documentation assessment only; it makes no RouterOS, deployment, credential, or production claim.

## Result and maturity assessment

**RESULT=PASS_WITH_DOCUMENTED_DEBT.** The current RALPH documentation route is usable: the index directs readers to the command contract, lifecycle, concepts, authority/recovery model, architecture, and extraction ledger. Those documents consistently describe RALPH as ZEN Control process infrastructure, not a deployed ZEN service or RouterOS authority.

The set is not fully mature because `docs/RALPH-LITE.md` remains a protected historical guide. It contains material useful for audit context but no longer describes all current behavior. Current navigation labels it historical and sends readers to the maintained RALPH tree; this avoids presenting legacy lifecycle and console statements as current behavior without changing the protected file.

Extraction material is **discovery-ready, not product-ready**: it identifies the Core → Project Adapter → ZEN boundary and concrete coupling, but confirms no package, installer, host configuration, migration, or executable adapter exists.

## Document disposition

| Disposition | Documents | Reason |
| --- | --- | --- |
| Updated | `docs/ralph/README.md`; `docs/README.md` | Current navigation distinguishes the maintained RALPH set from the historical protected guide. |
| Created | `docs/ralph/RECONCILIATION_SITREP.md` | Records reconciliation outcome, evidence, debt, and follow-up boundary. |
| Retained and clearly historical | `docs/RALPH-LITE.md` | It is a registered RALPH tooling path. No controller-derived, one-step self-hosting grant was active for this step, so it was not edited. |
| Current source of behavior | `docs/ralph/operator-reference.md`, `lifecycle.md`, `concepts.md`, `authority-validation-recovery.md`, `architecture.md`, `extraction/EXTRACTION_READINESS.md` | These describe the implemented CLI, persisted lifecycle vocabulary, authority boundaries, and current extraction limits. |
| Retired | None | No file was deleted or concealed; historical material remains explicitly labeled for auditability. |

## Legacy and supersession findings

`docs/RALPH-LITE.md` must not be used as the current lifecycle contract. Its rendered lifecycle presents `PROPOSED` and `RETIRED` as status outcomes, while the current lifecycle reference distinguishes `PLAN_COMPLETE` as a legacy proposal entry and `RETIRED` as an audited event returning to `IDLE`. It also describes the JSONL event stream as a future web-console source even though the repository includes the current local web console.

The maintained replacements are:

- command names, options, prerequisites, and recovery outcomes: [operator reference](operator-reference.md);
- persisted statuses and Mermaid lifecycle: [lifecycle](lifecycle.md);
- authority, evidence, repair, and final-qualification rules: [authority, validation, and recovery](authority-validation-recovery.md) and [concepts](concepts.md);
- current coupling and non-installability of a standalone RALPH: [extraction readiness](extraction/EXTRACTION_READINESS.md).

No Compose filename, deployment method, RouterOS status label, or legacy ZEN terminology is asserted as current RALPH behavior in this documentation route. RALPH is explicitly process infrastructure, not a component of the deployed ZEN stack.

## Validation record

The following repository-local checks were performed for this reconciliation:

- `python3 scripts/ralph.py status` identified the active approved plan and current step without changing controller-owned files.
- `python3 scripts/ralph.py --help` was compared with command names documented in the operator reference, including `retire-plan`, `authorize-self-hosting`, recovery, finalization, reconciliation, usage, and `serve`.
- Documented `python3 scripts/ralph.py` and `python3 scripts/ralph_gate.py` invocations were enumerated against repository command surfaces.
- Mermaid-bearing RALPH documents were identified for syntax review: `architecture.md` uses `flowchart LR`; `lifecycle.md` uses `stateDiagram-v2`; the extraction boundary is deliberately plain text rather than Mermaid.
- Relative links and documented repository paths are verified by the focused local documentation check recorded below.

The controller remains authoritative for final qualification. This SITREP is evidence of a focused local reconciliation, not a substitute for controller gates.

## Remaining debt and implementation discrepancies

1. **Protected-guide reconciliation:** update `docs/RALPH-LITE.md` only after the controller first creates the exact self-hosting authority block and an operator grants the controller-derived one-step path set for this approved step. Do not hand-edit or broaden that authority.
2. **Legacy-guide content:** when authorized, replace its lifecycle/status and web-console wording with maintained references rather than duplicating a second command contract.
3. **Extraction:** the documented Core → Project Adapter → ZEN boundary remains conceptual; package boundaries, configuration, migration, and host-neutral qualification are unimplemented.
4. **Maturity evidence:** this step validates repository documentation and CLI shape only. It does not supply runtime deployment, live RouterOS, browser, external-system, or operator evidence.

## Follow-up issue list

| Priority | Evidence-backed issue | Bounded next action |
| --- | --- | --- |
| High | The protected historical guide has stale lifecycle and console wording, but no self-hosting grant was active. | Obtain controller-created exact authority gate and explicit operator authorization, then reconcile only the registered path. |
| Medium | Current behavior is intentionally distributed across conceptual, lifecycle, authority, and command pages. | Keep the index as canonical route; consider a later approved consolidation after protected-guide authority is available. |
| Medium | Extraction documentation records no clean standalone installation. | Do not advertise portability; implement and test an adapter/configuration boundary in a separately approved plan. |
| Low | Mermaid validation is limited to repository-local syntax/form review. | Add a renderer-based documentation gate only in a separately approved tooling/test change. |
