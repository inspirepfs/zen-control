# RALPH-Lite concepts

## Purpose and authority

RALPH-Lite supervises repository changes toward a human-approved objective. A model may propose and implement; the deterministic controller decides whether work is authorized, qualified, recoverable, and ready for controlled publication. A model summary is evidence of neither correctness nor authority. RALPH is not a ZEN runtime component and has no RouterOS authority.

## Proposal and digest-bound approval

`propose` produces a structured, read-only plan. The controller validates it, calculates its SHA-256 digest, and persists plan plus digest in `AWAITING_APPROVAL`. `approve <PLAN_HASH>` succeeds only when the supplied hash, persisted hash, and rendered `.ralph/plan.md` agree. Approval applies to that exact plan, not a similar or edited one.

Approval creates and records a Git-backed recovery checkpoint before changing to `APPROVED`. It captures approval-time HEAD, branch/upstream, staged/dirty/untracked baseline, patches, and a private local Git ref. It is recovery evidence, not permission for autonomous destructive recovery.

## One step, qualification, and repair

Every model loop handles only the current approved step. The controller checks changed paths, protected/RALPH tooling authority, and test-change policy, then runs authoritative qualification. On PASS it records the step result and advances. On FAIL it records a failure fingerprint and retains the same step for repair. Repair is a `RUNNING` phase, not a separate status, and the same fingerprint has at most three repair attempts before human block.

After all steps pass, final qualification is run against the plan delta. Its PASS result is bound to a delta fingerprint before `READY_TO_COMMIT`; later changes require requalification.

## Gates, evidence, and completion

`BLOCKED_HUMAN` is a stop. A human may record bounded `steer` direction, `resume` a same-step retry, resolve only an explicitly delegated runtime/operator-evidence gate, or retire an obsolete plan. Steering cannot override protected paths or turn a policy failure into PASS.

Controller evidence includes the exact plan hash, checkpoint, state, journal, structured events, step history, human gate/steering record, qualification output/fingerprint, completion report, and recorded commit/push proof. Controller-owned `.ralph/` evidence is not editable model authority.

`READY_TO_COMMIT` means final qualification passed; it is not model publication authority. The controller may commit only the qualified plan delta, and may push only the configured upstream after divergence checks. It never force-pushes or invents a remote/branch. `PUSHED` proves Git publication only, not deployment, ZEN health, or RouterOS enforcement.
