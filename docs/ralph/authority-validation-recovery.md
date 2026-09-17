# RALPH authority, validation, and recovery

RALPH-Lite is a supervised repository-change controller. Its durable record is important, but no record by itself grants a model authority to make changes, accept work, or publish it. This page explains the boundaries operators use when reviewing a run or recovering one safely.

## Four things that must not be conflated

| Thing | What it is | What it is not |
| --- | --- | --- |
| Stored intent | The persisted rendered plan, its SHA-256, step/acceptance data, and separately recorded bounded steering. | Execution permission. Steering does not change the approved plan or its hash. |
| Stored evidence | Controller state, journal, events, gate output/durations, failure fingerprints, checkpoint data, reports, usage ledger, and Git proof. | A model claim, an editable shortcut to PASS, or proof of deployment/runtime health. |
| Stored approval | A human approval of the supplied hash after the controller confirms that supplied hash, persisted hash, and rendered plan agree. It also has a recorded recovery checkpoint. | Approval of an edited, similar, truncated, reformatted, or stale plan. |
| Executable authority | The controller's current state plus policy checks that permit exactly the current approved step to be run, qualified, and—after final qualification—guardedly finalized. | General model, operator, web-console, RouterOS, deployment, secret, or force-push authority. |

The deterministic controller is the only component that converts a model turn and its evidence into an accepted step. Controller-owned `.ralph/` records are audit evidence, not files an implementation worker may edit to advance state.

## Decision boundaries

| Area | May act or decide | Boundary |
| --- | --- | --- |
| Planning | The model may propose a read-only structured 5–10 step plan; the controller validates and persists it. | A proposal stays in `AWAITING_APPROVAL`; it cannot run. A human must approve its exact digest. |
| Approval | A human approves the exact presented plan hash; the controller verifies all three hash/rendered-plan values and creates the checkpoint. | A mismatch, changed file, or stale/incorrect hash is rejected. Regenerate and review a new proposal rather than editing an active plan. |
| Execution | The model can implement exactly one currently approved step in the workspace. | The controller snapshots/restores protected authority, enforces changed-path and test policy, and does not let a turn select another step or accept itself. |
| Repair | The controller retains the failed current step and failure fingerprint for a same-step repair. | The same fingerprint has at most three repair attempts. There is no skip, test/gate weakening, or repair-limit override. |
| Validation | The controller runs authoritative step gates and, after all steps, independent final qualification over the plan delta. | A passing model summary, browser output, or human assertion cannot substitute for a required controller gate. Final PASS is bound to a delta fingerprint. |
| Review and finalization | A human may review report/evidence; the controller may requalify, commit the qualified paths, and push only the configured safe upstream. | `READY_TO_COMMIT` is not publication authority. Delta change requires requalification; there is no force-push, invented remote, deployment, health, or RouterOS claim. |
| External systems | Operators provide only explicitly delegated runtime/operator evidence. | Autonomous RALPH never accesses live RouterOS, production systems, secret stores, credentials, or `.env*` data. Git publication is repository evidence, not production action. |
| Human gate | A human may give recorded bounded steering, resume after fixing a block, retire an obsolete plan, or use `resolve-gate` for an explicitly delegated current gate. | Human action cannot turn a policy/repair/plan-integrity failure into PASS or broaden protected-path authority. |

The web console is an operator surface only: its state-changing actions invoke the CLI and its local job/log files have no independent controller authority.

## Qualification, review, and budgets

For every model loop, the controller records the step, phase, files, result, gates, timing, repair number, failure fingerprint, and next action in the journal; live text and structured events provide the same operational trail. The controller first checks plan integrity and policy (including protected paths, RALPH tooling authority, and test-change policy), then runs its authoritative gates. A failed step stays on the same approved step for repair.

After each step is accepted, the controller clears one-step self-hosting context and advances to the next approved step. When all steps are accepted, final qualification records its gate output, durations, completion time, and the exact plan-delta fingerprint. Only that result produces `READY_TO_COMMIT`; `requalify` is required if that delta is no longer current.

Some gates require human action but remain bounded:

- `resolve-gate` records `HUMAN_CONFIRMED` and advances only for the exact current gate that the approved step explicitly delegated to an operator/human. It cannot resolve policy, authority, repair, or plan-file blocks.
- `steer` records direction and retries the same step. A narrow new-test grant can name only the exact gated new `tests/` path; it never authorizes an existing test or protected/tooling path.
- A RALPH tooling edit is restored and blocked unless `authorize-self-hosting` grants the controller-derived exact registered path set for the current gate and step. The grant is one-step, is audited, and never includes `.ralph/` or protected paths.

Budgets are safeguards, not success criteria. The controller uses a maximum of three repairs for the same failure fingerprint and preserves an operator usage reserve before another model turn. It also records focused-turn metrics (including commands, input, and reported files) and may emit an efficiency advisory after a qualified step, pausing before the next turn. A loop limit likewise pauses cleanly with the plan still approved. Neither pause accepts unfinished work, and neither permits bypassing qualification.

## Recovery playbook

Start with the authoritative state and evidence, not a manual edit:

```bash
python3 scripts/ralph.py status
python3 scripts/ralph.py checkpoints
python3 scripts/ralph.py checkpoint-info <CHECKPOINT_ID>
```

| Situation | Safe recovery action | Do not do |
| --- | --- | --- |
| Invalid, unapproved, changed, or stale plan | Do not run it. Reject/regenerate the pending proposal, or review/replan an active plan that is blocked for integrity. | Edit `.ralph/plan.md`, state, or digest to make values agree. |
| Step gate fails | Inspect journal/gate output and let the controller repair the same step within its current failure budget. | Advance, skip the gate, or weaken tests. |
| Environment block | Repair the local environment, then run `resume <PLAN_HASH> --reason "..."` for the same step. | Call the environment failure PASS or resolve it as a human evidence gate. |
| Interrupted CLI/browser run | Inspect `status`, journal/events, and web job/log metadata if applicable; rerun the authoritative CLI when the recorded status permits. | Infer success from a disappeared browser/job or alter web metadata. |
| Usage reserve, loop, or efficiency pause | Restore available capacity or review the advisory, then run the controller again from its recorded approved state. | Spend through the reserve or treat a pause as a completed step. |
| Same failure exhausts three repairs | `BLOCKED_HUMAN` is intentional. Review the fingerprint, evidence, and whether bounded steering, a corrected environment, replan, or retirement is appropriate. | Reset repair accounting, repeatedly resume without addressing the failure, or claim a fourth autonomous repair. |
| Explicit delegated operator/runtime gate | Supply the actual bounded evidence with `resolve-gate <PLAN_HASH> --gate <HG-ID> --reason "..."`. | Use it for policy, test, authority, or validation failures. |
| Validation-only historical block | Where the controller classifies it as eligible, use `recover-validation-block <PLAN_HASH>` to rerun qualification without Codex. | Use this recovery path for scope, policy, integrity, or environment blocks. |
| Corrupt/missing state or checkpoint evidence | Preserve what remains, inspect the checkpoint/ref and Git worktree, and obtain human recovery direction; recreate a plan if audit continuity cannot be proved. | Hand-edit controller state, delete/prune active evidence, or perform an autonomous destructive rollback. |
| Partial work or repository inconsistency | Compare changed paths with approval baseline/checkpoint and review diffs. Repair only the same approved step when scope/policy remain valid; otherwise human-review/replan or retire. | Fold unrelated dirty work into the plan or overwrite approval-time user changes. |
| Finalization refuses a dirty overlap, stale delta, or manual Git outcome | Requalify the exact delta; for a human-reviewed qualified manual commit/push, use `reconcile-commit` and then `reconcile-push` only after their strict proof checks. | Claim `COMMITTED`/`PUSHED` by changing state or force-push. |

Recovery checkpoints hold approval-time Git identity, branch/upstream, dirty/staged/untracked baselines, patches, and a private local recovery ref. They are recovery anchors and audit evidence, not permission for automated destructive restore. Destructive recovery, loss of required evidence, policy relaxation, and judgements outside the approved plan remain human decisions.

## Observability checklist

Use the durable record to answer “what happened?” before taking action:

- `status` for state, current step, hash, block reason, qualification, and publication fields (it can initialize missing runtime artifacts);
- `.ralph/journal.md`, `.ralph/live.log`, and `.ralph/events.jsonl` for loop, gate, human-gate, and operational chronology;
- `.ralph/state.json` for controller-owned state, repair context, evidence, and approvals—read it, never hand-edit it;
- `.ralph/usage-ledger.jsonl` and `usage --details` for recorded per-turn and available usage context; and
- completion reports plus checkpoint manifests and Git refs for accepted-step, qualification, recovery, commit, and push evidence.

These records establish controller decisions and repository publication facts. They do not prove a deployment, external-system outcome, or runtime health.
