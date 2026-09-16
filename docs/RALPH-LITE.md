# RALPH-Lite Operator Guide

RALPH-Lite is ZEN Control's supervised autonomous engineering loop. It turns a bounded human-approved objective into a sequence of implementation steps, validates every step with controller-owned gates, preserves authority boundaries, records evidence, and can finish with a reviewed commit and push.

The model proposes and implements. The controller owns policy, qualification, recovery, Git publication, and the human gates.

## Design rules

RALPH-Lite follows these rules:

- Human approval is required before implementation begins.
- A Git-backed recovery checkpoint is created before the first model turn of an approved plan.
- The approved plan is immutable during execution.
- Protected files, secrets, RALPH tooling authority and test-change policy are enforced by the controller, not by the model.
- Tests and controller qualification are authoritative. Model claims do not convert missing evidence into PASS.
- Human gates are explicit. Policy gates cannot silently broaden authority.
- `steer` records bounded human direction; it is not a generic policy bypass.
- Existing tests remain protected when a step is `add-only`; tests created by the approved plan may be refined by later retries of the same plan.
- Git commit/push is controller-owned. Codex never receives arbitrary publication authority.
- No force-push path exists.
- Missing live/operator evidence stays missing or PENDING.

## Lifecycle

```text
IDLE
  ↓
PROPOSED / AWAITING_APPROVAL
  ↓ approve
APPROVED
  ↓
RECOVERY CHECKPOINT
  ↓
RUNNING
  ├─ PASS → next approved step
  ├─ FAIL → bounded repair of same step
  ├─ BLOCKED_HUMAN → review / steer / resolve / resume / retire
  ├─ BLOCKED_ENVIRONMENT → repair environment / resume
  └─ PAUSED_USAGE_LIMIT → zero-model usage wait / resume
  ↓
FINAL QUALIFICATION
  ↓
READY_TO_COMMIT
  ├─ finalize --commit → COMMITTED
  ├─ manual qualified commit → reconcile-commit → COMMITTED
  ↓
finalize --push or external push
  ↓
PUSHED / reconcile-push
```

`RETIRED` is an auditable terminal outcome for an obsolete active plan. It does not mean the plan passed.

## Operator cookbook

### Start a new bounded job

```bash
python3 scripts/ralph.py propose \
  --goal "<bounded ZEN objective>"
```

Review `.ralph/plan.md`, then approve using the exact plan hash:

```bash
python3 scripts/ralph.py approve <PLAN_HASH>
```

Approval creates the recovery checkpoint before implementation authority is granted.

Run:

```bash
python3 scripts/ralph.py run --color auto
```

### Check status

```bash
python3 scripts/ralph.py status
python3 scripts/ralph.py usage --details
```

### Review a human gate

```bash
python3 scripts/ralph_gate.py --view review --details
```

Machine-readable form:

```bash
python3 scripts/ralph_gate.py --json
```

### Give bounded human direction

Use `steer` when the objective remains valid but the agent needs human direction within the approved authority envelope:

```bash
python3 scripts/ralph.py steer <PLAN_HASH> \
  --gate <GATE_ID> \
  --direction "<bounded direction>"
```

For a policy gate involving one exact new test path, a human can grant only that exact path:

```bash
python3 scripts/ralph.py steer <PLAN_HASH> \
  --gate <GATE_ID> \
  --direction "This exact regression test is required by the approved objective." \
  --allow-new-test tests/test_exact_regression.py
```

`--allow-new-test` is deliberately narrow:

- the path must be under `tests/`;
- the path must be named by the current gate;
- the path must not have existed at approval;
- protected/tooling paths can never be authorised this way.

### Retry a blocked step

`resume` retries the same approved step. It does not accept the step or advance it.

```bash
python3 scripts/ralph.py resume <PLAN_HASH> \
  --reason "<human reason for retry>"
```

### Resolve an explicitly delegated human/operator gate

`resolve-gate` is only for a gate the approved step explicitly delegated to human/operator evidence. It cannot override policy or controller authority.

```bash
python3 scripts/ralph.py resolve-gate <PLAN_HASH> \
  --gate <GATE_ID> \
  --reason "<evidence satisfying the gate>"
```

### Retire an obsolete active plan

```bash
python3 scripts/ralph.py retire-plan <PLAN_HASH> \
  --reason "<why this approved plan is now obsolete>"
```

Retirement preserves the audit history and returns the controller to `IDLE` without invoking Codex.

## Recovery checkpoints

Approval creates a checkpoint under:

```text
.ralph/recovery/RP-YYYYMMDD-HHMMSS-<plan>/
```

It includes:

- approval-time HEAD;
- current branch and configured upstream;
- baseline dirty paths;
- baseline untracked paths;
- baseline staged paths;
- tracked working patch;
- staged patch;
- a private local Git reference under `refs/ralph/recovery/`.

List checkpoints:

```bash
python3 scripts/ralph.py checkpoints
```

Inspect one:

```bash
python3 scripts/ralph.py checkpoint-info <CHECKPOINT_ID>
```

The checkpoint is evidence and a recovery anchor. Destructive recovery remains a human operation.

## Approval-time file ownership

RALPH distinguishes file origin at the plan approval boundary.

| Origin | Meaning |
|---|---|
| tracked | existed in approval-time HEAD |
| preexisting-dirty | tracked path already modified at approval |
| preexisting-untracked | untracked user/operator file already present at approval |
| absent | path did not exist at approval |
| plan-owned | absent at approval and subsequently created by this approved plan |

This matters for `add-only` test policy. A regression test created by the approved plan may be refined during a later repair/retry loop. A test that existed before approval remains protected.

## TUI

RALPH-Lite uses a dependency-free ANSI TUI. Colour is enabled automatically for a terminal.

```bash
python3 scripts/ralph.py run --color auto
python3 scripts/ralph.py run --color always
python3 scripts/ralph.py run --color never
```

`NO_COLOR=1` always disables ANSI colour.

### Colour/event legend

| Event | Meaning |
|---|---|
| READ | file/content inspected |
| CREATE | new file created |
| EDIT | existing/plan-owned file changed |
| DELETE | file deleted |
| MOVE | file renamed/moved |
| RUN / COMMAND | command execution |
| THINK | bounded reasoning summary |
| TEST / VALIDATE | qualification activity |
| PASS / COMPLETE / READY | successful controller state |
| WARN / POLICY | review required |
| FAIL / ERROR | failed validation/action |
| HUMAN / BLOCKED | explicit human intervention required |
| CHECKPOINT | recovery point created |

The live console contains:

- current plan/step/loop/phase;
- repair number;
- quota and efficiency status;
- recovery checkpoint;
- approved test authority;
- plan progress;
- bounded acceptance context;
- file actions;
- per-loop diffstat;
- changed Python symbols where deterministically available;
- bounded syntax-coloured unified diff preview;
- implementation summary;
- gate result and token counts.

The durable `.ralph/live.log` remains plain text. Structured events are also written to:

```text
.ralph/events.jsonl
```

The JSONL stream is the intended future source for a local web console.

## Policy review

Policy gates should be reviewed rather than blindly resumed.

The policy card shows:

- current gate and step;
- approved test policy;
- requested test/protected paths;
- approval-baseline origin of each path;
- approved acceptance criteria;
- recommended operator action;
- an exact `steer` command shape.

Typical responses:

- **plan-created test under `add-only`:** continue within existing authority;
- **pre-existing test under `add-only`:** replan or keep the existing test unchanged;
- **protected/RALPH tooling path:** do not override; remove/replan the change;
- **valid objective but missing human context:** `steer` bounded direction;
- **runtime/operator evidence explicitly delegated:** `resolve-gate`.

## Final qualification

After all approved implementation steps are accepted, the controller runs final qualification. Available gates include:

- Python compile;
- full unit/regression suite;
- UX validation;
- environment validation when present;
- supply-chain validation when present;
- public-release audit when present;
- `git diff --check`.

A plan becomes `READY_TO_COMMIT` only when final qualification passes.

## Completion reports

RALPH writes:

```text
.ralph/reports/<plan-prefix>-summary.md
.ralph/reports/<plan-prefix>-summary.json
```

The report includes:

- plan goal/hash;
- accepted-step breakdown;
- direct PASS vs HUMAN_CONFIRMED;
- repaired/recovered steps;
- loop count;
- human gates and steering decisions;
- final qualification gates;
- changed files and line counts;
- changed symbols;
- protected/tooling boundary status;
- plan-owned files;
- recovery checkpoint/reference;
- usage/token totals;
- suggested commit subject;
- recorded/reconciled commit and push state.

Regenerate/review:

```bash
python3 scripts/ralph.py report <PLAN_HASH>
python3 scripts/ralph.py finalize <PLAN_HASH>
```

## Automated commit

When the plan started from an unambiguous baseline:

```bash
python3 scripts/ralph.py finalize <PLAN_HASH> --commit
```

Optional subject override:

```bash
python3 scripts/ralph.py finalize <PLAN_HASH> --commit \
  --message "feat(analytics): improve service evidence"
```

RALPH refuses automated commit when, among other safeguards:

- final qualification is not PASS;
- approval-time staged work existed;
- a plan path was already dirty at approval;
- unexpected working-tree paths appeared;
- protected/RALPH tooling paths are part of the product plan delta;
- a recorded plan path disappeared;
- `git diff --check` fails;
- the public-release audit fails.

This refusal is intentional. Ralph does not guess ownership of overlapping edits.

## Dirty-overlap / migration closure

If a qualified plan overlaps files that were already dirty when its recovery checkpoint was created, perform a human-reviewed manual commit first. Then reconcile it into the plan state.

```bash
python3 scripts/ralph.py reconcile-commit <PLAN_HASH> \
  --commit <COMMIT_SHA> \
  --reason "Manual closure after reviewed dirty-overlap/migration state"
```

`reconcile-commit` verifies:

- current plan is `READY_TO_COMMIT`;
- final qualification is PASS;
- commit exists and is reachable from current HEAD;
- every recorded plan path is present in that commit;
- the plan itself does not include protected/RALPH tooling paths;
- extra commit paths are limited to files already known in the approval-time baseline.

It then records `COMMITTED` without creating or rewriting a commit.

This is intended for exceptional migration/overlap closure, not the normal path.

## Push

Normal controller-owned push:

```bash
python3 scripts/ralph.py finalize <PLAN_HASH> --push
```

Requirements include:

- state is `COMMITTED`;
- current branch is attached;
- a configured upstream exists;
- upstream can be fetched;
- upstream is not ahead/diverged;
- there is something to push.

RALPH uses the configured upstream only. There is no force-push option.

If a human or external process already pushed the reconciled commit, adopt that state with:

```bash
python3 scripts/ralph.py reconcile-push <PLAN_HASH>
```

`reconcile-push` fetches the configured remote and marks `PUSHED` only when the exact recorded commit is an ancestor of the configured upstream.

## Git authority boundary

Codex implementation turns do not receive publication authority. Git commit/push is performed by deterministic controller code after controller-owned validation.

RALPH never:

- force pushes;
- invents a remote/branch for publication;
- rewrites history to make a run look clean;
- treats an unverified external commit as its own;
- silently absorbs pre-existing staged or dirty work.

## Usage / context efficiency

```bash
python3 scripts/ralph.py usage
python3 scripts/ralph.py usage --details
python3 scripts/ralph.py usage --json
```

RALPH preserves a configured quota reserve and can pause without another model turn when backend limits say execution should stop.

The development loop uses bounded/delta-oriented context rather than repeatedly ingesting the entire repository.

## Files

| Path | Purpose |
|---|---|
| `scripts/ralph.py` | deterministic supervisor/state machine |
| `scripts/ralph_gate.py` | read-only human-gate review surface |
| `scripts/ralph_tui.py` | dependency-free terminal renderer |
| `scripts/ralph_web.py` | loopback-only local operator web console |
| `.ralph/policy.md` | controller policy contract |
| `.ralph/plan.md` | current immutable approved/proposed plan |
| `.ralph/state.json` | controller state |
| `.ralph/context.json` | compact accepted implementation context |
| `.ralph/journal.md` | durable loop/human decision journal |
| `.ralph/live.log` | plain-text live trace |
| `.ralph/events.jsonl` | structured event stream |
| `.ralph/ideas.md` | out-of-scope ideas bucket |
| `.ralph/recovery/` | approval-time recovery checkpoints |
| `.ralph/reports/` | completion reports |

Runtime `.ralph/` state is local operational evidence and should not be treated as product source.

## Troubleshooting

### `BLOCKED_HUMAN policy violation`

Review first:

```bash
python3 scripts/ralph_gate.py --view review --details
```

Do not use `resolve-gate` for a policy/authority violation. Use bounded `steer`, retry within existing authority, or retire/replan.

### New `add-only` test is blocked on retry

Current versions classify test ownership from the approval checkpoint. A genuinely plan-created test should remain editable. If the card says it existed before approval, do not override it without reviewing the checkpoint.

### `finalize --commit` refuses dirty overlap

This is a safety result, not a failed implementation. Review the listed overlaps. If the product change is already manually committed after review, use `reconcile-commit`.

### Commit was pushed manually

After `reconcile-commit`:

```bash
python3 scripts/ralph.py reconcile-push <PLAN_HASH>
```

### Plan is obsolete

Use `retire-plan`. Do not edit `.ralph/state.json` to make a plan disappear.

### Final qualification fails

Treat it as a real release/engineering failure. Do not manufacture a PASS or weaken thresholds merely to leave `READY_TO_COMMIT`.

## Local web console

RALPH-Lite v0.3.0 adds a zero-dependency local web console on top of the same controller state and structured event stream used by the TUI. It is an operator surface, **not** a second state machine. Every state-changing action invokes the existing `scripts/ralph.py` command path and therefore retains the same plan hashes, authority checks, test policy, recovery checkpoints, human gates and Git publication guards.

Start it with:

```bash
python3 scripts/ralph.py serve
```

Default address:

```text
http://127.0.0.1:8765/
```

An alternate loopback port is allowed:

```bash
python3 scripts/ralph.py serve --port 8877
```

Loopback remains the default. For a trusted home-lab LAN, v0.3.1 supports an explicit private-LAN mode bound to one specific RFC1918/ULA address. Wildcard binds such as `0.0.0.0`/`::` and public addresses remain refused.

Example:

```bash
python3 scripts/ralph.py serve --host 192.168.2.10 --allow-lan
```

LAN mode generates a fresh browser access token on every server start and prints a URL such as:

```text
http://192.168.2.10:8765/#<access-token>
```

The token is carried in the browser URL fragment, removed from the visible address bar after page load, and sent to Ralph only in the `X-RALPH-AUTH` request header. API reads and all state-changing actions require that token in LAN mode, while writes continue to require the independent per-process CSRF token as well. Host-header validation permits only the exact configured bind IP, limiting DNS-rebinding exposure.

LAN mode is intended for a trusted private home-lab network. It is not an Internet exposure mode and does not enable wildcard/public binds.

### Web console views

The dashboard shows:

- controller state, active plan hash, current step and loop count;
- Codex quota headroom and last context-efficiency result;
- Git branch/upstream/dirty state;
- approval-time recovery checkpoint;
- full plan progress and per-step test authority;
- current human gate/block reason;
- plan-owned/changed files;
- the structured `.ralph/events.jsonl` activity stream;
- bounded controller output;
- the current completion-report preview when available.

The browser polls local state; it does not ask Codex another question merely to refresh the display.

### Web actions

The console exposes the normal supervised lifecycle where the current controller state makes the action meaningful:

- propose a new bounded goal;
- approve or reject a proposal;
- start the approved run;
- steer, resume or resolve an open human gate;
- retire an obsolete plan;
- review finalization;
- commit a qualified plan;
- push the committed plan.

Exceptional commit/push reconciliation remains available through the CLI. The browser intentionally keeps the routine happy path prominent and does not turn every recovery mechanism into a one-click action.

### Web control safety

The local server:

- binds to loopback only;
- generates a new in-memory CSRF token on every server start;
- requires the CSRF token on all state-changing HTTP requests;
- exposes no CORS permission for external origins;
- applies no policy bypass or force-push surface;
- requires explicit text confirmation before retire, commit and push operations;
- permits only one background Ralph job at a time;
- writes background runner output to local ignored `.ralph/web-run.log`;
- writes local runner metadata to ignored `.ralph/web-job.json`.

The existing CLI remains the authoritative recovery surface if a browser session disappears or a web action is interrupted.

### Background run semantics

`propose` and `run` can take long enough that the browser request should not remain open. The console therefore starts those commands as a single local background Ralph job and continues rendering progress from the event/state files. A second background run is refused while the first process is alive.

The web process itself does not own or infer plan completion. `scripts/ralph.py` continues to update the same durable controller state.
