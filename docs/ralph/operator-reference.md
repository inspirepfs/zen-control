# RALPH-Lite operator reference

This reference is the parser contract for `python3 scripts/ralph.py`. Run it
from the repository root. It operates on local Git and `.ralph/` evidence; it
does not contact RouterOS. `<PLAN_HASH>`, `<CHECKPOINT_ID>`, and `<COMMIT_SHA>`
are values printed by RALPH, never credentials. Do not put passwords, tokens,
or router addresses on command lines. Parser, state, authority, or local I/O
errors return non-zero: inspect `status` and local gate evidence rather than
editing controller files.

## Exact-plan approval

`propose` validates a structured plan, computes canonical SHA-256, persists the
plan and digest in `state.json`, and writes the canonical rendering to
`.ralph/plan.md`. `approve <PLAN_HASH>` accepts only when the supplied digest,
persisted `plan_hash`, and exact `plan.md` bytes (compared with the controller
rendering) all agree. It creates the Git-backed checkpoint before status becomes
`APPROVED`.

An edited, truncated, reformatted, stale, or otherwise changed plan file is
rejected. Pending approval says the proposal must be regenerated; an approved
plan is blocked for human review when `run` detects a change. An old/mistyped
digest is a hash mismatch. Preserve evidence and create a reviewed new proposal
(or reject the pending one); never rewrite `plan.md` or `state.json` by hand to
make a hash agree.

## Command contracts

All examples are local and placeholder-only. **Codex** can consume model usage;
**Git** can mutate local Git/the configured upstream. Each failure column gives
the safe recovery; in all cases start by checking `python3 scripts/ralph.py status`.

| Syntax | Prerequisite / state | Effect and persistence | Failure and recovery | Safe example |
|---|---|---|---|---|
| `init` | Tracked `.ralph/policy.md`; any state. | Creates missing runtime dirs/files, default state/context, empty ledgers; no plan authority. | Missing policy/filesystem error: restore policy through reviewed source control, retry. | `python3 scripts/ralph.py init` |
| `propose --goal "..."` **Codex** | `IDLE`, `PLAN_COMPLETE`, or `PUSHED`; Codex available. | Persists validated plan/digest, canonical `plan.md`, reset accounting; appends planning usage; `AWAITING_APPROVAL`. | Invalid proposal/Codex failure grants no authority. Fix environment or resolve active plan, then propose. | `python3 scripts/ralph.py propose --goal "Document a bounded objective"` |
| `approve <PLAN_HASH>` | `AWAITING_APPROVAL`, exact digest/persisted plan/unchanged canonical file; human review. | Creates recovery directory/private Git ref; records checkpoint/baseline; `APPROVED`. | Hash/file/checkpoint failure refuses approval. Retain evidence and regenerate reviewed proposal. | `python3 scripts/ralph.py approve <PLAN_HASH>` |
| `reject <PLAN_HASH> --reason "..."` | Pending exact hash and non-empty reason. | Audits rejection, restores prior eligible state or `IDLE`; no authority/checkpoint. | Wrong hash/state/reason: use printed digest/factual reason, then propose anew. | `python3 scripts/ralph.py reject <PLAN_HASH> --reason "Scope needs revision"` |
| `retire-plan <PLAN_HASH> --reason "..."` | Exact active approved, paused, or blocked plan; non-empty human reason. | Audits `RETIRED`, clears active authority, returns `IDLE`. | Wrong hash/inactive: this is not PASS/rollback; use checkpoint for human recovery, then replan. | `python3 scripts/ralph.py retire-plan <PLAN_HASH> --reason "Objective superseded"` |
| `run [--max-loops N] [--wait-for-limits\|--no-wait-for-limits] [--usage-poll-seconds N] [--color auto\|always\|never]` **Codex** | `APPROVED`, unchanged plan/checkpoint; `N >= 1`, poll >=15 sec. | Executes approved steps/qualification; records state, journal, events, context, usage, changes; may pause/block/remain approved/reach `READY_TO_COMMIT`. | Plan change blocks review; policy/repair gates cannot be bypassed. Wait for usage or use matching retry/retire action. | `python3 scripts/ralph.py run --max-loops 1 --color never` |
| `steer <PLAN_HASH> --gate <HG-ID> --direction "..." [--allow-new-test tests/path]` | Exact active blocked plan/current gate; within approved step. Test paths authorize exact new tests only. | Audits/persists direction/context, clears self-host grant, retries same step. | Gate/hash/path authority error: cannot override policy/protected paths; replan or retire. | `python3 scripts/ralph.py steer <PLAN_HASH> --gate <HG-ID> --direction "Keep the existing API"` |
| `authorize-self-hosting <PLAN_HASH> --gate <HG-ID> --path <PATH> [--path <PATH> ...] --reason "..."` | Exact authority-block gate/current same-plan-step tooling candidate; registered paths only, never `.ralph/`. | Persists narrow one-step tooling grant/audit; edits nothing. | Stale candidate/path/hash/gate error: get scoped human authority or replan, never widen manually. | `python3 scripts/ralph.py authorize-self-hosting <PLAN_HASH> --gate <HG-ID> --path scripts/ralph.py --reason "Approved correction"` |
| `resume <PLAN_HASH> --reason "..."` | Exact active blocked approved step; non-empty reason. | Audits reason, clears self-host context, retries same step. | Wrong state/hash/reason: fix stated problem; it does not cure policy/environment failure. | `python3 scripts/ralph.py resume <PLAN_HASH> --reason "Local dependency restored"` |
| `resolve-gate <PLAN_HASH> --gate <HG-ID> --reason "..."` | `BLOCKED_HUMAN`, exact gate/hash, no active implementation failure, explicit approved runtime/operator delegation. | Records evidence/context and `HUMAN_CONFIRMED`; advances without Codex. | Policy/authority/repair/plan-file blocks reject it. Supply delegated evidence or resume/steer/retire. | `python3 scripts/ralph.py resolve-gate <PLAN_HASH> --gate <HG-ID> --reason "Approved operator evidence recorded"` |
| `recover-validation-block <PLAN_HASH>` | Exact unchanged plan, validation-only current-step block, product-development changes only. | Re-runs qualification without Codex; advances on PASS or records new fingerprint. | Non-validation/policy/scope/hash failure: normal repair/human action; never bypass gate. | `python3 scripts/ralph.py recover-validation-block <PLAN_HASH>` |
| `checkpoints` | Local repo; any state. | Initializes missing runtime files; prints up to 30 manifest summaries. | Corrupt manifest may fail listing. Preserve evidence; no automatic destructive restore. | `python3 scripts/ralph.py checkpoints` |
| `checkpoint-info <CHECKPOINT_ID>` | Readable existing manifest. | Prints manifest only; no state write. | Unknown/corrupt ID: get ID from `checkpoints`; lost evidence is human recovery. | `python3 scripts/ralph.py checkpoint-info <CHECKPOINT_ID>` |
| `report <PLAN_HASH>` | Exact current hash. | Regenerates completion Markdown/JSON from state/qualification evidence. | Wrong hash/incomplete evidence: repair/requalify evidence, then regenerate. | `python3 scripts/ralph.py report <PLAN_HASH>` |
| `requalify <PLAN_HASH>` | Exact hash and `READY_TO_COMMIT`. | Runs final qualification, binds fresh delta fingerprint/output/durations on PASS; updates report. | Failure becomes `BLOCKED_HUMAN`; repair/review and regain qualification, never commit stale result. | `python3 scripts/ralph.py requalify <PLAN_HASH>` |
| `finalize <PLAN_HASH> [--commit\|--push] [--message "subject"]` **Git** | Exact hash. Review: `READY_TO_COMMIT`/`COMMITTED`/`PUSHED`; commit: `READY_TO_COMMIT`; push: `COMMITTED`, safe configured upstream. | Default renders review/report. Commit stages exactly qualified paths, commits and records `COMMITTED`; push guards/upstreams then records `PUSHED`. | Refuses missing checkpoint, dirty/staged overlap, unexpected/protected paths, stale fingerprint, audit/upstream failures. Requalify or reconcile after human review; never force-push. | `python3 scripts/ralph.py finalize <PLAN_HASH>` |
| `reconcile-commit <PLAN_HASH> --commit <COMMIT_SHA> --reason "..."` **Git** | Exact hash/reason and manually made commit strictly proved qualified delta. | Records verified SHA, reconciliation reason/time, `COMMITTED`, journal, report. | Unqualified/unexpected commit: correct it or return to human publication review; never assert state manually. | `python3 scripts/ralph.py reconcile-commit <PLAN_HASH> --commit <COMMIT_SHA> --reason "Manual commit reviewed"` |
| `reconcile-push <PLAN_HASH>` **Git** | Exact hash, `COMMITTED`/`PUSHED`, recorded SHA, upstream/fetch/proof SHA is upstream ancestor. | Records reconciled `PUSHED`; does not push. | Missing SHA/upstream/proof: establish safe upstream or use guarded push; do not claim publication. | `python3 scripts/ralph.py reconcile-push <PLAN_HASH>` |
| `usage [--details] [--json] [--no-save]` | Local state; live usage backend optional; `--no-save` is read-only refresh support. | Reads ledger/context, queries limits; successful normal query caches state; details/json alter output. | Neither live nor cached limits returns 2. Retry/inspect cache; unavailable usage is not quota permission. | `python3 scripts/ralph.py usage --details` |
| `models [--json]` **Codex** | Authenticated Codex app-server available. | Reads the current model catalog plus configured/project-selected model; no selection is changed. | Catalog failure is read-only; restore Codex access and retry. | `python3 scripts/ralph.py models --json` |
| `model-policy show|set|reset|set-effort|reset-effort` **Codex for validation** | Project-local policy; model/effort selections are validated against the authenticated current model catalog where available. | Atomically stores RALPH's project model and reasoning-effort overrides in `.ralph/model-policy.json`; reset actions return the corresponding field to the user Codex default. Live changes affect the next model process/turn, never an already-running turn. | Unknown model/unsupported effort/catalog failure leaves the prior valid selection intact. | `python3 scripts/ralph.py model-policy set-effort --effort high` |
| `redeem-reset [--credit-id ID] --confirm REDEEM [--json]` **Codex account action** | A banked reset is available and the operator explicitly confirmed redemption. | Calls the supported authenticated reset-credit consume operation with a fresh idempotency key; never auto-redeems. | `noCredit`, `nothingToReset`, and `alreadyRedeemed` are reported without inventing quota. Re-read usage before further work. | `python3 scripts/ralph.py redeem-reset --confirm REDEEM --json` |
| `usage-reset-stats --confirm RESET [--json]` | Local usage ledger may exist. | Moves the local reporting baseline forward; preserves the ledger and does **not** reset/redeem provider quota. | Missing/corrupt marker is local reporting state only; live provider limits remain authoritative. | `python3 scripts/ralph.py usage-reset-stats --confirm RESET` |
| `serve [--host ADDR] [--port N] [--allow-lan] [--username NAME] [--password-file FILE] [--session-hours N] [--usage-refresh-seconds N]` | Local operator use; loopback default. LAN needs explicit private bind/auth; refresh >=15, session >0. | Starts local web UI; actions call guarded CLI and write job/log evidence. | Unsafe bind/missing LAN auth/invalid limits: use CLI status/recovery, never edit web files; keep passwords out of history. | `python3 scripts/ralph.py serve --host 127.0.0.1 --port 8765` |
| `status` | Any state. | Prints plan/status/step/loop/gate/block/efficiency/quota; normal use is read-only, though first use may bootstrap missing runtime files. | Corrupt state: preserve it and obtain human recovery; never invent fields. | `python3 scripts/ralph.py status` |

## Durable `.ralph/` artifacts

`.gitignore` ignores `.ralph/*` except tracked `.ralph/policy.md`. Runtime
evidence is local operational data, not product source or normal commit input.
`init_files` creates missing runtime artifacts; bootstrap is not permission to
overwrite active evidence. Copy evidence to protected local support storage
before human-directed recovery.

| Artifact | Writer / reader | Lifecycle, source control, regeneration | Corruption or deletion |
|---|---|---|---|
| `policy.md` | Tracked policy; every CLI initialization/workers read it. | Source-controlled authority contract; must exist. | Never edit/delete during approved work; restore only reviewed source control. |
| `state.json` | `ralph.py` atomic writer; CLI/TUI/gate/web/reports read. | Ignored authoritative state; `init` creates default only if absent. | Do not hand-edit/delete/promote `.tmp`; preserve copy and seek human recovery. |
| `efficiency-policy.json` | `ralph.py efficiency-policy` atomic writer; active controller and web console read live. | Ignored live resource-policy state, deliberately separate from `state.json`; `init` creates safe defaults. | Do not hand-edit while active. Use web controls or `efficiency-policy` CLI; invalid values are rejected and writes are atomic. |
| `model-policy.json` | `ralph.py model-policy` atomic writer; model launcher/web read before new model processes. | Ignored project-local model and reasoning-effort overrides; absence/`null` for either field means use the user's corresponding Codex configured default. | Do not hand-edit during active work; use the model/effort pickers or CLI. Reset is non-destructive to global Codex config. |
| `usage-stats-reset.json` | `usage-reset-stats` atomic writer; usage reports read as a cutoff. | Ignored local display baseline; does not delete `usage-ledger.jsonl` or change provider quota/reset credits. | Safe to preserve for audit. Removing it intentionally re-exposes earlier local ledger history. |
| `plan.md` | `propose` writes; approve/run/humans read exact bytes. | Ignored canonical plan, replaced only by new proposal. | Do not reformat/delete active file; preserve and regenerate after review. |
| `context.json` | Controller saves handoff; prompts/`usage` read. | Ignored schema-tagged atomic cache; init creates default. | Invalid data falls back in memory. Do not hand-fix; delete only inactive, accepting lost handoff. |
| `journal.md` | Controller appends loops/gates/retirement/reconciliation; humans inspect. | Ignored append-only audit; init heading; not fully regenerable. | Preserve damage; never rewrite active audit. Missing history needs human review. |
| `ideas.md` | Controller/worker captures scope ideas; humans curate. | Ignored local bucket; init creates; grants no scope. | Recover useful entries before deletion; init recreates empty. |
| `live.log` | `live_write` appends; TUI/web/operators read. | Ignored plain trace; init header; events are structured counterpart. | Archive/rotate after investigation only; deletion loses trace, init recreates header. |
| `events.jsonl` | Controller/TUI appends; TUI/web read. | Ignored structured append stream; init creates empty; not state authority. | Preserve malformed lines; never fabricate. Deletion loses history; init recreates empty. |
| `usage-ledger.jsonl` | Completed Codex turns append counters; usage/web read. | Ignored local ledger; self-trims past 8 MiB to latest 20,000 rows; no prompts/source/credentials. | Bad rows skipped; archive before deletion. Init recreates empty but historical totals vanish. |
| `recovery/RP-.../` and `refs/ralph/recovery/RP-...` | Approval/checkpoint writes manifest, status, patches, private ref; checkpoint/finalization read. | Ignored filesystem evidence plus local Git ref; approval baseline, not automatic rollback. | Never edit/delete/prune active checkpoint. Missing/corrupt checkpoint blocks finalization; restoration is human Git work. |
| `reports/<prefix>-summary.md` and `.json` | Completion builder writes; report/finalize/web/TUI read. | Ignored derived evidence; regenerated by `report`, requalify, finalization. | Delete only if inactive/no audit need; regenerate after underlying state is sound. |
| `web-job.json` | Web console writes job metadata/dead-PID completion; web reads. | Ignored replaceable UI metadata; no controller authority. | Never use to claim/stop work. After no active job, archive/delete; next web action recreates. |
| `web-run.log` | Web console appends background CLI output; operators read. | Ignored diagnostic log for background web jobs. | Archive/delete only after job ended and durable state/journal inspected; later job recreates. |
| `state.tmp`, `context.tmp` | Atomic writers make transient replacements. | Ignored, normally removed by replace. | Leftover suggests interruption: preserve for diagnosis, never promote over primary file. |

## Copy/paste-safe workflow and restart

This workflow uses no secrets and no network devices. Copy the `propose` hash
only after reviewing `.ralph/plan.md` and obtaining human approval; stop at each
block.

```bash
python3 scripts/ralph.py init
python3 scripts/ralph.py status
python3 scripts/ralph.py propose --goal "<bounded, reviewed objective>"
# Review .ralph/plan.md; obtain approval for its exact printed SHA-256.
python3 scripts/ralph.py approve <PLAN_HASH>
python3 scripts/ralph.py run --max-loops 1 --color never
python3 scripts/ralph.py status
```

Repeat only the last `run`/`status` pair while status is `APPROVED`. At
`BLOCKED_HUMAN`, inspect before choosing the table's matching narrow action:

```bash
python3 scripts/ralph_gate.py --view review --details
```

At `READY_TO_COMMIT`, review before the separate guarded Git decisions:

```bash
python3 scripts/ralph.py finalize <PLAN_HASH>
python3 scripts/ralph.py requalify <PLAN_HASH>
python3 scripts/ralph.py finalize <PLAN_HASH> --commit
python3 scripts/ralph.py finalize <PLAN_HASH> --push
```

After a terminal/browser interruption, start with `status`, then use
`checkpoints`, `checkpoint-info`, and `report`. Persisted state, canonical plan,
checkpoint, journal, and qualification fingerprint determine restart authority;
terminal output and web-job metadata do not.

## Efficiency governor, model selection, quota actions, and token reporting

RALPH separates **efficiency policy** from **usage admission**. The default 5% Codex reserve is a configurable start gate for new work, not an in-flight kill switch. When new work begins above the configured reserve in every relevant Codex window, RALPH admits it and binds that admission to the resulting plan identity. That exact plan may continue through model turns, qualification, bounded repair, review, and completion even if remaining allowance later falls below the reserve. Backend denial remains authoritative. A different/new plan does not inherit admission.

Example: a plan admitted with 15% remaining may legitimately finish at 1%. At 1%, another plan is blocked until allowance recovers above the configured reserve. Changing the reserve during execution affects future admissions only.

The live policy is stored atomically in `.ralph/efficiency-policy.json`, independently of `state.json`. The web console can therefore change policy while an active RALPH process is persisting controller state. RALPH reloads it at model-turn and post-step decision boundaries.

### Per-mode limits

Each enabled mode owns a complete independent limit set rather than deriving limits from multipliers:

| Mode | Default prompt commands | Commands | Files inspected | Cumulative input | Non-cached input | Intent |
|---|---:|---:|---:|---:|---:|---|
| `STRICT` | 4 | 6 | 6 | 450,000 | 75,000 | Small, tightly bounded work. |
| `NORMAL` | 6 | 8 | 8 | 600,000 | 100,000 | Baseline/default engineering work. |
| `RELAXED` | 12 | 32 | 32 | 2,400,000 | 400,000 | Documentation, architecture, extraction, migration and broad analysis. |
| `OFF` | n/a | n/a | n/a | n/a | n/a | Ordinary efficiency pauses disabled. |

When `OFF` is selected, ordinary mode-limit fields are disabled in the web UI so the operator cannot mistake inactive thresholds for enforced controls. The configurable new-work reserve and emergency runaway ceilings remain active because they are separate safety/resource controls. Runaway ceilings are always enforced and must remain at least as high as every enabled mode limit.

The web panel is deliberately compact: the section header contains **Efficiency mode**, **New-work reserve %**, the current policy revision and the live/pending state in one line. Only the currently selected mode's five limits are shown below; emergency ceilings remain under an expandable section. Hover/ⓘ help explains each control, and limit values show their baseline. A small reset icon appears beside values that differ from baseline. Changes are staged and applied atomically with **Apply changes**; browser refresh does not overwrite staged edits. **Restore baselines** stages all defaults and **Discard staged** restores the last applied policy. The planner recommendation is not repeated in the panel because NORMAL is the default and recommendation does not change policy authority.

Equivalent CLI control remains available:

```bash
python3 scripts/ralph.py efficiency-policy show --json
python3 scripts/ralph.py efficiency-policy set --mode relaxed --reserve-percent 7.5 \
  --relaxed-max-commands 36 --relaxed-max-reported-files 36
python3 scripts/ralph.py efficiency-policy reset-mode
python3 scripts/ralph.py efficiency-policy reset
```

`run --efficiency-mode ...` remains a compatibility/operator shortcut that changes the live selected mode. The planner may recommend `RELAXED` for inherently broad goals but never changes the mode silently.

Expected resource stops remain distinct:

- `PAUSED_EFFICIENCY_POLICY` — the selected enabled mode threshold was exceeded after a qualified step;
- `PAUSED_RUNAWAY` — always-on emergency ceiling exceeded;
- `BLOCKED_INSUFFICIENT_START_RESERVE` — new work without matching plan admission attempted to start at/below reserve.

### Live model and effort pickers

The authenticated Codex model and reasoning-effort pickers are exposed in the console's **top utility bar**, alongside live/PID state, token-stat reset and logout, so execution selection remains available without scrolling. On desktop the model/effort pair is stacked to preserve horizontal space; live/PID is stacked beside it, followed by token-stat reset and right-justified logout. On mobile the model and effort controls use an explicit 50/50 row. Selection is stored only in `.ralph/model-policy.json`; RALPH does not rewrite `~/.codex/config.toml`. Model and effort options come from the authenticated Codex model catalog. Either selection can be reset independently to the configured Codex default. A live change affects the **next** Codex process/model turn and never interrupts an already-running process. If a model change makes an existing project-local effort override invalid for the new model, RALPH clears that effort override rather than launching an unsupported combination.

### Banked reset redemption

When the Codex rate-limit surface reports one or more available reset credits, the web toolbar displays an animated **Redeem** button. If detailed credits are available, the earliest-expiring available credit is presented first. Clicking **Redeem** opens a confirmation dialog describing the account action; redemption occurs only after explicit confirmation. The CLI independently requires `--confirm REDEEM`, and the consume request uses a fresh idempotency key. RALPH never redeems a banked reset automatically.

After a successful redemption action, the web usage monitor refreshes immediately so provider quota/reset-credit state does not remain visually stale until the periodic refresh.

### Consumption by plan and local statistics reset

`usage-ledger.jsonl` remains the durable local source for observed model-turn counters. **Consumption by plan** uses an aligned compact table-like summary with plan identity, turns, total tokens, cache ratio and a single-line goal. The expand chevron is positioned independently from the data grid so long goals cannot collapse into a narrow column. Expanding a row exposes:

- input and non-cached input;
- cached and cache-write input;
- output and reasoning output;
- average input/output per observed turn;
- first/last observed timestamps;
- model(s) used;
- compact consumption breakdowns by scope, phase and step.

The red **Reset token stats** control is also in the top utility bar and requires confirmation. It writes only `.ralph/usage-stats-reset.json`, moving the local reporting baseline forward. It does **not** delete the ledger, redeem/reset provider quota, modify banked reset credits, or create new work authority. Earlier rows remain available for audit/recovery with explicit pre-reset reads; ordinary web/CLI reports show only post-baseline activity. The monitor refreshes immediately after reset.
