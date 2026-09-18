# RALPH-Lite Behavioural Baseline

## Evidence status

This is a static baseline for approved plan
`e2c3bfa3fbbd27bf9af14c5f4fba18829b4d074f4e1ea09d71cbd2a97d9a55e2`,
step 1. “Known” below means directly inspected source, tracked path, or a
non-executing file count. It does **not** mean a command was executed or that a
test passed. No qualification, CLI operation, state mutation, service start,
or external Codex/RouterOS interaction was performed to create this baseline.

## Static inventory

| Item | Known baseline | Evidence status |
| --- | --- | --- |
| RALPH-prefixed tests | 9 modules: `test_ralph_lite.py`, `test_ralph_lifecycle.py`, `test_ralph_retry_hardening.py`, `test_ralph_efficiency.py`, `test_ralph_model.py`, `test_ralph_gate.py`, `test_ralph_web.py`, `test_ralph_web_live_refresh.py`, and `test_ralph_self_hosting.py`. | Known from targeted test-file inventory; unexecuted. |
| Total test files | 120 `tests/test_*.py` files at this snapshot. | Known from a non-executing `find` count; unexecuted. |
| Embedded root | Each inspected entry surface derives repository root from the file under `scripts/` using `parents[1]`. | Known statically. |
| Durable state | `.ralph/` beneath that root holds controller state and adjacent operational artifacts. | Known statically. |
| Controller authority | `scripts/ralph.py` owns plan approval, loop/repair accounting, protection, gate execution, journaling, recovery/finalization, and Codex invocation. | Known statically. |
| Web/gate authority | The web console forwards CLI actions; the gate utility is read-only and neither owns controller state transitions. | Known statically and covered by named RALPH test areas; unexecuted. |

## Known command entry points

The controller entry point is `python3 scripts/ralph.py <command>`. Its
top-level commands statically include:

`init`, `propose`, `approve`, `reject`, `retire-plan`, `run`,
`efficiency-policy`, `model-policy`, `models`, `redeem-reset`,
`usage-reset-stats`, `steer`, `authorize-self-hosting`, `resume`,
`resolve-gate`, `recover-validation-block`, `checkpoints`,
`checkpoint-info`, `report`, `requalify`, `finalize`, `reconcile-commit`,
`reconcile-push`, `usage`, `serve`, and `status`.

`efficiency-policy` has `show`, `set`, `reset`, and `reset-mode` subcommands;
`model-policy` has `show`, `set`, `reset`, `set-effort`, and `reset-effort`. `serve` starts the local web
console through the existing controller command, defaulting to loopback
`127.0.0.1:8765`. `scripts/ralph_gate.py` is a separate read-only review CLI
with normal rendering plus `--json`, `--markdown`, and `--history` modes.

These are command definitions only. No command above was invoked for this
baseline, except non-mutating source/file inspection needed to document it.

## State lifecycle and authority

The controller starts from a default `IDLE` state with a versioned
`zen_ralph_lite_state_v1` record. It can propose a 5–10-step plan, calculate a
canonical SHA-256 plan hash, require explicit human approval of that exact
hash, and then execute one approved step per Codex loop. State records include
the plan/hash/current step, loop count, failures, last result/block reason,
recovery checkpoint, changed/owned paths, bounded human steering and
self-hosting grants, step results, final qualification, and reconciliation
metadata.

Known durable artifacts under `.ralph/` include `state.json`, `plan.md`,
`policy.md`, `ideas.md`, `journal.md`, `live.log`, `context.json`,
`events.jsonl`, `recovery/`, `reports/`, `usage-ledger.jsonl`,
`usage-stats-reset.json`, `efficiency-policy.json`, and `model-policy.json`.
The controller creates state/policy writes atomically where the inspected
helpers write JSON. This statement is source behavior, not a runtime durability
test result.

Authority is intentionally controller-centred: policy, protected path checks,
test-change policy, exact-plan approval, bounded human steering, scoped
self-hosting grants, repair limits, and qualification are decided in the
controller. Git supports checkpoints/finalization. The web console constructs
controller CLI arguments; the human-gate utility turns blocked state into a
read-only review card. Neither is evidence of permission to edit state directly.

## Usage, model, and efficiency behaviour

The efficiency policy is a project-local
`zen_ralph_efficiency_policy_v2` JSON policy with `STRICT`, `NORMAL`,
`RELAXED`, and `OFF` modes. The static defaults use a normal prompt command
budget of 6 and preserve emergency runaway ceilings even when ordinary policy
is off. Policy load/normalization is performed around controller decisions and
the policy module supports migration of the prior v1 layout.

The model policy is a project-local `zen_ralph_model_policy_v2` JSON record.
It independently accepts a single non-whitespace model identifier and a
reasoning-effort identifier (or no override for either), records a revision/time,
and is reloaded for each new Codex process. Legacy v1 policy normalizes into v2
with no effort override. Missing project overrides fall back independently to
the user's Codex `model` and `model_reasoning_effort` configuration. The controller also uses Codex
app-server stdio for model catalog (including supported reasoning efforts), rate-limit/usage, and reset-credit
operations, persists usage-related records locally, and can pause/admit work
according to the configured reserve. These are static capabilities; no live
Codex query occurred.

## Web behaviour

The web surface derives the same root and `.ralph` paths, reads a bounded
snapshot/events view, and maps approved UI actions to `scripts/ralph.py`
arguments. It defaults to loopback, refuses non-loopback binding without
explicit LAN opt-in, validates Host headers, checks CSRF on writes, and requires
session/password authentication in LAN mode. Its live monitor can refresh
controller usage/model data. This baseline makes no claim that a server was
started, authentication was exercised, or an HTTP response was observed.

## Human-gate behaviour

`scripts/ralph_gate.py` reads state and live history to classify a currently
blocked condition, assign an operator/release/developer owner, and render
operator, developer, release, or review guidance. It supplies specific ZEN
guidance for incident evidence and performance evidence, including the known
performance acceptance command:

```text
python3 scripts/perf_acceptance.py ../zen-performance.json
```

The gate utility explicitly does not edit controller state, resume a plan, or
call Codex. This is static evidence; no human gate was opened or resolved here.

## Known qualification definitions — not run

The ordinary controller qualification definition, in order, is:

```text
python3 -m py_compile <top-level app/*.py and scripts/*.py>
python3 -m unittest discover -s tests -v
python3 scripts/ux_validate.py
```

The final qualification definition first repeats those gates, then conditionally
adds each existing script from this set:

```text
python3 scripts/env_validate.py
python3 scripts/supply_chain_validate.py
python3 scripts/public_release_audit.py
```

It ends with:

```text
git diff --check
```

`env_validate.py` and `supply_chain_validate.py` were present in the targeted
script inventory. `public_release_audit.py` is conditional by source definition
and was not asserted present by this baseline. The compile, unit-test, UX, and
optional validator commands were not run in this step; therefore this document
records no PASS, FAIL, duration, coverage, or release-readiness result for
them. The documentation-only working tree was checked separately with `git diff
--check` after these files were written; that syntax/whitespace check is not
evidence that the controller's full qualification passed.

## Extraction invariants recorded, not changed

- Current ZEN root resolution, `.ralph` location, operator command spellings,
  deployment/bind defaults, and qualification definitions remain unchanged.
- Existing `zen_*` state/policy schema labels are compatibility values.
- Core lifecycle authority remains distinct from the host validation choices and
  ZEN-specific gate guidance identified in the companion dependency ledger.
