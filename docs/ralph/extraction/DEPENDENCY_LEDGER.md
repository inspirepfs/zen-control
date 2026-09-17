# RALPH–ZEN Dependency Ledger

## Scope and classification key

This is a static extraction baseline captured for approved plan
`e2c3bfa3fbbd27bf9af14c5f4fba18829b4d074f4e1ea09d71cbd2a97d9a55e2`,
step 1. It describes the embedded implementation as inspected; it does not
move code, change an operator command, or assert that any command was run.

Every row has exactly one classification from this key:

| Classification | Meaning |
| --- | --- |
| `CORE` | RALPH lifecycle capability that is not intrinsically a ZEN application dependency. |
| `HOST_LAYOUT` | Current embedding relies on the ZEN repository layout or local runtime paths. |
| `HOST_VALIDATION` | The host project supplies or selects validation behavior. |
| `EXTERNAL_TOOL` | A local executable or service interface outside the RALPH modules is required. |
| `COMPATIBILITY` | A persisted or exchanged label whose existing value must remain readable. |
| `OPERATOR_SURFACE` | A human-facing or web bridge that exposes controller capability. |

Runtime criticality is `critical` when the normal controller path cannot
continue correctly without it, `conditional` when it is used only by its
feature/command, and `informational` when it is read-only presentation.

| ID | Dependency | Current location | Classification | Runtime criticality | Extraction action | Risk |
| --- | --- | --- | --- | --- | --- | --- |
| DL-01 | Repository root is `Path(__file__).resolve().parents[1]`, so launching the checked-in module under `scripts/` establishes the ZEN root. | `scripts/ralph.py`, `scripts/ralph_web.py`, `scripts/ralph_gate.py` | `HOST_LAYOUT` | critical | Replace repeated derivation with a host-profile root resolver while preserving this value for ZEN. | A different package layout can redirect all state, commands, and Git calls. |
| DL-02 | `.ralph/` is a project-root-relative durable state directory. | `scripts/ralph.py`; policy/model/efficiency modules; web and gate readers | `HOST_LAYOUT` | critical | Make the directory an explicit host contract; retain ZEN's `.ralph` location. | Relocation breaks active plans and operator history. |
| DL-03 | The controller owns state, plan, ideas, journal, live event log, context, events, recovery, reports, usage ledger, and usage-reset artifacts under `.ralph/`. | Constants and state helpers in `scripts/ralph.py` | `CORE` | critical | Inventory owner/reader/writer per artifact before any move; keep formats intact. | Losing or mis-owning an artifact compromises approval, recovery, or audit history. |
| DL-04 | Efficiency and model settings are project-local atomic JSON files: `.ralph/efficiency-policy.json` and `.ralph/model-policy.json`. | `scripts/ralph_efficiency.py`, `scripts/ralph_model.py` | `COMPATIBILITY` | conditional | Preserve filenames and schemas through the profile seam; defer migration. | A new location or non-atomic writer can change live-turn behavior. |
| DL-05 | The controller inserts its `scripts/` directory in `sys.path` and imports sibling `ralph_tui`, `ralph_efficiency`, and `ralph_model` modules. | `scripts/ralph.py` imports | `HOST_LAYOUT` | critical | Keep a package-compatible internal import boundary before extraction. | Direct sibling imports fail after a layout move. |
| DL-06 | `.ralph/policy.md` is controller-owned policy and its controls are injected into the execution prompt. | `scripts/ralph.py`; `.ralph/policy.md` | `CORE` | critical | Keep policy ownership and prompt reference as a host-configured policy path. | Changing authority text or ownership weakens the control loop. |
| DL-07 | Git supplies working-tree status, recovery refs/checkpoints, delta binding, branch/upstream, commit, and push reconciliation. | Git helpers and finalization paths in `scripts/ralph.py` | `EXTERNAL_TOOL` | critical | Specify Git capability as a host prerequisite/adapter; retain ZEN command semantics. | A non-Git host cannot provide recovery or finalization guarantees. |
| DL-08 | The `codex` executable and its app-server stdio interface provide plan/step execution, model catalog, rate limits, and reset-credit operations; the global Codex config may provide a default model. | `scripts/ralph.py` Codex helpers; `~/.codex/config.toml` lookup | `EXTERNAL_TOOL` | critical | Define the executable/app-server contract separately from the project-local model override. | Missing/auth-incompatible Codex blocks proposal/run and usage/model features. |
| DL-09 | Plan and result JSON schemas retain `zen_ralph_lite_state_v1`, `zen_ralph_lite_context_v1`, and controller `PLAN_SCHEMA`/`RESULT_SCHEMA` labels and fields. | `scripts/ralph.py` | `COMPATIBILITY` | critical | Treat existing `zen_*` identifiers and result context limits as compatibility values. | Renaming produces unreadable active state or invalid controller/model exchanges. |
| DL-10 | Policy schemas are `zen_ralph_efficiency_policy_v2` and `zen_ralph_model_policy_v1`; efficiency supports legacy v1 normalization. | `scripts/ralph_efficiency.py`, `scripts/ralph_model.py` | `COMPATIBILITY` | conditional | Preserve schemas, migration behavior, and validation limits until a separately approved migration. | Policy loss or schema drift changes resource/model selection. |
| DL-11 | Controller qualification selects ZEN source directories (`app/`, `scripts/`) and runs ZEN's UX validator. | `qualification_gates()` in `scripts/ralph.py`; `scripts/ux_validate.py` | `HOST_VALIDATION` | critical | Move command registration into a ZEN profile, keeping core gate orchestration separate. | A generic package would compile/test the wrong surface or omit host UX checks. |
| DL-12 | Full qualification conditionally adds ZEN environment, supply-chain, and public-audit validators and always adds Git diff checking. | `final_qualification_gates()` in `scripts/ralph.py`; `scripts/env_validate.py`, `scripts/supply_chain_validate.py` when present | `HOST_VALIDATION` | critical | Represent named optional host validators explicitly; do not remove the controller's fail-fast runner. | Omission changes release evidence and may conceal host regressions. |
| DL-13 | Prompts name “ZEN Control,” impose targeted inspection, policy, one-step authority, test-change policy, and the controller response schema/context budget. | `plan_prompt()` and `step_prompt()` in `scripts/ralph.py` | `COMPATIBILITY` | critical | Separate host display/instruction text from generic loop rules, retaining operationally significant wording. | Altered prompts can expand scope or break controller result parsing. |
| DL-14 | The web console reads `.ralph` snapshots/events, takes an action payload, and invokes the existing `scripts/ralph.py` CLI; it does not own durable controller decisions. | `scripts/ralph_web.py` | `OPERATOR_SURFACE` | conditional | Keep it as a controller CLI adapter; profile its root, state, display, and executable location. | A direct state-writing web extraction would bypass controller authority. |
| DL-15 | Web behavior is loopback by default, requires explicit LAN opt-in, validates `Host`, applies CSRF, and uses session-password auth in LAN mode. | `scripts/ralph_web.py` | `OPERATOR_SURFACE` | conditional | Preserve bind/auth/CSRF/API behavior unchanged while separating host metadata. | A redesign can expose controller actions or change operator workflow. |
| DL-16 | The human-gate utility is read-only: it reads state/journal/live data, classifies blockers, produces operator/developer/release guidance, and never resumes a plan or calls Codex. | `scripts/ralph_gate.py` | `OPERATOR_SURFACE` | informational | Retain read-only authority boundary; identify only ZEN-specific wording as profile-owned later. | Treating guidance as execution authority bypasses human approval/evidence. |
| DL-17 | Gate guidance names ZEN Incident Monitor evidence and the ZEN performance acceptance command `python3 scripts/perf_acceptance.py ../zen-performance.json`. | `_guidance()` in `scripts/ralph_gate.py` | `HOST_VALIDATION` | conditional | Put host-specific incident/performance wording behind the profile without changing the current text or command. | Generic guidance could misdirect an operator or weaken evidence requirements. |
| DL-18 | Protected-path, tooling-path, test-change, self-hosting grant, repair-budget, and human-steering checks define the controller's execution authority. | `scripts/ralph.py`; RALPH lifecycle/retry/self-hosting tests | `CORE` | critical | Keep these controls in core lifecycle code, not in a ZEN application adapter. | Extraction that relocates authority can permit unapproved changes. |
| DL-19 | Nine RALPH-prefixed test modules exercise controller, lifecycle, retry, efficiency, model, gate, web, live-refresh, and self-hosting contracts. | `tests/test_ralph_*.py` | `HOST_VALIDATION` | conditional | Classify individual tests in a later test-disposition step; do not move or edit them now. | Premature test moves obscure embedded integration coverage. |

## Extraction constraints evidenced here

- The root/layout, host validators, ZEN wording, and web executable path are
  host dependencies; the lifecycle/authority/repair logic is not evidence of a
  dependency on ZEN application modules.
- Persistent `zen_*` schema names and current `.ralph` filenames are
  compatibility contracts, not permission to migrate state in this step.
- The controller remains the only authority for approval, loop accounting,
  qualification, recovery, and execution. The web and gate surfaces are
  adapters/readers.
