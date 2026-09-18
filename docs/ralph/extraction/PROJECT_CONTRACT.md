# Minimum host-project contract

This contract is the minimum evidenced by the current ZEN Control embedding.
Its labels distinguish a host obligation from current implementation details.
It is not a package manifest, SDK, or plugin contract.

| Contract item | Label | Current ZEN Control value/evidence | Host responsibility |
| --- | --- | --- | --- |
| Project root | `required` | The scripts derive `ROOT` as their repository parent. | Provide a resolved checkout root used consistently for paths, commands, and Git. |
| Project identity | `ZEN implementation` | Prompts and gate guidance name “ZEN Control.” | Supply the display/identity text; do not make it a core identity. |
| Project instructions | `required` | `.ralph/policy.md` is injected into execution prompts. | Supply a tracked authority/policy document at the configured policy path. |
| State directory | `required` | Project-root-relative `.ralph/`. | Supply a writable durable directory; current ZEN location is `.ralph/`. |
| State-directory name | `RALPH default` | Controller constants use `.ralph`. | May retain `.ralph`; a different location needs a future explicit adapter, not an implicit fallback. |
| Policy ownership | `required` | Controller checks for the tracked policy and treats it as authority. | Make policy content and change control project-owned while allowing core protocol enforcement. |
| Ordinary qualification | `required` | Python compilation, unittest discovery, and `scripts/ux_validate.py`. | Declare the applicable project commands and source/test roots. |
| Project gates | `optional` | Environment, supply-chain, and public-release validators are conditional by named ZEN paths. | Declare each additional validator and when it applies; absence is not synthesized by core. |
| RALPH lifecycle validation | `RALPH default` | Approval/hash checks, state transitions, path authority, repair limits, usage/model/efficiency/resource controls, and Git finalization remain in the controller. | Do not supply or weaken lifecycle gates through host-project validation. |
| Git capability | `required` | Status, checkpoints, delta binding, commit/push, and final `git diff --check`. | Provide a usable worktree and Git capability for the current lifecycle. |
| Codex runtime capability | `required` | `codex` CLI/app-server performs planning/execution, usage/model-catalog operations, and exposes the reasoning efforts supported by each authenticated model. | Provide the locally authorized executable/service capability, including configured model/reasoning-effort defaults and supported effort metadata; credentials remain outside this contract. |
| Allowed scopes and protected paths | `required` | Controller and policy restrict protected paths, test changes, and self-hosting. | Declare host path/scope restrictions and test-change policy for every approved step. |
| Project metadata | `optional` | Branch/upstream, host display wording, and host validator labels appear in snapshots/guidance. | Supply only metadata used for display, audit, or command selection; it cannot grant authority. |
| Web console | `optional` | `scripts/ralph_web.py` is an operator adapter. | If enabled, provide bind/auth settings and a controller CLI path; it remains non-authoritative. |
| Gate guidance | `optional` | `scripts/ralph_gate.py` reads controller state and names ZEN evidence. | If enabled, provide project-specific evidence wording without execution powers. |

## Current ZEN profile values

- Root: the ZEN Control checkout containing `scripts/`.
- State root: `.ralph/`; its policy is `.ralph/policy.md`.
- Qualification: compile the current Python sources, run unittest discovery,
  and run `scripts/ux_validate.py`; final qualification conditionally adds the
  named ZEN validators and ends with Git diff checking.
- Host-project validation is registered through the ZEN profile. It is
  deliberately separate from RALPH lifecycle validation: the profile supplies
  project commands, while the controller retains approval, lifecycle, policy,
  usage, model/reasoning-effort, efficiency, resource, and Git authority checks.
- Persisted `zen_*` schema identifiers remain compatibility values. This seam
  change performs no state migration; any rename is separate extraction debt.
- Git: local status, checkpoint/recovery refs, guarded publication, and an
  upstream are the current capabilities.
- Allowed scope: the approved plan, policy, protected-path rules, and
  step-specific test-change policy define it.  Metadata or web requests never
  broaden it.

No host may infer a generic packaging, SDK, or plugin mechanism from this
table.  Those are explicitly outside the evidenced contract.
