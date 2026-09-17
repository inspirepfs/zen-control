# RALPH extraction readiness

RALPH-Lite currently operates as supervised engineering infrastructure inside ZEN Control. This inventory describes the present boundary; it is not an extraction implementation plan or a claim that clean standalone installation exists.

## Readiness assessment

**Pre-extraction boundary readiness: 90% (target range 88–92%). Physical extraction: 0%.** The score is evidence-based: the dependency ledger, core boundary, configuration and state ownership maps, test disposition, implemented profile seam (`scripts/ralph_profile.py`), focused profile/boundary tests, dry run, integration guide, and ADR describe the same boundary. The remaining 10% is substantive: no package layout, installation/configuration contract, state migration, non-ZEN host implementation, or independent operational validation exists. This score measures preparation only, never standalone readiness.

The full proposed file/import/path/test/state/configuration disposition is [DRY_RUN.md](DRY_RUN.md). All unresolved rows there are **extraction debt**.

## Conceptual boundary

```text
                 supplies policy, configuration, qualification, operators
                                      |
                                      v
+----------------+       +--------------------------+       +-------------------+
| RALPH Core     | ----> | Project Adapter          | ----> | ZEN Control       |
| plan/state     |       | root/path mapping        |       | repository, tests |
| approval/gates | <---- | qualification commands   | <---- | Git/worktree      |
| repair ledger  |       | host policy and prompts  |       | local operator UI |
+----------------+       +--------------------------+       +-------------------+
        |                         |                                 |
        +---- current code has these concerns co-located ------------+
```

The left-hand concepts are portable only in principle today. `scripts/ralph.py` and `scripts/ralph_web.py` contain core behavior and ZEN/project choices together; the adapter is a documentation boundary, not a package or interface that can yet be installed separately.

## Dependency ledger

| Current dependency | Classification | Coupling / current location | Extraction disposition |
| --- | --- | --- | --- |
| Plan schema, digest-bound approval, state transitions, repair limit, journal/evidence rules, scoped self-hosting checks | RALPH core | `scripts/ralph.py`; controller-owned `.ralph/` records | Retain as the eventual core API and state model; separate filesystem access behind a state-store interface. |
| Repository root derived from `scripts/ralph.py` / `scripts/ralph_web.py` parent directories | Accidental coupling | `ROOT = Path(__file__).resolve().parents[1]` | Replace with an explicit host-root/configuration input. |
| Fixed `.ralph/` layout (`state.json`, `plan.md`, `journal.md`, `context.json`, events, recovery, reports, usage and web files) | ZEN adapter/policy and runtime dependency | Constants in both controller and web console; `.gitignore` ignores all but policy | Parameterize a per-host state directory and define migration/retention ownership. No clean installer or migration exists. |
| Tracked `.ralph/policy.md` and runtime rules | ZEN adapter/policy | Repository policy governs every active run | Move to a host-supplied policy contract; preserve core policy validation without assuming this file path. |
| ZEN-branded plan and step prompts, the approved-step handoff, six-command budget, and result schema | Mixed: core protocol plus ZEN policy | `plan_prompt()` and `step_prompt()` in `scripts/ralph.py` | Keep generic plan/result protocol in core; inject project name, policy text, workflow limits, and host instructions. |
| `ralph_tui` import and local modules (`ralph_gate`, web CLI bridge) | General project integration | `scripts/ralph.py` imports `ralph_tui`; CLI/web invoke sibling scripts | Package core/UI adapters with explicit entry points; current imports require the ZEN `scripts/` layout. |
| Python interpreter, `app/` and `scripts/` source roots, `tests/` discovery, `scripts/ux_validate.py` | Project adapter | `qualification_gates()` | Make host qualification a declared command list/callback. These ZEN assumptions are not core behavior. |
| Optional `scripts/env_validate.py`, `supply_chain_validate.py`, and `public_release_audit.py`; `git diff --check` final gate | General project integration | `final_qualification_gates()` | Detect/configure through the adapter rather than probing named repository files. Git remains an explicit host capability. |
| Git worktree/status, branch/upstream, checkpoint ref/patch, guarded commit/push | General project integration | Controller and web `git` subprocess calls | Split a Git publication/checkpoint adapter from core; non-Git hosts need a different implementation. |
| Codex executable/app-server and `$HOME/.codex/config.toml` model lookup | Runtime-state dependency | `run_codex`, `query_codex_rate_limits`, `configured_codex_model()` | Define a model-runner and usage-provider interface. Current local executable and user-home configuration are required. |
| ZEN-specific usage schemas (`zen_ralph_lite_context_v1`, `zen_ralph_usage_turn_v1`, `zen_ralph_web_snapshot_v1`) | Accidental coupling | Runtime JSON emitted by controller/web | Version generic RALPH schemas; provide migration only after a compatibility decision. |
| Local web server, loopback/LAN defaults, session/auth/CSRF, HTML console, `.ralph/web-job.json` and `web-run.log` | ZEN adapter/policy and operator-console dependency | `scripts/ralph_web.py` | Make the console optional and consume a controller API. It currently requires the local state layout and sibling CLI. |
| ZEN repository protections: secrets/certs/env patterns, protected tooling paths, ignored runtime/backups directories | ZEN adapter/policy | `scripts/ralph.py`, `.gitignore` | Move protected-path and excluded-directory sets to host policy; do not transfer ZEN exclusions as universal defaults. |
| RouterOS/production/credential prohibition | ZEN policy | `.ralph/policy.md` and injected step prompt | Keep as this host's policy. A reusable core must require an explicit external-systems policy, never infer access. |

## What an adopting host must supply now

A host must currently provide all of the following; otherwise RALPH-Lite is not cleanly installable.

- A checkout whose root is two directories above the controller script, with Git available and a worktree safe for controller snapshots/checkpoints.
- The ZEN `scripts/` layout, including `ralph.py`, `ralph_tui.py`, `ralph_gate.py`, and, if the console is used, `ralph_web.py`; Python can locate sibling modules only because of that layout.
- A writable, ignored `.ralph/` directory and a tracked `.ralph/policy.md`, plus operator acceptance that the controller owns all other files there.
- Python 3, the `codex` executable for planning/execution, and (for live usage checks) the supported Codex app-server and an optional readable `$HOME/.codex/config.toml`.
- `app/` and/or `scripts/` Python sources, a `tests/` unittest suite, and `scripts/ux_validate.py`. Optional final validators have the exact ZEN filenames listed above.
- Local Git identity/upstream configuration if checkpointing, commit, push, or the console's Git snapshot is used; a human operator to perform required approvals and gates.

There is no package manifest, installer, host configuration file, state migration, adapter interface, or documented non-ZEN qualification profile. Copying the scripts into another repository is therefore an unsupported integration, not a clean installation.

## Documentation map and intentional duplication

| Documentation | Why it overlaps | Extraction disposition |
| --- | --- | --- |
| `docs/ralph/README.md` and `docs/RALPH-LITE.md` | The first is the ZEN RALPH documentation index; the second is a ZEN-rooted operator guide. Both intentionally introduce RALPH's supervised role and authority boundary. | Keep the index with the host documentation; move/rewrite the operator guide as an adapter-specific guide when a distributable core exists. Avoid treating either duplicate wording as portable API. |
| `docs/ralph/operator-reference.md` and `docs/ralph/authority-validation-recovery.md` | Both intentionally describe operator evidence and recovery: one is command-oriented, one is authority-oriented. | Retain the concepts in core documentation; parameterize command names, paths, and evidence locations for each adapter. |
| `docs/ralph/architecture.md`, `concepts.md`, and `lifecycle.md` | These deliberately repeat key plan/state/gate vocabulary from different reader perspectives. | Use them as the source for a future core conceptual set, after separating current ZEN paths and CLI specifics. |

## Extraction order (future work)

1. Define core interfaces for state storage, model execution, qualification, Git publication, and operator surfaces.
2. Implement a ZEN adapter that supplies the current paths, policy, prompts, validators, and Git behavior without changing existing semantics.
3. Add installation/configuration and migration support only after the adapter boundary is executable and tested.

Until then, documentation must describe RALPH-Lite as ZEN Control infrastructure rather than a standalone product.
