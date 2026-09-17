# RALPH core boundary

This is the Step 2 extraction map for the currently embedded RALPH-Lite
controller.  A disposition describes the intended boundary only; it does not
move code, change an entry point, or define an installable package.

| Concern | Evidence today | Disposition | Boundary rule |
| --- | --- | --- | --- |
| Controller lifecycle, plan approval, loop accounting, repair limits, scoped self-hosting, and stop conditions | `scripts/ralph.py`; lifecycle/retry/self-hosting tests | `move` | Preserve controller authority as RALPH core behavior. |
| Recovery checkpoints, plan-delta binding, event/journal evidence, resource accounting, and usage pauses | `scripts/ralph.py` and controller-owned state | `move` | Retain the behavior and schemas; make location and external services host supplied later. |
| State artifacts and their filesystem store | `.ralph/` constants and readers | `split` | Core owns schemas, lifecycle, and access rules; the host supplies the root and retention location. |
| Policy enforcement and injected core control rules | `.ralph/policy.md`, `step_prompt()` | `split` | Core enforces its non-negotiable protocol; host policy provides project-specific prohibitions and instructions. |
| Project root resolution, identity, prompt display text, instructions, allowed scopes, and metadata | scripts-relative root and ZEN wording | `adapter-required` | A host profile must provide these values while ZEN preserves today's values. |
| Project qualification and final release validators | `qualification_gates()` and named ZEN validators | `adapter-required` | Core may orchestrate failures; the command list and applicability are host-owned. |
| Git checkpointing, guarded commit/push, branch/upstream reconciliation | controller Git helpers | `adapter-required` | The current Git capability is required by this embedding; core must not infer a repository implementation. |
| Codex executable, app-server usage interface, and configured default model | controller subprocess/configuration helpers | `adapter-required` | A runtime adapter supplies the executable and usage/model capability. |
| Web console bind/auth/CSRF surface and CLI bridge | `scripts/ralph_web.py` | `adapter-required` | It remains an optional controller adapter and must not write controller decisions directly. |
| Read-only human-gate guidance | `scripts/ralph_gate.py` | `split` | Read-only blocker interpretation can travel with RALPH; ZEN wording and evidence commands stay host-owned. |
| Existing RALPH-prefixed tests | `tests/test_ralph_*.py` | `split` | Separate portable behavioral assertions from embedded ZEN integration coverage before any relocation. |
| ZEN application tests, UX validation, RouterOS restrictions, incident/performance guidance, and protected path patterns | `tests/`, `scripts/ux_validate.py`, `.ralph/policy.md`, gate guidance | `remain` | These are ZEN implementation/policy controls, not RALPH defaults. |
| Persisted `zen_*` schemas and current `.ralph` filenames | controller/policy state readers | `review-required` | They remain readable compatibility values until a separately approved migration decision. |

## Authority direction

```text
ZEN host policy, paths, qualification, Git capability, metadata
                         │
                         ▼
              RALPH controller authority
                         │
          ┌──────────────┴──────────────┐
          ▼                             ▼
 state/recovery store            optional web and gate readers
```

The controller remains the sole writer of approval, execution, recovery, and
qualification decisions.  The web console invokes controller commands; the
gate utility is read-only.  Neither becomes a replacement authority at the
extraction boundary.

## Deliberate non-boundary work

This map does not introduce packaging, an SDK, a plugin framework, migration,
or new entry points.  It records only the seams evidenced by the embedded
implementation.
