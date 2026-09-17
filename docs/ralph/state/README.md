# RALPH state map

The state root is ZEN's project-local `.ralph/`, resolved through `ZEN_PROFILE`; it is host-associated runtime state, not packaged core data. The controller remains the sole decision writer.

| State class | Actual paths | Disposition |
| --- | --- | --- |
| Approval/audit | `state.json`, `plan.md`, `journal.md`, `ideas.md`, `policy.md` | split schema/authority from host root |
| Evidence | `live.log`, `events.jsonl`, `reports/`, `recovery/` | core lifecycle rules; host storage/retention |
| Context/policy | `context.json`, `efficiency-policy.json`, `model-policy.json` | compatibility review; retain `zen_*` |
| Console runtime | `web-job.json`, `web-run.log` | optional web-adapter state |

See [state ownership](../extraction/STATE_OWNERSHIP.md). Renaming or relocating current files before migration design risks active plan, recovery, and audit breakage.
