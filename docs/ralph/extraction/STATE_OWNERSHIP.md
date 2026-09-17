# State ownership and extraction disposition

All paths below are relative to the configured state root, currently
`.ralph/`. “Controller” means the RALPH controller and its approved internal
helpers; a web request reaches a writer only through the controller CLI.
Existing files and schemas are not changed by this inventory.

| Artifact | Owner | Readers | Writers | Scope and lifetime | Project-specific content | Portability | Disposition |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `state.json` | Controller authority | Controller, web snapshot, gate | Controller | One active/project lifecycle state; durable | Plan hash, ZEN worktree/Git facts, host gate context | Schema is core-owned; values are host-bound | `split` |
| `plan.md` | Controller authority | Controller, operators, web | Controller | Active plan through retirement/completion | ZEN goal, steps, host acceptance | Generic plan protocol; host content is not portable | `split` |
| `ideas.md` | Controller authority | Controller, operators | Controller | Durable cross-loop ideas bucket | ZEN backlog observations | File behavior portable; entries are host-specific | `split` |
| `journal.md` | Controller authority | Controller, operators, gate | Controller | Durable audit history | ZEN loop results, gate/qualification evidence | Record format portable; evidence paths are host-specific | `split` |
| `policy.md` | Controller authority with host change control | Controller/prompt, operators | Approved repository maintenance, never the active worker | Tracked durable authority document | RouterOS, credential, path, and ZEN operational restrictions | Core consumes a policy; contents remain host-specific | `split` |
| `live.log` | Controller | Controller, web, gate | Controller | Append-only current/recent execution trace | ZEN commands and local evidence | Log mechanism portable; text is host-specific | `move` |
| `context.json` | Controller | Controller, prompt construction | Controller | Durable compact handoff between loops | `zen_ralph_lite_context_v1`, ZEN paths/findings | Existing schema must remain readable | `review-required` |
| `events.jsonl` | Controller/TUI event helper | Controller, web, gate | Controller/TUI helper | Append-only event history | ZEN command and operator event text | Event stream behavior portable | `move` |
| `recovery/<checkpoint>/manifest.json` | Controller | Controller, operators | Controller | Per-checkpoint durable recovery evidence | Git refs, ZEN worktree paths, dirty-file facts | Checkpoint protocol portable; Git details require adapter | `split` |
| `reports/<plan>-summary.json` and `.md` | Controller | Controller, web, operators | Controller | Per-plan durable report | ZEN plan, qualification, publication facts | Report generation portable; host evidence is not | `split` |
| `usage-ledger.jsonl` | Controller | Controller, web | Controller | Bounded durable usage/accounting history | Local Codex usage observations and plan scope | Ledger behavior portable; provider fields need adapter | `split` |
| `usage-stats-reset.json` | Controller | Controller, web | Controller | Durable local statistics baseline | Local reset timestamp/usage facts | Portable only with the usage provider contract | `adapter-required` |
| `efficiency-policy.json` | Controller policy helper | Controller, web | Controller policy helper via approved action | Durable live resource policy | `zen_ralph_efficiency_policy_v2` and host limits | Preserve filename/schema and v1 normalization | `review-required` |
| `model-policy.json` | Controller model helper | Controller, web | Controller model helper via approved action | Durable project model override | `zen_ralph_model_policy_v1`, local model choice | Preserve filename/schema pending decision | `review-required` |
| `web-job.json` | Web adapter | Web, controller status view | Web adapter | While a local web job is active/recent | Local process/job metadata | Not controller authority; console-specific | `adapter-required` |
| `web-run.log` | Web adapter | Operators | Web adapter | Local web-server run trace | Local bind/job diagnostics | Console-specific | `adapter-required` |
| `state.json.repair-*.bak` | Controller recovery process | Controller/operator recovery | Controller recovery process | Short-to-medium recovery backup | Prior project state | Existing recovery compatibility only | `review-required` |
| Atomic `*.tmp` siblings | Controller/policy helpers | No normal reader | Controller/policy helpers | Transient write interval only | Same as target artifact | Implementation detail, not a migration format | `move` |

The owner does not change when an operator uses the web console: the console is
an adapter, not a state authority.  Retention, state-root placement, and host
content are adapter decisions; controller lifecycle and integrity rules remain
core concerns.
