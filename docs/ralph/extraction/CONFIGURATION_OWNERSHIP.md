# Configuration ownership

Configuration is separated by decision authority, not by the current location
of the code that reads it.  This preserves current ZEN behavior while making
future extraction choices auditable.

| Configuration | Owner | Current source | Reader | Extraction disposition |
| --- | --- | --- | --- | --- |
| Approval hash, one-step execution, repair ceiling, state transitions, protected authority checks | RALPH core | `scripts/ralph.py` and controller policy enforcement | Controller | `move` |
| State root and project root mapping | Host adapter | scripts-relative root and `.ralph/` constants | Controller, web, gate | `adapter-required` |
| Project identity and prompt display wording | ZEN implementation | Controller prompts and gate text | Controller, gate, web | `remain` |
| Project instructions, RouterOS/production restrictions, credential prohibition, and protected paths | ZEN policy | `.ralph/policy.md` | Controller prompt/enforcement | `remain` |
| Allowed scopes and test-change policy for an approved step | Human-approved plan plus ZEN policy | Plan/state/policy | Controller | `split` |
| Python source roots, unittest discovery, UX validation, and optional release validators | ZEN implementation | `qualification_gates()` / final gates | Controller | `adapter-required` |
| Git worktree, checkpoint/ref, commit/push, branch and upstream operations | Git adapter | Controller Git helpers | Controller, web snapshot | `adapter-required` |
| Codex executable, app-server usage/model catalog, and global default model/reasoning effort | Runtime adapter | Controller helpers and user-local Codex configuration | Controller | `adapter-required` |
| Project-local efficiency limits and model/reasoning-effort overrides | Controller policy helpers under host state root | `efficiency-policy.json`, `model-policy.json` | Controller, web | `review-required` |
| Web bind, LAN opt-in, session/auth, CSRF, and executable location | Web adapter with host security policy | `scripts/ralph_web.py` | Web console | `adapter-required` |
| Gate audience wording and ZEN incident/performance evidence commands | ZEN implementation | `scripts/ralph_gate.py` | Gate utility | `remain` |

`RALPH default` values are limited to controller protocol behavior and the
current `.ralph` state-directory convention.  A host must explicitly provide
all project-specific values above; absent values are not permission for a
generic fallback or a speculative plugin framework.
