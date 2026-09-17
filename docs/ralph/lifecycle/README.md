# RALPH lifecycle map

Current authority is embedded in `scripts/ralph.py` and documented in [the ZEN lifecycle reference](../lifecycle.md). The project-neutral direction retains digest-bound plans, one approved step, qualification, repair limits, recovery, and finalization without changing stop conditions.

| Concern | Actual evidence | Disposition |
| --- | --- | --- |
| Plan digest and approval | `.ralph/plan.md`, `.ralph/state.json` | move protocol |
| Loop/repair/human stop | `scripts/ralph.py`, `.ralph/journal.md` | move protocol |
| Goal, scope, test-change policy | approved plan, `.ralph/policy.md` | split host content/core enforcement |
| Qualification commands | ZEN profile and `scripts/ux_validate.py` | host adapter |

The [dry run](../extraction/DRY_RUN.md) names the actual future file and import changes; no lifecycle code moves in this step.
