# RALPH authority map

The controller decides approval, execution, qualification, recovery, and loop accounting. The web console invokes its CLI and `ralph_gate.py` is read-only. Core authority can move; ZEN policy and operations remain host-local.

| Authority | Evidence | Disposition |
| --- | --- | --- |
| Approval/stop controls | `scripts/ralph.py`, `.ralph/policy.md` | core enforcement |
| ZEN protected-path, credential, production restrictions | `.ralph/policy.md` | ZEN policy |
| Web bind/auth/CSRF | `scripts/ralph_web.py` | optional ZEN adapter |
| Incident/performance guidance | `scripts/ralph_gate.py`, `ZEN_PROFILE` | ZEN host guidance |

See [authority, validation, and recovery](../authority-validation-recovery.md) and [ADR-XXXX](../../adr/ADR-XXXX-ralph-extraction-boundary.md).
