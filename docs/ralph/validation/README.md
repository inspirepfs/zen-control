# RALPH validation map

RALPH core orchestrates qualification; ZEN supplies current commands through the profile seam, preserving current behavior.

| Validation | Actual path/test | Disposition |
| --- | --- | --- |
| Profile core boundary | `tests/test_ralph_profile.py`, `tests/test_ralph_profile_boundary.py` | portable behavioral candidate |
| Web/gate boundary | `tests/test_ralph_web_gate_profile_boundary.py` | embedded integration coverage |
| Lifecycle/retry | `tests/test_ralph_lifecycle.py`, `tests/test_ralph_retry_hardening.py` | split after classification |
| Host qualification | `scripts/ux_validate.py`, `app/`, `scripts/`, `tests/` | ZEN profile |

Focused checks cover link targets and the profile boundary, not a standalone installer or qualification profile.
