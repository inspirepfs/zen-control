# Test disposition

No test is moved or edited in this step.  The classifications below describe
the current evidence boundary and reserve future tests for a later approved
change.

| Disposition | Existing paths | What they establish | Extraction action now |
| --- | --- | --- | --- |
| RALPH core | `tests/test_ralph_lifecycle.py`, `tests/test_ralph_lite.py`, `tests/test_ralph_retry_hardening.py`, `tests/test_ralph_efficiency.py`, `tests/test_ralph_model.py` | Lifecycle, approval/result protocol, retry/repair controls, and policy/model behavior | Keep in place; later separate assertions that need only a core contract. |
| RALPH–ZEN integration | `tests/test_ralph_gate.py`, `tests/test_ralph_self_hosting.py`, `tests/test_ralph_web.py`, `tests/test_ralph_web_live_refresh.py` | Read-only gate behavior, ZEN policy/path authority, and web-to-controller/local-state integration | Keep in place as embedded integration evidence. |
| ZEN | `tests/` other than the nine RALPH-prefixed modules listed above | ZEN application, RouterOS, UX, release, security, and operations behavior | Remain ZEN-owned; no extraction claim is made for them. |
| Future extraction-boundary tests | None currently exist | A future core/adapter contract would need root, state-store, qualification, Git, and operator-adapter boundary coverage | Do not create, rename, or reserve a test path in this step. |

The first category is not proof that its current imports are standalone: these
tests still run in the ZEN repository.  The second category is intentionally
kept distinct so an eventual core extraction cannot accidentally discard host
authority and operator coverage.
