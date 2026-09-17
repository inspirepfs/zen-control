# ZEN Control RALPH integration

ZEN Control is the supported embedded RALPH-Lite host today. It supplies host values while the controller retains lifecycle authority.

| ZEN-owned concern | Actual evidence | Future split status |
| --- | --- | --- |
| Profile | `scripts/ralph_profile.py` / `ZEN_PROFILE` | retain ZEN adapter |
| Root/state | ZEN checkout and `.ralph/` | host-associated runtime state stays local |
| Consumers | `ralph.py`, `ralph_web.py`, `ralph_gate.py` import `ZEN_PROFILE` | preserve behavior through adapter |
| Validation | source/test roots, `scripts/ux_validate.py`, optional release validators | ZEN profile |
| Security/operations | `.ralph/policy.md`, web bind/auth/CSRF, RouterOS/production/credential prohibition | ZEN-local |
| Guidance | ZEN Incident Monitor; `python3 scripts/perf_acceptance.py ../zen-performance.json` | ZEN-local |
| Compatibility | `.ralph` names and persisted `zen_*` schemas | no migration here |

This intentionally duplicates `docs/ralph/` boundary material so ZEN operators retain a host guide while a future independent repository has core-oriented documentation. It does not authorize standalone installation. See the [dry run](../../ralph/extraction/DRY_RUN.md).
