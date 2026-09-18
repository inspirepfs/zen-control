# RALPH extraction dry run

**Result: NOT READY FOR PHYSICAL EXTRACTION.** This dry run documents the implemented `ZEN_PROFILE` seam. It does not copy/move code, rename schemas, package, install, migrate state, or operate RALPH outside ZEN Control.

| Surface | Actual evidence | Proposed disposition |
| --- | --- | --- |
| Controller | `scripts/ralph.py`; sibling `ralph_tui.py`, `ralph_efficiency.py`, `ralph_model.py` imports | future project-neutral core; package imports are extraction debt |
| Profile seam | `scripts/ralph_profile.py`; imports in `ralph.py`, `ralph_web.py`, `ralph_gate.py` | retain unchanged ZEN profile; define stable host contract later |
| Operator adapters | `scripts/ralph_web.py`, `scripts/ralph_gate.py` | web optional; gate read-only; ZEN auth/CSRF/guidance remain local |
| Tests | `test_ralph_profile.py`, `test_ralph_profile_boundary.py`, `test_ralph_web_gate_profile_boundary.py`, `test_ralph_web.py`, `test_ralph_web_live_refresh.py`, `test_ralph_gate.py` | retain embedded coverage; classify portable assertions before moving |
| Validation | `scripts/ux_validate.py`; `app/`, `scripts/`, `tests/`; optional `env_validate.py`, `supply_chain_validate.py`, `public_release_audit.py` | ZEN profile supplies commands; core orchestrates results |
| State | `.ralph/state.json`, `plan.md`, `journal.md`, `context.json`, `events.jsonl`, `recovery/`, `reports/`, policy/model/usage/web files | retain local root/filenames; split lifecycle schemas from storage |
| Configuration | `.ralph/policy.md`, efficiency/model-and-effort policy, root/CLI/guidance profile values | ZEN-local; existing `zen_*` schemas remain readable |
| Documentation | `docs/ralph/`, `docs/zen/ralph-integration/`, ADR | deliberate duplication retained for separation |

| Item | Move/remain/break status |
| --- | --- |
| Approval, plan digest, loop/repair controls, recovery integrity, audit rules | move behavior only after a core package boundary exists |
| `ZEN_PROFILE` root, state root, metadata, CLI; ZEN validation/policy/web security/guidance | remain ZEN adapter; extracting now breaks paths, source-root evidence, and operator workflow |
| `.ralph/` files and `zen_*` schemas | host-local compatibility; moving now risks active plans/history/readers |
| Sibling imports, Codex/Git subprocess assumptions | extraction debt: package import, runtime/usage, and Git adapters |
| Packaging, installer, configuration, migration, non-ZEN operations | extraction debt; no supported independent repository exists |

Focused evidence from the ZEN checkout:

```bash
python3 -m unittest tests.test_ralph_profile tests.test_ralph_profile_boundary tests.test_ralph_web_gate_profile_boundary
python3 -c "from pathlib import Path; assert all(p.exists() for p in [Path('docs/ralph/architecture/README.md'), Path('docs/ralph/extraction/DRY_RUN.md'), Path('docs/zen/ralph-integration/README.md'), Path('docs/adr/ADR-XXXX-ralph-extraction-boundary.md')])"
```

Passing this proves the documented profile boundary and link targets only. It does not prove standalone qualification, installation, migration, or operations; those are extraction debt.
