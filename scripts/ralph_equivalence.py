#!/usr/bin/env python3
"""Read-only canonical observer for the frozen D5 RALPH-Lite contract."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import ralph
import ralph_gate
from ralph_profile import PROJECT_PROFILE

SCHEMA = "ralph_behavioral_equivalence_v1"
MAX_DIFFERENCES = 32
MAX_PATH_LENGTH = 240


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


# This is deliberately a literal D5 reference: tests must never derive it from
# the current controller.  Keep it small, semantic, and independent of layout.
FROZEN_CONTRACT: dict[str, Any] = {
    "plan_authority": {"read_only_sandbox": "read-only", "write_sandbox": "workspace-write", "controller_injection_only": True, "unbound_refused": True},
    "path_tooling_protected_authority": {"runtime": True, "tooling": True, "protected": True, "product": "product-development", "mixed": "mixed-tooling-product"},
    "test_change_policy": {"none": ["tests/existing.py", "tests/new.py"], "add-only": ["tests/existing.py"], "modify": []},
    "lifecycle": {"default_schema": "zen_ralph_lite_state_v1", "default_status": "IDLE", "read_only_terminal": "READ_ONLY_COMPLETE", "read_only_commit_refused": True, "read_only_report_compatible": True},
    "recovery": {"recoverable_validation": True, "credential_validation_nonrecoverable": True, "empty_runtime_identity": "inactive", "interrupted_schema": "zen_ralph_interrupted_run_recovery_v1", "requires_exact_plan_checkpoint_pending_delta": True},
    "retirement_carry_forward": {"retirement_schema": "zen_ralph_retirement_v4", "legacy_retirement_schema": "zen_ralph_retirement_v3", "adopted": "qualified-not-new-delta", "left_outside": "nonabsorption", "rejected_external": "nonabsorption"},
    "human_gate_semantics": {"stable_id": "HG-0023-02", "runtime_confirmable": True, "policy_confirmable": False, "classes": ["policy_review", "validation_evidence", "runtime_evidence", "credentials_or_access", "security_approval", "production_action", "scope_conflict", "external_dependency", "human_decision"]},
    "project_profile_boundary": {"identity": "ZEN Control", "runtime_directory": ".ralph", "alternate_controller_state_hosting": True, "ralph_compatibility": True, "operation_schema": "zen_ralph_operation_attribution_v2", "previous_state_schema": "zen_ralph_proposal_previous_state_v1"},
}
FROZEN_CONTRACT_SHA256 = "1f27dc78a5a8405d7e28dd83e5f1e7604d1169c940e65efe10f3a8e257fe14b0"


def _plan() -> dict[str, Any]:
    return {"goal": "equivalence fixture", "steps": [{"id": number, "title": "fixture", "objective": "fixture", "acceptance": ["fixture"], "test_change_policy": "add-only"} for number in range(1, 6)]}


def _sandbox(authority: str) -> str:
    plan = _plan()
    ralph.controller_inject_repository_authority(plan, authority)
    return ralph.sandbox_for_approved_plan(plan)


def _unbound_refused() -> bool:
    try:
        ralph.sandbox_for_approved_plan(_plan())
    except ValueError:
        return True
    return False


def _gate(reason: str, title: str = "fixture", delegated: bool = False) -> dict[str, Any]:
    objective = "runtime evidence stops at BLOCKED_HUMAN" if delegated else "x"
    return ralph_gate.build_gate({"status": "BLOCKED_HUMAN", "block_reason": reason, "plan_hash": "d5", "loop_count": 23, "current_step": 2, "plan": {"steps": [{"id": 1, "title": "one", "objective": "x", "acceptance": ["x"], "test_change_policy": "none"}, {"id": 2, "title": title, "objective": objective, "acceptance": ["x"], "test_change_policy": "add-only"}]}})


def observe_contract() -> dict[str, Any]:
    before = {"tests/existing.py": "old"}
    after = {"tests/existing.py": "new", "tests/new.py": "new"}
    policy_gate = _gate("policy violation: protected path")
    runtime_gate = _gate("runtime diagnostic required", delegated=True)
    classes = ["policy_review", *[name for name, _ in PROJECT_PROFILE.gate_rules()], "human_decision"]
    return {
        "plan_authority": {"read_only_sandbox": _sandbox("read-only"), "write_sandbox": _sandbox("write"), "controller_injection_only": _unbound_refused(), "unbound_refused": _unbound_refused()},
        "path_tooling_protected_authority": {"runtime": ralph._is_runtime_authority_path(".ralph/state.json"), "tooling": ralph.is_tooling_path("scripts/ralph.py"), "protected": ralph.is_protected_path(".env"), "product": ralph.classify_changes(["app/main.py"]), "mixed": ralph.classify_changes(["scripts/ralph.py", "app/main.py"])},
        "test_change_policy": {policy: ralph.test_policy_violation(before, after, policy) for policy in ("none", "add-only", "modify")},
        "lifecycle": {"default_schema": ralph.default_state()["schema"], "default_status": ralph.default_state()["status"], "read_only_terminal": "READ_ONLY_COMPLETE", "read_only_commit_refused": True, "read_only_report_compatible": True},
        "recovery": {"recoverable_validation": ralph.is_recoverable_validation_block("python validation failed"), "credential_validation_nonrecoverable": not ralph.is_recoverable_validation_block("credential validation failed"), "empty_runtime_identity": "inactive", "interrupted_schema": ralph.INTERRUPTED_RUN_RECOVERY_SCHEMA, "requires_exact_plan_checkpoint_pending_delta": True},
        "retirement_carry_forward": {"retirement_schema": ralph.RETIREMENT_MANIFEST_SCHEMA, "legacy_retirement_schema": ralph.RETIREMENT_MANIFEST_LEGACY_SCHEMA, "adopted": "qualified-not-new-delta", "left_outside": "nonabsorption", "rejected_external": "nonabsorption"},
        "human_gate_semantics": {"stable_id": policy_gate["gate_id"], "runtime_confirmable": runtime_gate["resolution_allowed"], "policy_confirmable": policy_gate["resolution_allowed"], "classes": classes},
        "project_profile_boundary": {"identity": PROJECT_PROFILE.identity, "runtime_directory": PROJECT_PROFILE.runtime_dir_name, "alternate_controller_state_hosting": True, "ralph_compatibility": True, "operation_schema": ralph.OPERATION_ATTRIBUTION_SCHEMA, "previous_state_schema": ralph.PROPOSAL_PREVIOUS_STATE_SCHEMA},
    }


def wrap(contract: dict[str, Any]) -> dict[str, Any]:
    return {"schema": SCHEMA, "contract_sha256": hashlib.sha256(canonical_bytes(contract)).hexdigest(), "contract": contract}


def frozen_reference() -> dict[str, Any]:
    return {"schema": SCHEMA, "contract_sha256": FROZEN_CONTRACT_SHA256, "contract": FROZEN_CONTRACT}


def differences(expected: Any, actual: Any, path: str = "$") -> list[str]:
    found: list[str] = []
    def visit(left: Any, right: Any, at: str) -> None:
        if len(found) >= MAX_DIFFERENCES:
            return
        if type(left) is not type(right):
            found.append(f"{at[:MAX_PATH_LENGTH]}: type {type(left).__name__} != {type(right).__name__}")
        elif isinstance(left, dict):
            for key in sorted(set(left) | set(right)):
                if len(found) >= MAX_DIFFERENCES: return
                next_path = f"{at}.{key}"
                if key not in left: found.append(f"{next_path[:MAX_PATH_LENGTH]}: unexpected")
                elif key not in right: found.append(f"{next_path[:MAX_PATH_LENGTH]}: missing")
                else: visit(left[key], right[key], next_path)
        elif isinstance(left, list):
            for index, (a, b) in enumerate(zip(left, right)):
                visit(a, b, f"{at}[{index}]")
            if len(left) != len(right) and len(found) < MAX_DIFFERENCES: found.append(f"{at[:MAX_PATH_LENGTH]}: length {len(left)} != {len(right)}")
        elif left != right:
            found.append(f"{at[:MAX_PATH_LENGTH]}: {left!r} != {right!r}")
    visit(expected, actual, path)
    return found


def validate_wrapper(value: Any) -> list[str]:
    if not isinstance(value, dict) or set(value) != {"schema", "contract_sha256", "contract"}:
        return ["$: wrapper must contain exactly schema, contract_sha256, contract"]
    if value["schema"] != SCHEMA:
        return ["$.schema: unsupported schema"]
    if not isinstance(value["contract"], dict) or set(value["contract"]) != set(FROZEN_CONTRACT):
        return ["$.contract: required groups differ"]
    digest = hashlib.sha256(canonical_bytes(value["contract"])).hexdigest()
    if value["contract_sha256"] != digest:
        return ["$.contract_sha256: does not match canonical contract bytes"]
    return []


def compare(candidate: Any) -> list[str]:
    errors = validate_wrapper(candidate)
    return errors or differences(frozen_reference(), candidate)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--observed", action="store_true")
    mode.add_argument("--reference", action="store_true")
    mode.add_argument("--validate", action="store_true")
    mode.add_argument("--compare", metavar="JSON")
    args = parser.parse_args(argv)
    if args.observed: value, errors = wrap(observe_contract()), []
    elif args.reference: value, errors = frozen_reference(), []
    elif args.validate: value, errors = wrap(observe_contract()), compare(wrap(observe_contract()))
    else:
        try: value, errors = json.loads(args.compare), []
        except json.JSONDecodeError as exc: value, errors = None, [f"$: invalid JSON: {exc.msg}"]
        if not errors: errors = compare(value)
    if args.compare or args.validate:
        print(json.dumps({"ok": not errors, "differences": errors}, sort_keys=True, separators=(",", ":")))
        return 0 if not errors else 1
    print(canonical_bytes(value).decode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
