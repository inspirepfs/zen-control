#!/usr/bin/env python3
"""D6 EX-READY freeze manifest and deterministic validator for embedded RALPH-Lite."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import ralph
import ralph_efficiency
import ralph_equivalence
import ralph_model
from ralph_profile import PROJECT_PROFILE, ZEN_PROFILE

SCHEMA = "ralph_ex_ready_freeze_v1"
MAX_DIFFERENCES = 64
SCHEMA_IDENTIFIER = re.compile(r"zen_ralph_[a-z0-9_]+")

# Literal ZEN-baseline obligations, including legacy names held by fixtures.
PERSISTED_SCHEMA_IDENTIFIERS = [
    "zen_ralph_approval_repository_evidence_v1", "zen_ralph_approved_plan_artifact_v1", "zen_ralph_carry_forward_inventory_v1", "zen_ralph_carry_forward_reconciliation_v3", "zen_ralph_completion_v1", "zen_ralph_efficiency_policy_v1", "zen_ralph_efficiency_policy_v2", "zen_ralph_interrupted_run_recovery_v1", "zen_ralph_lite_context_v1", "zen_ralph_lite_state_v1", "zen_ralph_model_policy_v1", "zen_ralph_model_policy_v2", "zen_ralph_native_provenance_binding_v1", "zen_ralph_operation_attribution_v1", "zen_ralph_operation_attribution_v2", "zen_ralph_operation_reconciliation_v1", "zen_ralph_plan_control_v1", "zen_ralph_post_turn_repository_verification_v1", "zen_ralph_proposal_previous_state_v1", "zen_ralph_recovery_v2", "zen_ralph_retirement_rollback_preview_v1", "zen_ralph_retirement_v3", "zen_ralph_retirement_v4", "zen_ralph_self_upgrade_attribution_recovery_v1", "zen_ralph_self_upgrade_recovery_v1", "zen_ralph_strict_native_provenance_v1", "zen_ralph_test_reconciliation_adoption_v1", "zen_ralph_usage_stats_reset_v1", "zen_ralph_usage_turn_v1", "zen_ralph_verified_attribution_v1", "zen_ralph_web_snapshot_v1",
]

FROZEN_MANIFEST: dict[str, Any] = {'schema': 'ralph_ex_ready_freeze_v1', 'baseline': {'source_label': 'dab5068', 'source_archive_sha256': '2572a7fac7ff0a40d3c0345d48176e6b5cba4aad5a0e2df7ad445626a1e8ae47', 'source_tree_sha256': 'db426756ec6da3eda05fbd7cf520ae76c9264fb1e7817afb5f24a4b3f794ac1e'}, 'inventory': {'controller_sources': {'scripts/ralph.py': '9c7f5a5dc2d2834f4be9503ce76c85eef1cc31a35aecf6cd77af6053700cd333', 'scripts/ralph_efficiency.py': 'edfc37bf619b41c74a6a64a003a9ce18c3006ab0ed003cfb9ec135cf69c66581', 'scripts/ralph_equivalence.py': '43e2e8230af8e3e88d262d909313a3f78ee25f023d08015e534c54ec2e61e5ef', 'scripts/ralph_gate.py': '18881fad171021f56ed2b2d6b222999fe9014924b9a05b45c41223009fddaf23', 'scripts/ralph_model.py': 'b3cb061be6a3a942a6b63415cab1ab6b4a40dc52dc0d44d493d75ab528c0ab61', 'scripts/ralph_profile.py': 'c4f66cc18eacbe4d165f980febbd82c61b3355073712d994fe2360975c9ad9e1', 'scripts/ralph_tui.py': '7dd2d09681e4e1a2afe6be535010a39774bb369aed7e111c5dc1cf33726bbcf1', 'scripts/ralph_web.py': '5b0208e0791690a511a4e3f65d31a4809651ca9ef92aa49c6f1035b6afd58a01'}, 'controller_tests': {'tests/test_ralph_carry_forward_reconciliation.py': '9da855c867f736229c10d7ea4e190b4b41049d9ce9814eae3425c6f1d48a7e1e', 'tests/test_ralph_controller_adoption_coverage.py': '00fd3eedf0304189e91a632b984106820e6cdc19da29824618c4990362cf6af6', 'tests/test_ralph_efficiency.py': '5daf142c3b0619ca52de8d235c6909565bd93412d725df1d0884947b39bbb0e9', 'tests/test_ralph_equivalence.py': 'd37541dc0fdd29a1a2df4e4202249c017e4617bb0cad74be272a09cd7148341d', 'tests/test_ralph_gate.py': '035598d5c05b6e6357eab2ea6979153eb46f205756f62fdfabe2b46d766265aa', 'tests/test_ralph_lifecycle.py': '5ceec9149446441414d7be5bb055d8f32296d4dea472563f8ab40da3e807d032', 'tests/test_ralph_lite.py': '4efd957c3a9e78ca3dadfa3bcee96104b0b611d89efdef0254625fee9d8a08f3', 'tests/test_ralph_model.py': '2e8ca719415096b3f9c4a3e34e0cc686c8b79810aed09b2b39a72a64d2611e0f', 'tests/test_ralph_plan_bounds.py': '11dab2f1193412d53d3ffbffc07c673ade73ec291a1f4df4348610ca6e9bc25e', 'tests/test_ralph_profile_boundary.py': '9553bd244865d0fc9934d4db6591fada4daab00303def9c71e138368766c7bd1', 'tests/test_ralph_reconciliation_lifecycle.py': 'a16b79190d57ee12904c1b35ab798e05c81d537766eeae73d21235c825d98837', 'tests/test_ralph_replacement_inventory.py': 'bab30fb3f3c406d46880f0fe2a6378e14aec86e8cb9496034115bbb03f214896', 'tests/test_ralph_retry_hardening.py': '5d641eaf0095613b32fd4669b1474c98067b0dd08b49f567a7142d34537b4d7e', 'tests/test_ralph_self_hosting.py': '1266e5f13aee3812fffcc9a2acf36ea0194de6f125610fe376cc550d98b8692e', 'tests/test_ralph_strict_output_schema.py': '9450879379b527ebe9bd33f0ab72148fba4e69e9bcab2d57f9f153f45ff913ac', 'tests/test_ralph_web.py': 'c47b43d76f27f1c61877253fdd8523a0b04f8870ff34ca54c8fbb08a3a4802e5', 'tests/test_ralph_web_adoption_coverage.py': 'd6f360162170961f5dabfd8b0799383918f5e196a3164a123432b04e5b7e3907', 'tests/test_ralph_web_gate_profile_boundary.py': '54d3de05166ab8b60cdc1d1634bc904facf1eb440492be9f6e9266f0d63f2576', 'tests/test_ralph_web_live_refresh.py': '40325645d93ec23e5ffcbfe5974d33afb52c4f1ea282545a27dc10919ff62c14', 'tests/test_ralph_web_plan_bounds.py': '3bb4e48dcae3b16398684ec6c84f0c57a52c337f692b20311d5b9a050366df3d', 'tests/test_ralph_web_retirement_rendering.py': 'cc2d7f1107a1bcf88f3b4d5fa4f732a6d3b43374b925fb0ddcec4470f9dd3634'}, 'host_qualification': {'.ralph/policy.md': '9d9fa1b732abb7006a7ffb506da7e265c419632ae76e352cf7034500fdb42320', 'scripts/ux_validate.py': 'ba65436bedf9710ddd1adf214c2bd5b23e269a045cdf951fe11e6d975722fde9', 'scripts/env_validate.py': '0cef3d0ac829b92705ceeb4ca8381516817ed625b8eb6f7b5e1c0ec559b02b9e', 'scripts/supply_chain_validate.py': '855fce169d40c1ecbe6f2232e5443c06659cd67b00917a584f3769f343d666f8', 'scripts/public_release_audit.py': 'cb5fcbe9540349677a09dbe0f0f0c599288e1fb89d4c324c157e77e9b27a6833'}}, 'behavioral_equivalence': {'schema': 'ralph_behavioral_equivalence_v1', 'reference_sha256': '1f27dc78a5a8405d7e28dd83e5f1e7604d1169c940e65efe10f3a8e257fe14b0', 'validator': 'scripts/ralph_equivalence.py --validate'}, 'compatibility': {'state_schema': 'zen_ralph_lite_state_v1', 'context_schema': 'zen_ralph_lite_context_v1', 'operation_attribution_schema': 'zen_ralph_operation_attribution_v2', 'proposal_previous_state_schema': 'zen_ralph_proposal_previous_state_v1', 'interrupted_run_recovery_schema': 'zen_ralph_interrupted_run_recovery_v1', 'retirement_schema': 'zen_ralph_retirement_v4', 'retirement_legacy_schema': 'zen_ralph_retirement_v3', 'efficiency_policy_schema': 'zen_ralph_efficiency_policy_v2', 'model_policy_schema': 'zen_ralph_model_policy_v2', 'runtime_directory': '.ralph', 'host_identity': 'ZEN Control'}, 'qualification': {'step_gate_names': ['python-compile', 'unit-tests', 'ux-validator'], 'final_gate_names': ['environment', 'supply-chain', 'public-audit', 'diff-check'], 'required_local_checks': ['python3 scripts/ralph_equivalence.py --validate', 'python3 -m unittest tests.test_ralph_equivalence']}, 'extraction_constraints': {'required_invariants': ['D0 read-only and repository mutation authority', 'D0.1 attribution and rollback', 'D0.1a CLI/Web runtime and authority parity', 'D1 authority closure', 'D2 retirement and dirty-tree disposition', 'D3 lifecycle and recovery integrity', 'D4 generic ProjectProfile boundary', 'D5 behavioral equivalence oracle'], 'allowed_host_coupling': ['ZEN_PROFILE is the current ProjectProfile adapter', 'zen_ralph_* persisted schemas remain compatibility contracts', '.ralph remains the current host runtime directory', 'RouterOS/incident/performance wording is profile-owned host policy'], 'excluded_from_d6': ['physical Stygnox extraction', 'product rename', 'persisted-schema migration', 'future runtime protocol', 'packaging or installer work', 'plugin loader', 'non-Git backend', 'Fast Lane feature implementation']}}
FROZEN_MANIFEST["compatibility"].update({
    "project_profile_adapter": "ZEN_PROFILE",
    "persisted_schema_identifiers": PERSISTED_SCHEMA_IDENTIFIERS,
})
FROZEN_MANIFEST_SHA256 = "5d66815fe07faf73e75fcffbb2a64a6258e122d7687c05771777aba90e5e8708"


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory_paths() -> list[str]:
    inventory = FROZEN_MANIFEST["inventory"]
    return sorted(path for group in inventory.values() for path in group)


def source_tree_sha256(root: Path = ROOT) -> str:
    rows: list[bytes] = []
    for relative in inventory_paths():
        path = root / relative
        digest = sha256_file(path) if path.is_file() else "<missing>"
        rows.append(f"{relative}\0{digest}\n".encode("utf-8"))
    return hashlib.sha256(b"".join(rows)).hexdigest()


def observed_compatibility() -> dict[str, Any]:
    return {
        "state_schema": ralph.default_state()["schema"],
        "context_schema": ralph.default_context()["schema"],
        "operation_attribution_schema": ralph.OPERATION_ATTRIBUTION_SCHEMA,
        "proposal_previous_state_schema": ralph.PROPOSAL_PREVIOUS_STATE_SCHEMA,
        "interrupted_run_recovery_schema": ralph.INTERRUPTED_RUN_RECOVERY_SCHEMA,
        "retirement_schema": ralph.RETIREMENT_MANIFEST_SCHEMA,
        "retirement_legacy_schema": ralph.RETIREMENT_MANIFEST_LEGACY_SCHEMA,
        "efficiency_policy_schema": ralph_efficiency.SCHEMA,
        "model_policy_schema": ralph_model.SCHEMA,
        "runtime_directory": PROJECT_PROFILE.runtime_dir_name,
        "host_identity": PROJECT_PROFILE.identity,
        "project_profile_adapter": "ZEN_PROFILE" if PROJECT_PROFILE is ZEN_PROFILE else "other",
        "persisted_schema_identifiers": sorted({
            name
            for relative in inventory_paths()
            for name in SCHEMA_IDENTIFIER.findall((ROOT / relative).read_text(encoding="utf-8"))
        }),
    }


def observed_qualification() -> dict[str, Any]:
    step_names = [name for name, _ in PROJECT_PROFILE.qualification_gates(ROOT, sys.executable)]
    final_names = [name for name, _ in PROJECT_PROFILE.final_validator_gates(ROOT, sys.executable)] + ["diff-check"]
    return {
        "step_gate_names": step_names,
        "final_gate_names": final_names,
        "required_local_checks": list(FROZEN_MANIFEST["qualification"]["required_local_checks"]),
    }


def differences(root: Path = ROOT) -> list[str]:
    found: list[str] = []
    expected_inventory = FROZEN_MANIFEST["inventory"]
    for group in ("controller_sources", "controller_tests", "host_qualification"):
        for relative, expected in sorted(expected_inventory[group].items()):
            path = root / relative
            if not path.is_file():
                found.append(f"$.inventory.{group}.{relative}: missing")
            else:
                actual = sha256_file(path)
                if actual != expected:
                    found.append(f"$.inventory.{group}.{relative}: sha256 {actual} != {expected}")
            if len(found) >= MAX_DIFFERENCES:
                return found

    expected_tree = FROZEN_MANIFEST["baseline"]["source_tree_sha256"]
    actual_tree = source_tree_sha256(root)
    if actual_tree != expected_tree:
        found.append(f"$.baseline.source_tree_sha256: {actual_tree} != {expected_tree}")

    expected_compatibility = FROZEN_MANIFEST["compatibility"]
    actual_compatibility = observed_compatibility()
    for key in sorted(expected_compatibility):
        if actual_compatibility.get(key) != expected_compatibility[key]:
            found.append(f"$.compatibility.{key}: {actual_compatibility.get(key)!r} != {expected_compatibility[key]!r}")

    expected_qualification = FROZEN_MANIFEST["qualification"]
    actual_qualification = observed_qualification()
    for key in ("step_gate_names", "final_gate_names", "required_local_checks"):
        if actual_qualification[key] != expected_qualification[key]:
            found.append(f"$.qualification.{key}: {actual_qualification[key]!r} != {expected_qualification[key]!r}")

    if ralph_equivalence.SCHEMA != FROZEN_MANIFEST["behavioral_equivalence"]["schema"]:
        found.append("$.behavioral_equivalence.schema: drift")
    if ralph_equivalence.FROZEN_CONTRACT_SHA256 != FROZEN_MANIFEST["behavioral_equivalence"]["reference_sha256"]:
        found.append("$.behavioral_equivalence.reference_sha256: drift")
    eq_differences = ralph_equivalence.compare(ralph_equivalence.wrap(ralph_equivalence.observe_contract()))
    for item in eq_differences:
        found.append(f"$.behavioral_equivalence.current{item[1:] if item.startswith('$') else '.' + item}")
        if len(found) >= MAX_DIFFERENCES:
            return found

    for relative in sorted(expected_inventory["controller_sources"]):
        if not ralph.is_tooling_path(relative):
            found.append(f"$.inventory.controller_sources.{relative}: no longer classified tooling")
    for relative in sorted(expected_inventory["controller_tests"]):
        if not ralph.is_tooling_path(relative):
            found.append(f"$.inventory.controller_tests.{relative}: no longer classified tooling")

    return found[:MAX_DIFFERENCES]


def validation_result(root: Path = ROOT) -> dict[str, Any]:
    issues = differences(root)
    return {
        "schema": SCHEMA,
        "ok": not issues,
        "manifest_sha256": hashlib.sha256(canonical_bytes(FROZEN_MANIFEST)).hexdigest(),
        "source_tree_sha256": source_tree_sha256(root),
        "behavioral_equivalence_sha256": ralph_equivalence.FROZEN_CONTRACT_SHA256,
        "differences": issues,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--manifest", action="store_true")
    mode.add_argument("--validate", action="store_true")
    args = parser.parse_args(argv)

    if args.manifest:
        print(canonical_bytes(FROZEN_MANIFEST).decode("utf-8"))
        return 0

    result = validation_result()
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["ok"] and result["manifest_sha256"] == FROZEN_MANIFEST_SHA256 else 1


if __name__ == "__main__":
    raise SystemExit(main())
