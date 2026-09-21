import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import ralph_ex_ready as ex

EXPECTED_MANIFEST_SHA256 = "5d66815fe07faf73e75fcffbb2a64a6258e122d7687c05771777aba90e5e8708"
EXPECTED_SOURCE_TREE_SHA256 = "db426756ec6da3eda05fbd7cf520ae76c9264fb1e7817afb5f24a4b3f794ac1e"
EXPECTED_EQUIVALENCE_SHA256 = "1f27dc78a5a8405d7e28dd83e5f1e7604d1169c940e65efe10f3a8e257fe14b0"


class RalphExReadyTests(unittest.TestCase):
    def test_frozen_manifest_digest_inventory_and_current_validation(self):
        self.assertEqual("ralph_ex_ready_freeze_v1", ex.SCHEMA)
        self.assertEqual(EXPECTED_MANIFEST_SHA256, ex.FROZEN_MANIFEST_SHA256)
        self.assertEqual(EXPECTED_MANIFEST_SHA256, hashlib.sha256(ex.canonical_bytes(ex.FROZEN_MANIFEST)).hexdigest())
        self.assertEqual(EXPECTED_SOURCE_TREE_SHA256, ex.source_tree_sha256())
        self.assertEqual(8, len(ex.FROZEN_MANIFEST["inventory"]["controller_sources"]))
        self.assertEqual(21, len(ex.FROZEN_MANIFEST["inventory"]["controller_tests"]))
        self.assertEqual(5, len(ex.FROZEN_MANIFEST["inventory"]["host_qualification"]))
        result = ex.validation_result()
        self.assertTrue(result["ok"], result["differences"])
        self.assertEqual(EXPECTED_EQUIVALENCE_SHA256, result["behavioral_equivalence_sha256"])

    def test_manifest_records_extraction_boundary_and_compatibility_obligations(self):
        manifest = ex.FROZEN_MANIFEST
        self.assertEqual("dab5068", manifest["baseline"]["source_label"])
        self.assertEqual("ZEN Control", manifest["compatibility"]["host_identity"])
        self.assertEqual(".ralph", manifest["compatibility"]["runtime_directory"])
        self.assertIn("zen_ralph_operation_attribution_v2", manifest["compatibility"].values())
        self.assertEqual(31, len(manifest["compatibility"]["persisted_schema_identifiers"]))
        self.assertEqual(
            manifest["compatibility"]["persisted_schema_identifiers"],
            ex.observed_compatibility()["persisted_schema_identifiers"],
        )
        self.assertIn("physical Stygnox extraction", manifest["extraction_constraints"]["excluded_from_d6"])
        self.assertIn("D5 behavioral equivalence oracle", manifest["extraction_constraints"]["required_invariants"])
        self.assertEqual(["python-compile", "unit-tests", "ux-validator"], manifest["qualification"]["step_gate_names"])
        self.assertEqual(["environment", "supply-chain", "public-audit", "diff-check"], manifest["qualification"]["final_gate_names"])

    def test_every_frozen_controller_path_is_structural_tooling(self):
        import ralph
        inventory = ex.FROZEN_MANIFEST["inventory"]
        for group in ("controller_sources", "controller_tests"):
            for path in inventory[group]:
                self.assertTrue(ralph.is_tooling_path(path), path)

    def test_validation_detects_bounded_source_drift_without_mutating_repository(self):
        before = {path: (ROOT / path).read_bytes() for path in ex.inventory_paths()}
        with tempfile.TemporaryDirectory() as td:
            replica = Path(td)
            for relative in ex.inventory_paths():
                target = replica / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / relative).read_bytes())
            tampered = replica / "scripts/ralph_equivalence.py"
            tampered.write_bytes(tampered.read_bytes() + b"\n# drift\n")
            issues = ex.differences(replica)
            self.assertTrue(any("scripts/ralph_equivalence.py" in issue for issue in issues))
            self.assertLessEqual(len(issues), ex.MAX_DIFFERENCES)
        self.assertEqual(before, {path: (ROOT / path).read_bytes() for path in before})

    def test_cli_validate_and_manifest_are_read_only(self):
        before = {path: (ROOT / path).read_bytes() for path in ex.inventory_paths()}
        validated = subprocess.run([sys.executable, "scripts/ralph_ex_ready.py", "--validate"], cwd=ROOT, text=True, capture_output=True)
        emitted = subprocess.run([sys.executable, "scripts/ralph_ex_ready.py", "--manifest"], cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(0, validated.returncode, validated.stdout + validated.stderr)
        self.assertTrue(json.loads(validated.stdout)["ok"])
        self.assertEqual(ex.FROZEN_MANIFEST, json.loads(emitted.stdout))
        self.assertEqual(before, {path: (ROOT / path).read_bytes() for path in before})

    def test_validator_has_no_external_or_mutating_execution_dependency(self):
        source = (ROOT / "scripts/ralph_ex_ready.py").read_text(encoding="utf-8")
        for forbidden_import in ("import subprocess", "import requests", "import socket", "import urllib"):
            self.assertNotIn(forbidden_import, source)
        for forbidden_call in ("run_codex(", "save_state(", "live_write(", "git_command("):
            self.assertNotIn(forbidden_call, source)


if __name__ == "__main__":
    unittest.main()
