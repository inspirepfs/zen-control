import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import ralph_equivalence as eq

EXPECTED_REFERENCE_SHA256 = "1f27dc78a5a8405d7e28dd83e5f1e7604d1169c940e65efe10f3a8e257fe14b0"


class RalphEquivalenceTests(unittest.TestCase):
    def test_frozen_literal_digest_and_current_equivalence(self):
        self.assertEqual(EXPECTED_REFERENCE_SHA256, eq.FROZEN_CONTRACT_SHA256)
        self.assertEqual(EXPECTED_REFERENCE_SHA256, hashlib.sha256(eq.canonical_bytes(eq.FROZEN_CONTRACT)).hexdigest())
        self.assertEqual([], eq.compare(eq.wrap(eq.observe_contract())))

    def test_required_groups_and_extraction_critical_scenarios(self):
        contract = eq.observe_contract()
        self.assertEqual(set(eq.FROZEN_CONTRACT), set(contract))
        self.assertEqual("read-only", contract["plan_authority"]["read_only_sandbox"])
        self.assertEqual("workspace-write", contract["plan_authority"]["write_sandbox"])
        self.assertTrue(contract["path_tooling_protected_authority"]["runtime"])
        self.assertEqual([], contract["test_change_policy"]["modify"])
        self.assertEqual("IDLE", contract["lifecycle"]["default_status"])
        self.assertEqual("HG-0023-02", contract["human_gate_semantics"]["stable_id"])
        self.assertTrue(contract["human_gate_semantics"]["runtime_confirmable"])
        self.assertFalse(contract["human_gate_semantics"]["policy_confirmable"])

    def test_observer_is_read_only_and_has_no_external_git_model_codex_path(self):
        before = {path: path.read_bytes() for path in (ROOT / "scripts" / "ralph_equivalence.py", ROOT / "tests" / "test_ralph_equivalence.py")}
        eq.observe_contract()
        self.assertEqual(before, {path: path.read_bytes() for path in before})
        source = (ROOT / "scripts" / "ralph_equivalence.py").read_text(encoding="utf-8")
        for forbidden in ("subprocess", "git", "codex", "requests", "urllib", "socket"):
            self.assertNotIn(forbidden, source.lower())

    def test_schema_digest_and_bounded_nested_drift_rejection(self):
        candidate = eq.frozen_reference()
        candidate = json.loads(json.dumps(candidate))
        candidate["contract"]["lifecycle"]["default_status"] = "DRIFT"
        candidate["contract_sha256"] = hashlib.sha256(eq.canonical_bytes(candidate["contract"])).hexdigest()
        self.assertIn("$.contract.lifecycle.default_status", "\n".join(eq.compare(candidate)))
        self.assertTrue(eq.compare({"schema": eq.SCHEMA, "contract": {}, "contract_sha256": "bad"}))
        self.assertLessEqual(len(eq.differences({str(i): i for i in range(100)}, {})), eq.MAX_DIFFERENCES)

    def test_cli_comparison_exit_behavior(self):
        reference = json.dumps(eq.frozen_reference())
        ok = subprocess.run([sys.executable, "scripts/ralph_equivalence.py", "--compare", reference], cwd=ROOT, text=True, capture_output=True)
        bad = subprocess.run([sys.executable, "scripts/ralph_equivalence.py", "--compare", "{}"], cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(0, ok.returncode)
        self.assertEqual(1, bad.returncode)
