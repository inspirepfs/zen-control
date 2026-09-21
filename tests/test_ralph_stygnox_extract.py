import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import ralph_ex_ready
import ralph_stygnox_extract as extract


class StygnoxExtractionSeedTests(unittest.TestCase):
    def test_seed_contract_is_bound_to_d6_and_d5(self):
        manifest = extract.seed_manifest()
        self.assertEqual("stygnox_extraction_seed_v1", manifest["schema"])
        self.assertEqual(ralph_ex_ready.FROZEN_MANIFEST_SHA256, manifest["source"]["d6_manifest_sha256"])
        self.assertEqual(
            ralph_ex_ready.FROZEN_MANIFEST["baseline"]["source_tree_sha256"],
            manifest["source"]["d6_source_tree_sha256"],
        )
        self.assertEqual(extract.D5_EQUIVALENCE_SHA256, manifest["source"]["d5_behavioral_equivalence_sha256"])
        self.assertEqual(8 + 21 + 3, len(manifest["content"]["copied_files"]))
        self.assertEqual(4, len(manifest["content"]["generated_files"]))

    def test_materialized_seed_is_exact_minimal_and_valid(self):
        watched = {
            relative: (ROOT / relative).read_bytes()
            for relative in extract._frozen_source_map()
        }
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "stygnox"
            manifest = extract.materialize(target)
            result = extract.validation_result(target)
            self.assertTrue(result["ok"], result["differences"])
            self.assertTrue((target / "README.md").is_file())
            self.assertTrue((target / "LICENSE").is_file())
            self.assertTrue((target / ".ralph/policy.md").is_file())
            self.assertTrue((target / "provenance/d6-ex-ready-manifest.json").is_file())
            self.assertFalse((target / "app").exists())
            self.assertFalse((target / "routeros").exists())
            self.assertFalse((target / "docker-compose.yml").exists())
            for relative, expected in manifest["content"]["copied_files"].items():
                self.assertEqual(expected, hashlib.sha256((target / relative).read_bytes()).hexdigest(), relative)
            self.assertEqual([], extract.differences(target))
        self.assertEqual(watched, {relative: (ROOT / relative).read_bytes() for relative in watched})

    def test_seed_preserves_known_compatibility_seams_without_adopting_zen_product(self):
        manifest = extract.seed_manifest()
        seams = "\n".join(manifest["constraints"]["known_compatibility_seams"])
        self.assertIn("ZEN_PROFILE", seams)
        self.assertIn(".ralph", seams)
        self.assertIn("zen_ralph_*", seams)
        self.assertIn("RALPH-Lite", seams)
        self.assertIn("Stygnox", extract.README_TEXT)
        self.assertIn("not a public release", extract.README_TEXT)
        self.assertNotIn("ZEN Control's supervised", extract.README_TEXT)

    def test_validator_reports_bounded_drift_and_unexpected_files(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "stygnox"
            extract.materialize(target)
            changed = target / "scripts/ralph.py"
            changed.write_bytes(changed.read_bytes() + b"\n# drift\n")
            extra = target / "app/should-not-exist.py"
            extra.parent.mkdir(parents=True)
            extra.write_text("bad = True\n", encoding="utf-8")
            issues = extract.differences(target)
            self.assertTrue(any("scripts/ralph.py" in issue and "sha256" in issue for issue in issues), issues)
            self.assertTrue(any("app/should-not-exist.py" in issue and "unexpected" in issue for issue in issues), issues)
            self.assertLessEqual(len(issues), extract.MAX_DIFFERENCES)

    def test_refuses_output_inside_source_or_nonempty_destination(self):
        with self.assertRaisesRegex(RuntimeError, "inside the source repository"):
            extract.materialize(ROOT / ".stygnox-seed-test")
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "stygnox"
            target.mkdir()
            (target / "keep.txt").write_text("operator data\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "not empty"):
                extract.materialize(target)
            self.assertEqual("operator data\n", (target / "keep.txt").read_text(encoding="utf-8"))

    def test_cli_manifest_write_validate_and_no_external_execution_dependency(self):
        source = (ROOT / "scripts/ralph_stygnox_extract.py").read_text(encoding="utf-8")
        for forbidden in ("import subprocess", "import requests", "import socket", "import urllib", "git_command(", "run_codex(", "save_state(", "live_write("):
            self.assertNotIn(forbidden, source)
        emitted = subprocess.run(
            [sys.executable, "scripts/ralph_stygnox_extract.py", "--manifest"],
            cwd=ROOT, text=True, capture_output=True,
        )
        self.assertEqual(0, emitted.returncode, emitted.stdout + emitted.stderr)
        self.assertEqual(extract.seed_manifest(), json.loads(emitted.stdout))
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "stygnox"
            written = subprocess.run(
                [sys.executable, "scripts/ralph_stygnox_extract.py", "--write", str(target)],
                cwd=ROOT, text=True, capture_output=True,
            )
            self.assertEqual(0, written.returncode, written.stdout + written.stderr)
            self.assertTrue(json.loads(written.stdout)["ok"])
            validated = subprocess.run(
                [sys.executable, "scripts/ralph_stygnox_extract.py", "--validate", str(target)],
                cwd=ROOT, text=True, capture_output=True,
            )
            self.assertEqual(0, validated.returncode, validated.stdout + validated.stderr)
            self.assertTrue(json.loads(validated.stdout)["ok"])


if __name__ == "__main__":
    unittest.main()
