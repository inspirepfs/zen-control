from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path


MODULE = Path(__file__).resolve().parents[1] / "scripts" / "ralph.py"
spec = importlib.util.spec_from_file_location("ralph_replacement_inventory", MODULE)
ralph = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(ralph)


class ReplacementInventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)
        subprocess.run(["git", "config", "user.email", "ralph@example.invalid"], cwd=self.root, check=True)
        subprocess.run(["git", "config", "user.name", "RALPH Test"], cwd=self.root, check=True)
        (self.root / "app.py").write_text("before\n", encoding="utf-8")
        subprocess.run(["git", "add", "app.py"], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-qm", "baseline"], cwd=self.root, check=True)
        self.old_root = ralph.ROOT
        ralph.ROOT = self.root

    def tearDown(self):
        ralph.ROOT = self.old_root
        self.tmp.cleanup()

    def manifest(self, *paths: str) -> dict:
        records = []
        for path in paths:
            evidence = ralph.retirement_path_fingerprint(path)
            records.append({"path": path, "baseline": "tracked", "plan_owned": False, "current": evidence["kind"], "unexpected": False, "evidence": evidence})
        return {"id": "RT-20260918T000000Z-abcdef123456", "paths": records, "repository_after": {"snapshot-only.py": "digest"}}

    def test_records_manifest_bound_and_snapshot_only_dirty_paths(self):
        (self.root / "app.py").write_text("retained\n", encoding="utf-8")
        manifest = self.manifest("app.py")
        (self.root / "snapshot-only.py").write_text("residue\n", encoding="utf-8")
        items = {item["path"]: item for item in ralph.replacement_dirty_inventory(manifest)}
        self.assertEqual(items["app.py"]["classification"], "MANIFEST_BOUND_UNCHANGED")
        self.assertEqual(items["app.py"]["disposition"], "PENDING_RECONCILIATION")
        self.assertEqual(items["snapshot-only.py"]["classification"], "SNAPSHOT_ONLY_EXTERNAL_RECONCILIATION")
        self.assertEqual(items["snapshot-only.py"]["disposition"], "REJECTED_EXTERNAL_RECONCILIATION_REQUIRED")

    def test_excludes_controller_runtime_paths_from_replacement_inventory(self):
        (self.root / "app.py").write_text("retained\n", encoding="utf-8")
        runtime = self.root / ".ralph" / "state.json"
        runtime.parent.mkdir(parents=True, exist_ok=True)
        runtime.write_text('{"status":"APPROVED"}\n', encoding="utf-8")
        items = {item["path"]: item for item in ralph.replacement_dirty_inventory(self.manifest("app.py"))}
        self.assertIn("app.py", items)
        self.assertNotIn(".ralph/state.json", items)

    def test_fails_closed_for_changed_forged_and_protected_evidence(self):
        (self.root / "app.py").write_text("retained\n", encoding="utf-8")
        manifest = self.manifest("app.py")
        (self.root / "app.py").write_text("changed\n", encoding="utf-8")
        (self.root / ".env").write_text("SECRET=never-read\n", encoding="utf-8")
        items = {item["path"]: item for item in ralph.replacement_dirty_inventory(manifest)}
        self.assertEqual(items["app.py"]["classification"], "MANIFEST_BOUND_CHANGED_NON_ADOPTABLE")
        self.assertFalse(items["app.py"]["eligible"])
        self.assertEqual(items[".env"]["classification"], "PROTECTED_NON_ADOPTABLE")

    def test_binding_detects_forged_or_mismatched_current_evidence(self):
        (self.root / "app.py").write_text("retained\n", encoding="utf-8")
        manifest = self.manifest("app.py")
        recorded = ralph.replacement_dirty_inventory(manifest)
        forged = [dict(item) for item in recorded]
        forged[0]["current_evidence"] = dict(forged[0]["current_evidence"], fingerprint="forged")
        self.assertNotEqual(
            [ralph.replacement_inventory_binding(item) for item in forged],
            [ralph.replacement_inventory_binding(item) for item in ralph.replacement_dirty_inventory(manifest)],
        )
