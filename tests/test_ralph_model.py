from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "ralph_model.py"
spec = importlib.util.spec_from_file_location("ralph_model_test_module", MODULE_PATH)
model = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(model)


class ModelPolicyTests(unittest.TestCase):
    def test_default_uses_codex_default(self):
        policy = model.normalize_policy(None)
        self.assertIsNone(policy["model"])
        self.assertEqual(policy["schema"], "zen_ralph_model_policy_v1")

    def test_override_is_atomically_persisted_and_revisioned(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            first = model.load_policy(root)
            selected = model.save_policy(root, "gpt-5.6-terra")
            loaded = model.load_policy(root)
            self.assertIsNone(first["model"])
            self.assertEqual(selected["model"], "gpt-5.6-terra")
            self.assertEqual(loaded["model"], "gpt-5.6-terra")
            self.assertGreater(selected["revision"], first["revision"])
            self.assertFalse((root / ".ralph" / "model-policy.json.tmp").exists())

    def test_reset_to_none_restores_codex_default_semantics(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            model.save_policy(root, "gpt-5.6-terra")
            reset = model.save_policy(root, None)
            self.assertIsNone(reset["model"])
            self.assertIsNone(model.load_policy(root)["model"])

    def test_model_identifier_rejects_whitespace_and_excessive_length(self):
        with self.assertRaisesRegex(ValueError, "single model identifier"):
            model.normalize_policy({"model": "gpt model"})
        with self.assertRaisesRegex(ValueError, "single model identifier"):
            model.normalize_policy({"model": "x" * 161})


if __name__ == "__main__":
    unittest.main()
