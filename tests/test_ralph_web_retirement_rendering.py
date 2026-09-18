from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("ralph_web_retirement_rendering", ROOT / "scripts" / "ralph_web.py")
web = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = web
spec.loader.exec_module(web)


class RetirementRenderingTests(unittest.TestCase):
    def test_page_renders_controller_retirement_provenance_and_explicit_disposition(self):
        self.assertIn("Retirement provenance", web.PAGE)
        self.assertIn("manifest SHA-256", web.PAGE)
        self.assertIn("Preview exact rollback paths", web.PAGE)
        self.assertIn("Confirm rollback (ROLLBACK)", web.PAGE)
        self.assertIn("Confirm carry-forward (CARRY_FORWARD)", web.PAGE)
        self.assertIn("Start replacement plan from", web.PAGE)
        self.assertIn("latestSnapshot?.latest_retirement?.record_id", web.PAGE)

    def test_page_renders_controller_reconciliation_classifications_and_refusal_disabled_state(self):
        self.assertIn("Per-path reconciliation", web.PAGE)
        self.assertIn("Classification:", web.PAGE)
        self.assertIn("Leave outside boundary", web.PAGE)
        self.assertIn("Mark externally required", web.PAGE)
        self.assertIn("Controller classification is display-only; no action is available.", web.PAGE)
        self.assertIn("Controller refused reconciliation state", web.PAGE)
        self.assertIn("All reconciliation actions are disabled", web.PAGE)

    def test_page_identifies_ready_to_commit_provenance_blockers(self):
        self.assertIn("READY_TO_COMMIT provenance blockers", web.PAGE)
        self.assertIn("Blocking unresolved controller reconciliation paths", web.PAGE)
        self.assertIn("Blocking controller refusal", web.PAGE)
