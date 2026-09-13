import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from app.release_readiness import build_release_readiness

ROOT = Path(__file__).resolve().parents[1]


def ready_inputs():
    return {
        "version": "0.55.2",
        "operations": {"ok": True, "issues": []},
        "startup": {"status": "ready", "issues": []},
        "diagnostics": {
            "overall": "healthy",
            "counts": {"healthy": 15, "warning": 0, "critical": 0, "offline": 0},
            "checks": [],
        },
        "performance": {
            "acceptance": {
                "schema": "zen_performance_acceptance_v2",
                "state": "pass",
                "targets": [{"key": "navigation", "state": "pass"}],
                "min_samples": 5,
            },
            "formal_acceptance": {
                "schema": "zen_formal_performance_acceptance_v1",
                "state": "pass",
                "request_state": "pass",
                "evidence_targets": [
                    {"key": "threshold_profile", "label": "Canonical acceptance thresholds", "state": "pass"},
                    {"key": "prepared_views", "label": "Prepared-view effectiveness", "state": "pass"},
                    {"key": "background_worker", "label": "Background worker timing", "state": "pass"},
                    {"key": "parallel_observation", "label": "Parallel observation utilisation", "state": "pass"},
                    {"key": "mutation_lane", "label": "Serialized mutation-lane contention", "state": "pass"},
                ],
            },
        },
        "config_smoke": {
            "state": "pass", "non_destructive": True, "source_digest": "x", "restored_digest": "x", "summary": "ok"
        },
        "restart": {
            "state": "pass", "controlled_stop_seen": True, "current_release_start_seen": True, "summary": "ok"
        },
        "auth": {
            "available": True, "shared_display_mode": True, "totp_count": 1,
            "login_mode": "password_or_totp", "recovery_codes_remaining": 5,
        },
        "pwa": {
            "mode": "online_first", "cached_private_data": False, "offline_mutations": False,
            "background_sync": False, "push_notifications": False, "server_auth_required": True,
            "shared_display_lock_server_enforced": True,
        },
        "runtime_health": {"schema": "zen_runtime_health_v1", "ok": True, "status": "healthy"},
    }


class FinalReleaseReadinessContractTests(unittest.TestCase):
    def test_exact_eight_pass_gate_is_final_ready(self):
        report = build_release_readiness(**ready_inputs())
        self.assertEqual("zen_release_readiness_v2", report["schema"])
        self.assertEqual(8, report["required_check_count"])
        self.assertEqual(8, len(report["checks"]))
        self.assertEqual({"pass": 8, "pending": 0, "fail": 0}, report["counts"])
        self.assertEqual("pass", report["state"])
        self.assertTrue(report["final_ready"])

    def test_request_only_performance_pass_cannot_manufacture_final_pass(self):
        values = ready_inputs()
        values["performance"].pop("formal_acceptance")
        report = build_release_readiness(**values)
        row = next(item for item in report["checks"] if item["key"] == "live_performance")
        self.assertEqual("pending", row["state"])
        self.assertEqual("pending", report["state"])
        self.assertFalse(report["final_ready"])

    def test_formal_runtime_evidence_pending_is_attributed(self):
        values = ready_inputs()
        values["performance"]["formal_acceptance"]["state"] = "pending"
        values["performance"]["formal_acceptance"]["evidence_targets"][1]["state"] = "pending"
        report = build_release_readiness(**values)
        row = next(item for item in report["checks"] if item["key"] == "live_performance")
        findings = row["evidence"]["findings"]
        self.assertEqual("pending", row["state"])
        self.assertEqual(["prepared_views"], [item["key"] for item in findings])

    def test_formal_failure_blocks_release_even_when_request_latency_passes(self):
        values = ready_inputs()
        values["performance"]["formal_acceptance"]["state"] = "fail"
        values["performance"]["formal_acceptance"]["evidence_targets"][0]["state"] = "fail"
        report = build_release_readiness(**values)
        self.assertEqual("fail", report["state"])
        self.assertFalse(report["final_ready"])

    def test_missing_embedded_runtime_health_is_pending(self):
        values = ready_inputs()
        values["runtime_health"] = None
        report = build_release_readiness(**values)
        row = next(item for item in report["checks"] if item["key"] == "runtime_readiness")
        self.assertEqual("pending", row["state"])
        self.assertEqual("pending", report["state"])

    def test_dead_embedded_worker_blocks_release(self):
        values = ready_inputs()
        values["runtime_health"] = {"schema": "zen_runtime_health_v1", "ok": False, "status": "degraded"}
        report = build_release_readiness(**values)
        row = next(item for item in report["checks"] if item["key"] == "runtime_readiness")
        self.assertEqual("fail", row["state"])
        self.assertEqual("fail", report["state"])

    def test_closure_matrix_reaches_formal_performance_slice(self):
        report = build_release_readiness(**ready_inputs())
        versions = {row["closed_in"] for row in report["closure_matrix"]}
        for version in {"0.53.1", "0.54.0", "0.54.1", "0.54.2", "0.54.3", "0.54.4"}:
            self.assertIn(version, versions)


class FinalReleaseReadinessSourceTests(unittest.TestCase):
    def test_live_readiness_uses_formal_performance_and_runtime_health(self):
        main = (ROOT / "app/main.py").read_text(encoding="utf-8")
        block = main.split("def current_release_readiness()", 1)[1].split("@app.on_event", 1)[0]
        self.assertIn("current_performance_snapshot()", block)
        self.assertIn("build_runtime_health(", block)
        self.assertIn("runtime_health=runtime_health", block)

    def test_release_page_declares_exact_final_target(self):
        template = (ROOT / "app/templates/release_readiness.html").read_text(encoding="utf-8")
        self.assertIn("Final release readiness", template)
        self.assertIn("PASS 8 · PENDING 0 · FAIL 0", template)
        self.assertIn("Formal performance evidence still requiring closure", template)

    def test_version_and_docs_move_to_v0545(self):
        main = (ROOT / "app/main.py").read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn('version="0.58.0"', main)
        self.assertIn("Current release: **v0.58.0**", readme)
        self.assertIn("## v0.54.5 — Final release-readiness closure", changelog)
        self.assertIn("## v0.54.5.1 — RouterOS request-path decoupling", changelog)


class ReleaseAcceptanceCliV2Tests(unittest.TestCase):
    def _run(self, report):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "readiness.json"
            path.write_text(json.dumps(report), encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(ROOT / "scripts/release_acceptance.py"), str(path)],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
            )

    def test_cli_accepts_exact_eight_pass_contract(self):
        result = self._run(build_release_readiness(**ready_inputs()))
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertIn("PASS=8 PENDING=0 FAIL=0", result.stdout)

    def test_cli_rejects_tampered_counts(self):
        report = build_release_readiness(**ready_inputs())
        report["counts"]["pass"] = 7
        result = self._run(report)
        self.assertEqual(4, result.returncode)
        self.assertIn("INVALID", result.stdout)

    def test_cli_rejects_dropped_check_even_if_state_says_pass(self):
        report = build_release_readiness(**ready_inputs())
        report["checks"].pop()
        result = self._run(report)
        self.assertEqual(4, result.returncode)
        self.assertIn("Expected exactly 8 release checks", result.stdout)


if __name__ == "__main__":
    unittest.main()
