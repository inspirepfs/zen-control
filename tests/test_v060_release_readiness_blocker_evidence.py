import json
import unittest

from app.release_readiness import build_release_readiness


class ReleaseReadinessBlockerEvidenceTests(unittest.TestCase):
    @staticmethod
    def inputs():
        return {
            "version": "0.60.0",
            "operations": {"ok": True, "issues": []},
            "startup": {"status": "ready", "issues": []},
            "diagnostics": {"overall": "healthy", "counts": {"healthy": 12, "warning": 0, "critical": 0, "offline": 0}, "checks": []},
            "performance": {
                "acceptance": {"schema": "zen_performance_acceptance_v2", "state": "pass", "targets": [], "min_samples": 5},
                "formal_acceptance": {"schema": "zen_formal_performance_acceptance_v1", "state": "pass", "request_state": "pass", "evidence_targets": []},
            },
            "config_smoke": {"state": "pass", "source_digest": "abc", "restored_digest": "abc"},
            "restart": {"state": "pass", "summary": "Controlled restart observed"},
            "auth": {"shared_display_mode": True, "totp_count": 1, "login_mode": "password_totp", "recovery_codes_remaining": 5},
            "runtime_health": {"schema": "zen_runtime_health_v1", "ok": True, "status": "healthy"},
            "pwa": {"mode": "online_first", "cached_private_data": False, "offline_mutations": False, "background_sync": False, "server_auth_required": True, "shared_display_lock_server_enforced": True},
        }

    @staticmethod
    def row(report, key):
        return next(item for item in report["checks"] if item["key"] == key)

    def test_pwa_evidence_lists_each_mandatory_invariant_without_changing_gate_state(self):
        self.assertEqual("pass", build_release_readiness(**self.inputs())["state"])
        values = self.inputs()
        values["pwa"].update({"cached_private_data": True, "background_sync": True})
        report = build_release_readiness(**values)
        row = self.row(report, "pwa_security")
        self.assertEqual("fail", row["state"])
        self.assertEqual("fail", report["state"])
        self.assertEqual({"online_first": "pass", "cached_private_data": "fail", "offline_mutations": "pass", "background_sync": "fail", "server_auth_required": "pass", "shared_display_lock_server_enforced": "pass"}, {item["key"]: item["state"] for item in row["evidence"]["invariants"]})

    def test_dependency_and_performance_findings_are_complete_bounded_and_sanitized(self):
        values = self.inputs()
        values["diagnostics"] = {
            "overall": "warning", "counts": {"healthy": 0, "warning": 25, "critical": 0, "offline": 0},
            "checks": [{"key": f"diagnostic_{number}", "label": f"Diagnostic {number}", "state": "warning", "summary": "Review required"} for number in range(24)] + [{"key": "token=secret-value", "label": "router.private.example", "state": "warning", "summary": "https://router.private.example/path?token=secret-value Traceback: password=hunter2"}],
        }
        values["performance"]["formal_acceptance"] = {
            "schema": "zen_formal_performance_acceptance_v1", "state": "fail", "request_state": "pass",
            "evidence_targets": [{"key": f"performance_{number}", "label": f"Performance evidence {number}", "state": "fail"} for number in range(15)],
        }
        report = build_release_readiness(**values)
        dependency = self.row(report, "dependency_health")
        performance = self.row(report, "live_performance")
        self.assertEqual("pending", dependency["state"])
        self.assertEqual(25, len(dependency["evidence"]["warning_checks"]))
        self.assertEqual("fail", performance["state"])
        self.assertEqual(15, len(performance["evidence"]["findings"]))
        serialized = json.dumps(report)
        for unsafe in ("secret-value", "router.private.example", "hunter2", "https://"):
            self.assertNotIn(unsafe, serialized)
        for finding in dependency["evidence"]["warning_checks"]:
            self.assertLessEqual(len(finding["key"]), 64)
            self.assertLessEqual(len(finding["label"]), 120)
            self.assertLessEqual(len(finding["summary"]), 240)
