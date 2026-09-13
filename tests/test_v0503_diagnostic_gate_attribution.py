import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class DiagnosticGateAttributionTests(unittest.TestCase):
    def setUp(self):
        from app.release_readiness import build_release_readiness
        self.build = build_release_readiness

    @staticmethod
    def inputs():
        return {
            "version": "0.55.2",
            "operations": {"ok": True, "issues": []},
            "startup": {"status": "ready", "issues": []},
            "diagnostics": {
                "overall": "healthy",
                "counts": {"healthy": 15, "warning": 0, "critical": 0, "offline": 0},
                "checks": [],
            },
            "performance": {"acceptance": {"state": "pending", "targets": [], "min_samples": 5}},
            "config_smoke": {"state": "pass", "source_digest": "abc", "restored_digest": "abc"},
            "restart": {"state": "pass", "summary": "Controlled restart observed"},
            "auth": {
                "available": True,
                "shared_display_mode": True,
                "totp_count": 1,
                "login_mode": "password_or_totp",
                "recovery_codes_remaining": 5,
            },
            "pwa": {
                "mode": "online_first",
                "cached_private_data": False,
                "offline_mutations": False,
                "background_sync": False,
                "push_notifications": False,
                "server_auth_required": True,
                "shared_display_lock_server_enforced": True,
            },
        }

    @staticmethod
    def dependency_row(report):
        return next(item for item in report["checks"] if item["key"] == "dependency_health")

    def test_warning_gate_names_the_exact_diagnostic_check(self):
        values = self.inputs()
        values["diagnostics"] = {
            "overall": "warning",
            "counts": {"healthy": 14, "warning": 1, "critical": 0, "offline": 0},
            "checks": [
                {"key": "telemetry", "label": "Telemetry database", "state": "healthy", "summary": "PostgreSQL telemetry reachable"},
                {"key": "classifier_consumer", "label": "Classifier consumer", "state": "warning", "summary": "Classifier consumer retaining last-known-good live catalogue"},
            ],
        }
        row = self.dependency_row(self.build(**values))
        self.assertEqual("pending", row["state"])
        self.assertEqual(
            [{
                "key": "classifier_consumer",
                "label": "Classifier consumer",
                "state": "warning",
                "summary": "Classifier consumer retaining last-known-good live catalogue",
            }],
            row["evidence"]["warning_checks"],
        )
        self.assertEqual([], row["evidence"]["blocking_checks"])
        self.assertIn("Classifier consumer", row["summary"])

    def test_healthy_diagnostic_checks_are_not_copied_into_gate_findings(self):
        values = self.inputs()
        values["diagnostics"]["checks"] = [
            {"key": "routeros_api", "label": "RouterOS API", "state": "healthy", "summary": "RouterOS reachable"},
        ]
        row = self.dependency_row(self.build(**values))
        self.assertEqual([], row["evidence"]["warning_checks"])
        self.assertEqual([], row["evidence"]["blocking_checks"])

    def test_failed_dependency_names_critical_and_offline_checks(self):
        values = self.inputs()
        values["diagnostics"] = {
            "overall": "critical",
            "counts": {"healthy": 13, "warning": 0, "critical": 1, "offline": 1},
            "checks": [
                {"key": "security_authority", "label": "Security & authority", "state": "critical", "summary": "Write authority not proven"},
                {"key": "ipfix_source", "label": "IPFIX flow source", "state": "offline", "summary": "IPFIX flow source unavailable to traffic-ingest"},
            ],
        }
        row = self.dependency_row(self.build(**values))
        self.assertEqual("fail", row["state"])
        self.assertEqual({"security_authority", "ipfix_source"}, {item["key"] for item in row["evidence"]["blocking_checks"]})
        self.assertIn("Security & authority", row["summary"])
        self.assertIn("IPFIX flow source", row["summary"])

    def test_aggregate_warning_without_detail_stays_pending_and_explicit(self):
        values = self.inputs()
        values["diagnostics"] = {
            "overall": "warning",
            "counts": {"healthy": 14, "warning": 1, "critical": 0, "offline": 0},
            "checks": [],
        }
        row = self.dependency_row(self.build(**values))
        self.assertEqual("pending", row["state"])
        self.assertEqual([], row["evidence"]["warning_checks"])
        self.assertTrue(row["evidence"]["detail_incomplete"])
        self.assertIn("detail unavailable", row["summary"].lower())

    def test_attribution_never_launders_warning_into_pass(self):
        values = self.inputs()
        values["diagnostics"] = {
            "overall": "warning",
            "counts": {"healthy": 14, "warning": 1, "critical": 0, "offline": 0},
            "checks": [{"key": "durable_evidence", "label": "Durable evidence & recovery", "state": "warning", "summary": "No snapshots yet"}],
        }
        report = self.build(**values)
        self.assertEqual("pending", report["state"])
        self.assertFalse(report["core_ready"])
        self.assertEqual("pending", self.dependency_row(report)["state"])

    def test_diagnostic_facts_are_not_copied_into_release_evidence(self):
        values = self.inputs()
        values["diagnostics"] = {
            "overall": "warning",
            "counts": {"healthy": 14, "warning": 1, "critical": 0, "offline": 0},
            "checks": [{
                "key": "application",
                "label": "ZEN application",
                "state": "warning",
                "summary": "Process performance evidence unavailable",
                "facts": {"secret": "password=hunter2", "host": "192.0.2.9"},
            }],
        }
        serialized = json.dumps(self.build(**values))
        self.assertNotIn("hunter2", serialized)
        self.assertNotIn("192.0.2.9", serialized)

    def test_finding_strings_are_bounded_for_portable_release_evidence(self):
        values = self.inputs()
        values["diagnostics"] = {
            "overall": "warning",
            "counts": {"healthy": 0, "warning": 1, "critical": 0, "offline": 0},
            "checks": [{
                "key": "x" * 500,
                "label": "y" * 500,
                "state": "warning",
                "summary": "z" * 2000,
            }],
        }
        finding = self.dependency_row(self.build(**values))["evidence"]["warning_checks"][0]
        self.assertLessEqual(len(finding["key"]), 64)
        self.assertLessEqual(len(finding["label"]), 120)
        self.assertLessEqual(len(finding["summary"]), 240)


class DiagnosticGateAttributionUxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = (ROOT / "app/main.py").read_text(encoding="utf-8")
        cls.release = (ROOT / "app/release_readiness.py").read_text(encoding="utf-8")
        cls.template = (ROOT / "app/templates/release_readiness.html").read_text(encoding="utf-8")
        cls.readme = (ROOT / "README.md").read_text(encoding="utf-8") + "\n" + (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

    def test_release_readiness_renders_named_warning_and_blocking_findings(self):
        self.assertIn("warning_checks", self.template)
        self.assertIn("blocking_checks", self.template)
        self.assertIn("Review in diagnostics", self.template)
        self.assertIn('href="/diagnostics"', self.template)

    def test_release_matrix_records_diagnostic_attribution_hardening(self):
        self.assertIn('("diagnostic_gate", "Diagnostic warning attribution & pre-HTTPS gate", "0.51.0")', self.release)

    def test_release_version_and_assets_are_current(self):
        self.assertIn('version="0.55.4"', self.main)
        self.assertIn('/static/diagnostics.css?v=0.55.4', self.template)

    def test_documentation_states_warning_identity_does_not_change_severity(self):
        self.assertIn("v0.55.2", self.readme)
        self.assertIn("does not downgrade, acknowledge or suppress", self.readme)


if __name__ == "__main__":
    unittest.main()
