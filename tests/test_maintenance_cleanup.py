import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class MaintenanceCleanupTests(unittest.TestCase):
    def test_historical_artifacts_are_removed(self):
        obsolete = [
            "compose.policy.yml",
            "mikrotik-control-service-r2.patch",
            "mikrotik-control-service-r21-ux.patch",
            "app/test-router.py",
            "telemetry/docker-compose.telemetry-merge.yml",
            "telemetry/docker-compose.postgres-merge.yml",
            "telemetry/env.postgres.example",
            "telemetry/env.telemetry.example",
            "telemetry/clickhouse/init.sql",
        ]
        for rel in obsolete:
            self.assertFalse((ROOT / rel).exists(), rel)

    def test_stylesheets_use_descriptive_names(self):
        index = (ROOT / "app/templates/index.html").read_text()
        activity = (ROOT / "app/templates/activity_device.html").read_text()
        for html in (index, activity):
            self.assertIn('/static/layout.css?v=0.55.4.2', html)
            self.assertIn('/static/activity.css?v=0.55.4.2', html)
            self.assertNotIn('/static/r15-1.css', html)
            self.assertNotIn('/static/r16.css', html)
        self.assertTrue((ROOT / "app/static/layout.css").exists())
        self.assertTrue((ROOT / "app/static/activity.css").exists())
        self.assertTrue((ROOT / "app/static/service-intelligence.css").exists())

    def test_user_facing_templates_have_no_release_round_labels(self):
        pattern = re.compile(r"\bR\d+(?:\.\d+)?\b")
        for rel in [
            "app/templates/index.html",
            "app/templates/activity_device.html",
            "app/templates/activity_service.html",
            "app/templates/login.html",
            "app/templates/recovery_codes.html",
        ]:
            text = (ROOT / rel).read_text()
            self.assertIsNone(pattern.search(text), rel)

    def test_app_css_does_not_contain_literal_escaped_newline_block(self):
        css = (ROOT / "app/static/app.css").read_text()
        self.assertNotIn(r"\n\n/*", css)

    def test_env_example_contains_current_runtime_dependencies(self):
        env = (ROOT / ".env.example").read_text()
        for key in [
            "MIKROTIK_HOST=",
            "MIKROTIK_USER=",
            "TELEMETRY_DB_PASSWORD=",
            "PIHOLE_PASSWORD=",
            "OTP_ENCRYPTION_KEY=",
        ]:
            self.assertIn(key, env)


if __name__ == "__main__":
    unittest.main()
