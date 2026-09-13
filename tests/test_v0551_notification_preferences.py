import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from app.policy_store import PolicyStore

ROOT = Path(__file__).resolve().parents[1]


class NotificationPreferenceStoreTests(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(prefix="zen-notification-prefs-", suffix=".db")
        os.close(fd)
        self.store = PolicyStore(self.path)

    def tearDown(self):
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass

    def test_defaults_are_safe_and_do_not_hide_attention(self):
        prefs = self.store.notification_preferences()
        self.assertTrue(prefs["enabled"])
        self.assertEqual("info", prefs["min_severity"])
        self.assertFalse(prefs["quiet_hours_enabled"])
        self.assertTrue(prefs["critical_bypass_quiet"])
        self.assertEqual(300, prefs["cooldown_seconds"])
        self.assertEqual([], prefs["muted_sources"])
        self.assertEqual([], prefs["muted_subjects"])
        self.assertEqual([], prefs["disabled_events"])

    def test_preferences_are_attention_only_and_do_not_bump_policy_revision(self):
        before = self.store.current_config_revision()
        saved = self.store.save_notification_preferences(
            enabled="1",
            min_severity="warning",
            quiet_hours_enabled="1",
            quiet_start="22:00",
            quiet_end="07:00",
            timezone_name="Europe/London",
            critical_bypass_quiet="1",
            cooldown_seconds="900",
            muted_sources=["telemetry"],
            muted_subjects=["192.168.2.26"],
            disabled_events=["background:background_job_failed"],
            actor="parent",
        )
        after = self.store.current_config_revision()
        self.assertEqual(before, after)
        self.assertEqual("warning", saved["min_severity"])
        self.assertEqual(900, saved["cooldown_seconds"])
        self.assertEqual(["telemetry"], saved["muted_sources"])
        self.assertEqual(["192.168.2.26"], saved["muted_subjects"])
        self.assertEqual(["background:background_job_failed"], saved["disabled_events"])

    def test_minimum_severity_source_subject_and_event_filters_mute_bell_not_evidence(self):
        self.store.save_notification_preferences(min_severity="warning")
        info = self.store.upsert_notification(
            dedupe_key="security:info",
            source="security",
            event_type="incident",
            severity="info",
            title="Informational security evidence",
        )
        listed = self.store.list_notifications()[0]
        self.assertEqual(info["id"], listed["id"])
        self.assertTrue(listed["attention_suppressed"])
        self.assertIn("threshold", listed["suppression_reason"])
        counts = self.store.notification_counts()
        self.assertEqual(0, counts["unread"])
        self.assertEqual(1, counts["unread_total"])
        self.assertEqual(1, counts["suppressed_unread"])

        self.store.save_notification_preferences(
            min_severity="info",
            muted_sources=["security"],
        )
        listed = self.store.list_notifications()[0]
        self.assertTrue(listed["attention_suppressed"])
        self.assertIn("source muted", listed["suppression_reason"])

        self.store.save_notification_preferences(
            min_severity="info",
            muted_subjects=["192.168.2.26"],
        )
        self.store.upsert_notification(
            dedupe_key="quota:device",
            source="quota:192.168.2.26",
            event_type="incident",
            severity="warning",
            title="Quota warning",
            subject="192.168.2.26",
        )
        device = next(row for row in self.store.list_notifications() if row["dedupe_key"] == "quota:device")
        self.assertTrue(device["attention_suppressed"])
        self.assertEqual("device/subject muted", device["suppression_reason"])

        self.store.save_notification_preferences(
            min_severity="info",
            disabled_events=["background:background_job_failed"],
        )
        self.store.upsert_notification(
            dedupe_key="background:test",
            source="background",
            event_type="background_job_failed",
            severity="warning",
            title="Worker failed",
        )
        worker = next(row for row in self.store.list_notifications() if row["dedupe_key"] == "background:test")
        self.assertTrue(worker["attention_suppressed"])
        self.assertEqual("event disabled", worker["suppression_reason"])

    def test_quiet_hours_are_dynamic_and_critical_can_bypass(self):
        self.store.save_notification_preferences(
            quiet_hours_enabled="1",
            quiet_start="22:00",
            quiet_end="07:00",
            timezone_name="UTC",
            critical_bypass_quiet="1",
        )
        prefs = self.store.notification_preferences()
        warning = {
            "source": "security", "event_type": "incident", "severity": "warning",
            "subject": "RouterOS", "attention_eligible_at": "",
        }
        critical = {**warning, "severity": "critical"}
        at_2300 = datetime(2026, 9, 12, 23, 0, tzinfo=timezone.utc)
        at_1200 = datetime(2026, 9, 12, 12, 0, tzinfo=timezone.utc)
        self.assertEqual("quiet hours", self.store._notification_policy_decision(warning, prefs, at_2300)["reason"])
        self.assertFalse(self.store._notification_policy_decision(critical, prefs, at_2300)["suppressed"])
        self.assertFalse(self.store._notification_policy_decision(warning, prefs, at_1200)["suppressed"])

    def test_reopen_cooldown_retains_unresolved_evidence_but_temporarily_mutes_attention(self):
        self.store.save_notification_preferences(cooldown_seconds="3600")
        row = self.store.upsert_notification(
            dedupe_key="background:cooldown",
            source="background",
            event_type="background_job_failed",
            severity="warning",
            title="Worker failed",
        )
        self.store.resolve_notification("background:cooldown", actor="worker", resolution="Recovered")
        reopened = self.store.upsert_notification(
            dedupe_key="background:cooldown",
            source="background",
            event_type="background_job_failed",
            severity="warning",
            title="Worker failed again",
        )
        self.assertEqual("unread", reopened["state"])
        self.assertFalse(reopened["resolved_at"])
        self.assertTrue(reopened["attention_eligible_at"])
        listed = self.store.list_notifications()[0]
        self.assertTrue(listed["attention_suppressed"])
        self.assertEqual("cooldown", listed["suppression_reason"])
        self.assertEqual(0, self.store.notification_counts()["unread"])

        critical = self.store.upsert_notification(
            dedupe_key="background:cooldown",
            source="background",
            event_type="background_job_failed",
            severity="critical",
            title="Worker failed critically",
        )
        self.assertEqual("", critical["attention_eligible_at"])
        self.assertEqual(1, self.store.notification_counts()["critical_unread"])

    def test_event_catalog_uses_source_family_for_per_device_quota_sources(self):
        self.store.upsert_notification(
            dedupe_key="quota:x",
            source="quota:192.168.2.26",
            event_type="incident",
            severity="warning",
            title="Quota warning",
            subject="192.168.2.26",
        )
        catalog = {row["key"]: row for row in self.store.notification_event_catalog()}
        self.assertIn("quota:incident", catalog)
        self.store.save_notification_preferences(disabled_events=["quota:incident"])
        catalog = {row["key"]: row for row in self.store.notification_event_catalog()}
        self.assertFalse(catalog["quota:incident"]["enabled"])

    def test_preference_validation_is_fail_closed(self):
        with self.assertRaises(ValueError):
            self.store.save_notification_preferences(min_severity="noise")
        with self.assertRaises(ValueError):
            self.store.save_notification_preferences(quiet_hours_enabled="1", quiet_start="22:00", quiet_end="22:00")
        with self.assertRaises(ValueError):
            self.store.save_notification_preferences(timezone_name="Not/AZone")
        with self.assertRaises(ValueError):
            self.store.save_notification_preferences(cooldown_seconds="123")


class NotificationPreferenceSurfaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = (ROOT / "app" / "main.py").read_text()
        cls.template = (ROOT / "app" / "templates" / "index.html").read_text()
        cls.help = (ROOT / "app" / "help_content.py").read_text()
        cls.css = (ROOT / "app" / "static" / "notifications.css").read_text()

    def test_preferences_are_first_class_notification_section(self):
        self.assertIn('"notifications": ("inbox", "preferences", "intelligence", "history")', self.main)
        self.assertIn("Notification preferences", self.template)
        self.assertIn("data-ux-group=\"preferences\"", self.template)
        self.assertIn("notification_preferences", self.main)
        self.assertIn("notification-rule-grid", self.css)

    def test_preferences_route_and_api_contract_exist(self):
        self.assertIn('@app.post("/local/notifications/preferences")', self.main)
        self.assertIn('"preferences": policy_store.notification_preferences()', self.main)
        self.assertIn('"event_catalog": policy_store.notification_event_catalog()', self.main)
        self.assertIn("NOTIFICATION_PREFERENCES_UPDATED", self.main)

    def test_help_explains_attention_only_boundary(self):
        self.assertIn('("notifications", "preferences"): "notifications"', self.help)
        self.assertIn("changes attention only", self.help)
        self.assertIn("quiet hours", self.help.lower())

    def test_release_identity_is_v0551(self):
        self.assertIn('version="0.55.3.1"', self.main)
        self.assertIn("Current release: **v0.55.3.1**", (ROOT / "README.md").read_text())
        self.assertIn("## v0.55.2", (ROOT / "CHANGELOG.md").read_text())
        self.assertIn('PWA_RELEASE = "0.55.3.1"', (ROOT / "app" / "pwa.py").read_text())


if __name__ == "__main__":
    unittest.main()
