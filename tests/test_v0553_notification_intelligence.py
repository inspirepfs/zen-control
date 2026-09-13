import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.policy_store import PolicyStore

ROOT = Path(__file__).resolve().parents[1]


class NotificationIntelligenceStoreTests(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(prefix="zen-notification-intel-", suffix=".db")
        os.close(fd)
        self.store = PolicyStore(self.path)

    def tearDown(self):
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass

    def warning(self, key, *, source="telemetry", subject="192.168.2.26", title="Warning"):
        return self.store.upsert_notification(
            dedupe_key=key,
            source=source,
            event_type="incident",
            severity="warning",
            title=title,
            subject=subject,
            source_ref=f"incident:{key}",
        )

    def test_defaults_are_attention_only_and_do_not_bump_policy_revision(self):
        settings = self.store.notification_intelligence_settings()
        self.assertTrue(settings["escalation_enabled"])
        self.assertEqual(1800, settings["warning_escalate_seconds"])
        self.assertEqual(5, settings["repeat_escalate_count"])
        self.assertEqual(2, settings["digest_min_items"])
        before = self.store.current_config_revision()
        saved = self.store.save_notification_intelligence_settings(
            escalation_enabled="1",
            warning_escalate_seconds="3600",
            repeat_escalate_count="10",
            digest_min_items="3",
            digest_window_minutes="180",
            actor="parent",
        )
        self.assertEqual(before, self.store.current_config_revision())
        self.assertEqual(3600, saved["warning_escalate_seconds"])
        self.assertEqual(10, saved["repeat_escalate_count"])

    def test_same_subject_correlates_across_source_families(self):
        self.warning("telemetry:a", source="telemetry:flow")
        self.warning("quota:a", source="quota:192.168.2.26", title="Quota warning")
        groups = self.store.notification_groups()
        self.assertEqual(1, len(groups))
        group = groups[0]
        self.assertEqual("subject:192.168.2.26", group["correlation_key"])
        self.assertEqual(2, group["notifications"])
        self.assertEqual({"telemetry:flow", "quota:192.168.2.26"}, set(group["sources"]))

    def test_timeline_records_lifecycle_without_changing_source_truth(self):
        row = self.warning("telemetry:timeline")
        self.store.upsert_notification(
            dedupe_key="telemetry:timeline", source="telemetry", event_type="incident",
            severity="warning", title="Warning repeated", subject="192.168.2.26",
        )
        self.store.mark_notification_read(row["id"], "parent")
        self.store.acknowledge_notification(row["id"], "parent")
        self.store.resolve_notification("telemetry:timeline", actor="monitor", resolution="Fresh again")
        events = [item["event"] for item in reversed(self.store.notification_timeline(row["id"]))]
        self.assertEqual(["created", "repeated", "read", "acknowledged", "resolved"], events)
        final = self.store.get_notification(row["id"])
        self.assertEqual("warning", final["source_severity"])
        self.assertTrue(final["resolved_at"])

    def test_age_escalation_raises_attention_not_source_severity_and_queues_new_push(self):
        subscription = self.store.register_push_subscription(
            username="parent",
            endpoint="https://push.example.invalid/intelligence",
            p256dh="key",
            auth="auth",
        )
        row = self.warning("telemetry:aged")
        # First push exists as a normal notification; make the source look old enough to escalate.
        old = datetime.now(timezone.utc) - timedelta(hours=1)
        with self.store._db() as db:
            db.execute(
                "UPDATE notifications SET first_seen_at=? WHERE id=?",
                (old.isoformat(timespec="seconds"), row["id"]),
            )
        result = self.store.evaluate_notification_intelligence(now=datetime.now(timezone.utc))
        self.assertEqual(1, result["escalated"])
        updated = self.store.get_notification(row["id"])
        self.assertEqual("warning", updated["source_severity"])
        self.assertEqual("critical", updated["severity"])
        self.assertEqual(1, updated["escalation_level"])
        self.assertIn("unresolved warning", updated["escalation_reason"])
        timeline = self.store.notification_timeline(row["id"])
        self.assertEqual("intelligence_escalated", timeline[0]["event"])
        with self.store._db() as db:
            kinds = [r["kind"] for r in db.execute(
                "SELECT kind FROM notification_push_deliveries WHERE notification_id=? ORDER BY id",
                (row["id"],),
            ).fetchall()]
        self.assertIn("escalation", kinds)
        self.assertTrue(subscription["enabled"])

    def test_repeat_escalation_and_acknowledgement_suppresses_automatic_escalation(self):
        self.store.save_notification_intelligence_settings(repeat_escalate_count="3")
        row = self.warning("telemetry:repeat")
        for _ in range(2):
            self.warning("telemetry:repeat")
        result = self.store.evaluate_notification_intelligence()
        self.assertEqual(1, result["repeat_escalations"])
        self.assertEqual("critical", self.store.get_notification(row["id"])["severity"])

        ack = self.warning("telemetry:ack")
        self.store.acknowledge_notification(ack["id"], "parent")
        old = datetime.now(timezone.utc) - timedelta(days=1)
        with self.store._db() as db:
            db.execute("UPDATE notifications SET first_seen_at=? WHERE id=?", (old.isoformat(timespec="seconds"), ack["id"]))
        self.store.evaluate_notification_intelligence(now=datetime.now(timezone.utc))
        self.assertEqual("warning", self.store.get_notification(ack["id"])["severity"])

    def test_intelligence_escalation_survives_source_repeat_then_resets_after_clear_reopen(self):
        self.store.save_notification_intelligence_settings(repeat_escalate_count="2")
        row = self.warning("telemetry:cycle")
        self.warning("telemetry:cycle")
        self.store.evaluate_notification_intelligence()
        self.assertEqual("critical", self.store.get_notification(row["id"])["severity"])
        repeated = self.warning("telemetry:cycle")
        self.assertEqual("critical", repeated["severity"])
        self.assertEqual("warning", repeated["source_severity"])
        self.store.resolve_notification("telemetry:cycle", resolution="Recovered")
        reopened = self.warning("telemetry:cycle")
        self.assertEqual("warning", reopened["severity"])
        self.assertEqual(0, reopened["escalation_level"])
        self.assertEqual(1, reopened["reopen_count"])

    def test_digest_preview_respects_attention_suppression_and_groups_repeats(self):
        self.store.save_notification_intelligence_settings(digest_min_items="2", digest_window_minutes="60")
        self.warning("telemetry:digest")
        self.warning("telemetry:digest")
        preview = self.store.notification_digest_preview()
        self.assertEqual(1, len(preview))
        self.assertGreaterEqual(preview[0]["events"], 2)
        self.store.save_notification_preferences(muted_subjects=["192.168.2.26"])
        self.assertEqual([], self.store.notification_digest_preview())

    def test_explanation_and_noise_analytics_are_derived_only(self):
        row = self.warning("telemetry:explain")
        self.warning("telemetry:explain")
        explanation = self.store.notification_explanation(row["id"])
        self.assertEqual("zen_notification_explanation_v1", explanation["schema"])
        self.assertEqual("warning", explanation["source_severity"])
        self.assertIn("eligible", explanation["attention"]["reason"])
        self.assertIn("Review Activity", explanation["action_hint"])
        self.assertEqual("explanation-only-no-mutation-authority", explanation["authority"])
        stats = self.store.notification_intelligence_stats()
        self.assertEqual("attention-only-derived", stats["authority"])
        self.assertEqual("telemetry", stats["noisy_sources"][0]["source"])
        self.assertGreaterEqual(stats["noisy_sources"][0]["events"], 2)

    def test_validation_is_fail_closed(self):
        with self.assertRaises(ValueError):
            self.store.save_notification_intelligence_settings(warning_escalate_seconds="123")
        with self.assertRaises(ValueError):
            self.store.save_notification_intelligence_settings(repeat_escalate_count="4")
        with self.assertRaises(ValueError):
            self.store.save_notification_intelligence_settings(digest_min_items="4")
        with self.assertRaises(ValueError):
            self.store.save_notification_intelligence_settings(digest_window_minutes="17")


class NotificationIntelligenceSurfaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = (ROOT / "app" / "main.py").read_text()
        cls.template = (ROOT / "app" / "templates" / "index.html").read_text()
        cls.help = (ROOT / "app" / "help_content.py").read_text()
        cls.css = (ROOT / "app" / "static" / "notifications.css").read_text()

    def test_intelligence_is_first_class_notification_section_and_explanation_surface(self):
        self.assertIn('"notifications": ("inbox", "preferences", "intelligence", "delivery", "history")', self.main)
        self.assertIn("Notification intelligence", self.template)
        self.assertIn("Why am I seeing this?", self.template)
        self.assertIn('data-ux-group="intelligence"', self.template)
        self.assertIn("notification-timeline-list", self.css)

    def test_api_settings_and_background_evaluator_exist(self):
        self.assertIn('@app.get("/api/notifications/intelligence")', self.main)
        self.assertIn('@app.get("/api/notifications/{notification_id}/explain")', self.main)
        self.assertIn('@app.post("/local/notifications/intelligence")', self.main)
        self.assertIn('"notifications.intelligence": _background_notification_intelligence', self.main)
        self.assertIn('scope="notifications:intelligence"', self.main)
        self.assertIn("NOTIFICATION_INTELLIGENCE_UPDATED", self.main)

    def test_help_states_attention_only_boundary(self):
        self.assertIn('("notifications", "intelligence"): "notifications"', self.help)
        self.assertIn("retains source severity separately from attention severity", self.help)
        self.assertIn("never authorises a RouterOS write", self.help)

    def test_release_identity_is_v0553(self):
        self.assertIn('version="0.58.0"', self.main)
        self.assertIn('PWA_RELEASE = "0.58.0"', (ROOT / "app" / "pwa.py").read_text())
        self.assertIn("const RELEASE = '0.58.0'", (ROOT / "app" / "static" / "service-worker.js").read_text())


if __name__ == "__main__":
    unittest.main()
