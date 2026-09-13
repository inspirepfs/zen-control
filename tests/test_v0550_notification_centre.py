import os
import tempfile
import unittest
from pathlib import Path

from app.policy_store import PolicyStore

ROOT = Path(__file__).resolve().parents[1]


class NotificationStoreTests(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(prefix="zen-notifications-", suffix=".db")
        os.close(fd)
        self.store = PolicyStore(self.path)

    def tearDown(self):
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass

    def test_durable_notification_deduplicates_and_tracks_lifecycle(self):
        row = self.store.upsert_notification(
            dedupe_key="test:alpha",
            source="test",
            event_type="example",
            severity="warning",
            title="Example warning",
            detail="first",
        )
        self.assertEqual("unread", row["state"])
        self.assertEqual(1, row["occurrences"])

        row = self.store.upsert_notification(
            dedupe_key="test:alpha",
            source="test",
            event_type="example",
            severity="warning",
            title="Example warning",
            detail="second",
        )
        self.assertEqual(row["id"], 1)
        self.assertEqual(2, row["occurrences"])
        counts = self.store.notification_counts()
        self.assertEqual(1, counts["total"])
        self.assertEqual(2, counts["events"])
        self.assertEqual(1, counts["deduplicated"])

        row = self.store.mark_notification_read(row["id"], "parent")
        self.assertEqual("read", row["state"])
        row = self.store.acknowledge_notification(row["id"], "parent")
        self.assertEqual("acknowledged", row["state"])
        self.assertEqual("parent", row["acknowledged_by"])
        row = self.store.dismiss_notification(row["id"], "parent")
        self.assertEqual("dismissed", row["state"])
        self.assertEqual(1, self.store.notification_counts()["dismissed"])

    def test_dismissed_signal_stays_dismissed_until_source_clears_or_escalates(self):
        row = self.store.upsert_notification(
            dedupe_key="worker:x",
            source="background",
            event_type="background_job_failed",
            severity="warning",
            title="Worker failed",
        )
        self.store.dismiss_notification(row["id"], "parent")
        same = self.store.upsert_notification(
            dedupe_key="worker:x",
            source="background",
            event_type="background_job_failed",
            severity="warning",
            title="Worker failed again",
        )
        self.assertEqual("dismissed", same["state"])

        escalated = self.store.upsert_notification(
            dedupe_key="worker:x",
            source="background",
            event_type="background_job_failed",
            severity="critical",
            title="Worker failed critically",
        )
        self.assertEqual("unread", escalated["state"])

        self.store.resolve_notification("worker:x", actor="worker", resolution="Recovered")
        reopened = self.store.upsert_notification(
            dedupe_key="worker:x",
            source="background",
            event_type="background_job_failed",
            severity="critical",
            title="Worker failed after recovery",
        )
        self.assertEqual("unread", reopened["state"])
        self.assertFalse(reopened["resolved_at"])
        self.assertFalse(reopened["acknowledged_at"])

    def test_existing_active_incident_is_backfilled_on_first_post_upgrade_scan(self):
        incident = self.store.upsert_incident(
            fingerprint="operations:upgrade",
            source="operations",
            severity="warning",
            title="Existing active incident",
            detail="pre-upgrade evidence",
        )
        with self.store._db() as db:
            db.execute("DELETE FROM notifications WHERE dedupe_key=?", ("incident:operations:upgrade",))
        self.assertEqual([], self.store.list_notifications())

        unchanged = self.store.upsert_incident(
            fingerprint="operations:upgrade",
            source="operations",
            severity="warning",
            title="Existing active incident",
            detail="pre-upgrade evidence",
        )
        self.assertEqual("unchanged", unchanged["action"])
        rows = self.store.list_notifications()
        self.assertEqual(1, len(rows))
        self.assertEqual("incident:operations:upgrade", rows[0]["dedupe_key"])
        self.assertEqual(1, rows[0]["occurrences"])

    def test_incident_lifecycle_drives_notification_without_duplicate_scan_noise(self):
        incident = self.store.upsert_incident(
            fingerprint="security:test",
            source="security",
            severity="warning",
            title="Security warning",
            detail="warning evidence",
        )
        self.assertEqual("opened", incident["action"])
        notification = self.store.list_notifications()[0]
        self.assertEqual("incident:security:test", notification["dedupe_key"])
        self.assertEqual(1, notification["occurrences"])

        unchanged = self.store.upsert_incident(
            fingerprint="security:test",
            source="security",
            severity="warning",
            title="Security warning",
            detail="warning evidence",
        )
        self.assertEqual("unchanged", unchanged["action"])
        notification = self.store.get_notification(notification["id"])
        self.assertEqual(1, notification["occurrences"])

        escalated = self.store.upsert_incident(
            fingerprint="security:test",
            source="security",
            severity="critical",
            title="Security warning",
            detail="critical evidence",
        )
        self.assertEqual("severity_changed", escalated["action"])
        notification = self.store.get_notification(notification["id"])
        self.assertEqual("critical", notification["severity"])
        self.assertEqual(2, notification["occurrences"])

        self.store.acknowledge_incident(incident["id"], "parent")
        notification = self.store.get_notification(notification["id"])
        self.assertEqual("acknowledged", notification["state"])

        self.store.resolve_incident(incident["id"], "parent", "Reviewed")
        notification = self.store.get_notification(notification["id"])
        self.assertTrue(notification["resolved_at"])
        self.assertEqual("Reviewed", notification["resolution"])

    def test_incident_suppression_prevents_notification_reopen_until_clear_scan(self):
        incident = self.store.upsert_incident(
            fingerprint="router:test",
            source="router",
            severity="warning",
            title="Router warning",
        )
        notification = self.store.list_notifications()[0]
        self.store.resolve_incident(incident["id"], "parent", "Temporarily resolved")

        suppressed = self.store.upsert_incident(
            fingerprint="router:test",
            source="router",
            severity="warning",
            title="Router warning",
        )
        self.assertEqual("suppressed", suppressed["action"])
        still_resolved = self.store.get_notification(notification["id"])
        self.assertTrue(still_resolved["resolved_at"])

        self.store.resolve_inactive_incidents("router", set())
        reopened = self.store.upsert_incident(
            fingerprint="router:test",
            source="router",
            severity="warning",
            title="Router warning",
        )
        self.assertEqual("reopened", reopened["action"])
        fresh = self.store.get_notification(notification["id"])
        self.assertEqual("unread", fresh["state"])
        self.assertFalse(fresh["resolved_at"])

    def test_terminal_background_failure_notifies_and_later_success_resolves(self):
        first = self.store.enqueue_background_job(
            kind="analytics.prepared-view",
            scope="analytics:activity",
            idempotency_key="notify-test-1",
            payload={"view": "activity:24h"},
            max_attempts=1,
        )
        claimed = self.store.claim_background_job(worker_name="test-worker", lease_seconds=30)
        self.assertEqual(first["id"], claimed["id"])
        self.store.fail_background_job(
            claimed["id"], worker_name="test-worker", lease_token=claimed["lease_token"], error="boom"
        )
        notification = self.store.list_notifications()[0]
        self.assertEqual("background_job_failed", notification["event_type"])
        self.assertEqual("Prepared read model failed", notification["title"])
        self.assertIn("boom", notification["detail"])
        self.assertFalse(notification["resolved_at"])

        self.store.enqueue_background_job(
            kind="analytics.prepared-view",
            scope="analytics:activity",
            idempotency_key="notify-test-2",
            payload={"view": "activity:24h"},
            max_attempts=1,
        )
        claimed = self.store.claim_background_job(worker_name="test-worker", lease_seconds=30)
        self.store.complete_background_job(
            claimed["id"], worker_name="test-worker", lease_token=claimed["lease_token"], result={"ok": True}
        )
        resolved = self.store.get_notification(notification["id"])
        self.assertTrue(resolved["resolved_at"])
        self.assertIn("completed successfully", resolved["resolution"])

    def test_stats_and_archive_are_truthful(self):
        a = self.store.upsert_notification(
            dedupe_key="a", source="test", event_type="x", severity="critical", title="A"
        )
        b = self.store.upsert_notification(
            dedupe_key="b", source="test", event_type="x", severity="info", title="B"
        )
        self.store.acknowledge_notification(a["id"], "parent")
        self.store.resolve_notification("a", actor="system", resolution="clear")
        self.store.dismiss_notification(b["id"], "parent")
        stats = self.store.notification_stats()
        self.assertEqual(2, stats["total"])
        self.assertEqual(1, stats["resolved"])
        self.assertEqual(1, stats["dismissed"])
        self.assertEqual(1, stats["acknowledged_samples"])
        self.assertEqual([], self.store.list_notifications(archived=False))
        self.assertEqual(2, len(self.store.list_notifications(archived=True)))


class NotificationSurfaceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = (ROOT / "app" / "main.py").read_text()
        cls.template = (ROOT / "app" / "templates" / "index.html").read_text()
        cls.help = (ROOT / "app" / "help_content.py").read_text()
        cls.css = (ROOT / "app" / "static" / "notifications.css").read_text()
        cls.readme = (ROOT / "README.md").read_text()

    def test_notification_centre_is_first_class_navigation_context(self):
        self.assertIn('"notifications", "incidents", "audit", "settings"', self.main)
        self.assertIn('"notifications": ("inbox", "preferences", "intelligence", "delivery", "history")', self.main)
        self.assertIn('data-panel="notifications"', self.template)
        self.assertIn("Notification centre", self.template)
        self.assertIn("notification-bell", self.template)
        self.assertIn("🔔", self.template)
        self.assertIn("notifications: [", self.template)

    def test_api_and_operator_lifecycle_routes_exist(self):
        for route in (
            '@app.get("/api/notifications")',
            '@app.post("/local/notifications/read-all")',
            '@app.post("/local/notifications/{notification_id}/read")',
            '@app.post("/local/notifications/{notification_id}/ack")',
            '@app.post("/local/notifications/{notification_id}/dismiss")',
        ):
            self.assertIn(route, self.main)
        self.assertIn('"schema": "zen_notifications_v1"', self.main)

    def test_help_and_css_are_product_integrated(self):
        self.assertIn('"notifications": _topic(', self.help)
        self.assertIn('("notifications", "inbox"): "notifications"', self.help)
        self.assertIn("notification-summary-grid", self.css)
        self.assertIn("notification-history-row", self.css)

    def test_release_version_is_v0550(self):
        self.assertIn('version="0.55.4.1"', self.main)
        self.assertIn("Current release: **v0.55.4.1**", self.readme)
        self.assertIn("## v0.55.2", (ROOT / "CHANGELOG.md").read_text())


if __name__ == "__main__":
    unittest.main()
