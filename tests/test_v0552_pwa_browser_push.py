import os
import tempfile
import unittest
from pathlib import Path

from app.policy_store import PolicyStore
from app.push_delivery import PushDeliveryError, PushDeliveryService, VapidIdentity

ROOT = Path(__file__).resolve().parents[1]


class PushStoreTests(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(prefix="zen-push-", suffix=".db")
        os.close(fd)
        self.store = PolicyStore(self.path)
        self.subscription = self.store.register_push_subscription(
            username="parent",
            endpoint="https://push.example.invalid/subscription/abc",
            p256dh="p256dh-key",
            auth="auth-key",
            user_agent="UnitTest/1.0",
        )

    def tearDown(self):
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass

    def test_subscription_surface_never_exposes_endpoint_or_browser_keys(self):
        safe = self.store.list_push_subscriptions(username="parent")[0]
        self.assertNotIn("endpoint", safe)
        self.assertNotIn("p256dh", safe)
        self.assertNotIn("auth", safe)
        self.assertEqual(64, len(safe["endpoint_hash"]))
        secret = self.store.get_push_subscription(self.subscription["id"], include_secret=True)
        self.assertTrue(secret["endpoint"].startswith("https://"))
        self.assertEqual("p256dh-key", secret["p256dh"])

    def test_notification_creation_queues_delivery_after_preference_evaluation(self):
        row = self.store.upsert_notification(
            dedupe_key="security:push-test",
            source="security",
            event_type="incident",
            severity="warning",
            title="Security warning",
            detail="Something needs attention",
            target_url="/?view=incidents&section=active#incidents/active",
        )
        stats = self.store.notification_push_delivery_stats()
        self.assertEqual(1, stats["pending"])
        claimed = self.store.claim_notification_push_deliveries(limit=5)
        self.assertEqual(1, len(claimed))
        self.assertEqual(row["id"], claimed[0]["notification_id"])
        self.assertIn('"severity":"warning"', claimed[0]["payload_json"])
        self.assertIn('"Security warning"', claimed[0]["payload_json"])

    def test_muted_notification_records_suppressed_delivery_not_pending(self):
        self.store.save_notification_preferences(muted_sources=["telemetry"])
        self.store.upsert_notification(
            dedupe_key="telemetry:quiet",
            source="telemetry",
            event_type="incident",
            severity="warning",
            title="Telemetry warning",
        )
        stats = self.store.notification_push_delivery_stats()
        self.assertEqual(0, stats["pending"])
        self.assertEqual(1, stats["suppressed"])

    def test_read_ack_or_resolve_cancels_unsent_push(self):
        row = self.store.upsert_notification(
            dedupe_key="security:cancel",
            source="security",
            event_type="incident",
            severity="warning",
            title="Cancel me",
        )
        self.store.mark_notification_read(row["id"], "parent")
        self.assertEqual(1, self.store.notification_push_delivery_stats()["cancelled"])

        row2 = self.store.upsert_notification(
            dedupe_key="security:resolve-cancel",
            source="security",
            event_type="incident",
            severity="warning",
            title="Resolve me",
        )
        self.store.resolve_notification("security:resolve-cancel", actor="system")
        self.assertEqual(2, self.store.notification_push_delivery_stats()["cancelled"])

    def test_delivery_retry_and_gone_subscription_are_durable(self):
        self.store.enqueue_notification_push_test(username="parent")
        row = self.store.claim_notification_push_deliveries(limit=1)[0]
        retried = self.store.fail_notification_push_delivery(row["id"], "temporary")
        self.assertEqual("pending", retried["status"])

        with self.store._db() as db:
            db.execute("UPDATE notification_push_deliveries SET available_at='1970-01-01T00:00:00+00:00' WHERE id=?", (row["id"],))
        row = self.store.claim_notification_push_deliveries(limit=1)[0]
        terminal = self.store.fail_notification_push_delivery(
            row["id"], "gone", disable_subscription=True
        )
        self.assertEqual("failed", terminal["status"])
        self.assertEqual(0, self.store.push_subscription_stats(username="parent")["enabled"])


class PushDeliveryServiceTests(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(prefix="zen-push-service-", suffix=".db")
        os.close(fd)
        self.key_dir = tempfile.TemporaryDirectory(prefix="zen-vapid-")
        self.store = PolicyStore(self.path)
        self.store.register_push_subscription(
            username="parent",
            endpoint="https://push.example.invalid/subscription/abc",
            p256dh="key",
            auth="auth",
        )
        self.audit_rows = []

    def tearDown(self):
        self.key_dir.cleanup()
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass

    def service(self, sender):
        identity = VapidIdentity(key_file=str(Path(self.key_dir.name) / "vapid.pem"))
        return PushDeliveryService(
            policy_store=self.store,
            audit=lambda *args: self.audit_rows.append(args),
            identity=identity,
            sender=sender,
            poll_seconds=2,
        )

    def test_vapid_identity_is_persistent_and_public_key_is_stable(self):
        key_file = str(Path(self.key_dir.name) / "stable.pem")
        first = VapidIdentity(key_file=key_file)
        second = VapidIdentity(key_file=key_file)
        self.assertEqual(first.public_key, second.public_key)
        self.assertTrue(first.public_key.startswith("B"))
        self.assertEqual(87, len(first.public_key))
        self.assertEqual(0o600, os.stat(key_file).st_mode & 0o777)

    def test_successful_worker_cycle_sends_and_records_success(self):
        delivered = []
        self.store.enqueue_notification_push_test(username="parent")
        service = self.service(lambda subscription, payload: delivered.append((subscription, payload)))
        result = service.run_cycle()
        self.assertEqual("ok", result["result"])
        self.assertEqual(1, result["sent"])
        self.assertEqual(1, len(delivered))
        self.assertEqual(1, self.store.notification_push_delivery_stats()["sent"])
        self.assertTrue(self.store.push_subscription_stats(username="parent")["last_success_at"])

    def test_http_410_disables_stale_browser_subscription(self):
        def gone(_subscription, _payload):
            raise PushDeliveryError("gone", status_code=410)

        self.store.enqueue_notification_push_test(username="parent")
        service = self.service(gone)
        result = service.run_cycle()
        self.assertEqual("degraded", result["result"])
        self.assertEqual(1, result["disabled"])
        self.assertEqual(0, self.store.push_subscription_stats(username="parent")["enabled"])


class PushSurfaceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = (ROOT / "app" / "main.py").read_text()
        cls.template = (ROOT / "app" / "templates" / "index.html").read_text()
        cls.js = (ROOT / "app" / "static" / "pwa.js").read_text()
        cls.worker = (ROOT / "app" / "static" / "service-worker.js").read_text()
        cls.requirements = (ROOT / "requirements.txt").read_text()

    def test_authenticated_subscription_test_and_disable_api_exist(self):
        for route in (
            '@app.get("/api/notifications/push")',
            '@app.post("/api/notifications/push/subscriptions")',
            '@app.post("/api/notifications/push/unsubscribe")',
            '@app.post("/api/notifications/push/test")',
        ):
            self.assertIn(route, self.main)
        self.assertIn("X-ZEN-CSRF", self.main)

    def test_browser_surface_uses_standard_push_manager_and_permission(self):
        self.assertIn("PushManager", self.js)
        self.assertIn("Notification.requestPermission", self.js)
        self.assertIn("pushManager.subscribe", self.js)
        self.assertIn("data-push-enable", self.template)
        self.assertIn("data-push-test", self.template)
        self.assertIn("quiet hours", self.template.lower())

    def test_service_worker_shows_push_and_bounds_click_to_same_origin(self):
        self.assertIn("self.addEventListener('push'", self.worker)
        self.assertIn("showNotification", self.worker)
        self.assertIn("self.addEventListener('notificationclick'", self.worker)
        self.assertIn("target.origin !== self.location.origin", self.worker)

    def test_runtime_dependency_is_explicit_and_release_is_v0552(self):
        self.assertIn("pywebpush", self.requirements)
        self.assertIn('version="0.55.3.1"', self.main)
        self.assertIn("const RELEASE = '0.55.3.1'", self.js)
        self.assertIn("const RELEASE = '0.55.3.1'", self.worker)


if __name__ == "__main__":
    unittest.main()
