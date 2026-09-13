import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.external_delivery import ExternalDeliveryError, NotificationExternalDeliveryService
from app.policy_store import PolicyStore

ROOT = Path(__file__).resolve().parents[1]


class ExternalDeliveryStoreTests(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(prefix="zen-external-delivery-", suffix=".db")
        os.close(fd)
        self.store = PolicyStore(self.path)

    def tearDown(self):
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass

    def _enable_webhook(self):
        with patch.dict(os.environ, {"ZEN_WEBHOOK_ALLOW_HTTP": "1"}, clear=False):
            return self.store.save_notification_external_delivery_settings(
                webhook_enabled="1",
                webhook_name="Local sink",
                webhook_url="http://webhook-sink:8092/webhook",
                actor="parent",
            )

    def test_webhook_settings_are_non_authoritative_and_http_is_fail_closed(self):
        before = self.store.current_config_revision()
        with self.assertRaises(ValueError):
            self.store.save_notification_external_delivery_settings(
                webhook_enabled="1", webhook_url="http://example.invalid/hook", actor="parent"
            )
        saved = self._enable_webhook()
        self.assertTrue(saved["webhook_enabled"])
        self.assertEqual(before, self.store.current_config_revision())
        with self.assertRaises(ValueError):
            self.store.save_notification_external_delivery_settings(
                webhook_enabled="1", webhook_url="https://user:password@example.invalid/hook"
            )

    def test_notification_queues_email_and_webhook_after_attention_policy(self):
        self._enable_webhook()
        env = {"ZEN_SMTP_ENABLED": "1", "ZEN_SMTP_TO": "parent@example.test"}
        with patch.dict(os.environ, env, clear=False):
            row = self.store.upsert_notification(
                dedupe_key="security:external",
                source="security",
                event_type="incident",
                severity="warning",
                title="External warning",
            )
        deliveries = self.store.list_notification_external_deliveries(limit=10)
        self.assertEqual(2, len(deliveries))
        self.assertEqual({"email", "webhook"}, {item["channel"] for item in deliveries})
        self.assertTrue(all(item["status"] == "pending" for item in deliveries))
        self.assertTrue(all(item["notification_id"] == row["id"] for item in deliveries))
        email = next(item for item in deliveries if item["channel"] == "email")
        self.assertEqual("environment-configured recipients", email["destination"])

    def test_muted_notification_records_suppressed_external_delivery(self):
        self._enable_webhook()
        self.store.save_notification_preferences(muted_sources=["telemetry"])
        self.store.upsert_notification(
            dedupe_key="telemetry:external-muted",
            source="telemetry",
            event_type="incident",
            severity="warning",
            title="Muted",
        )
        stats = self.store.notification_external_delivery_stats()["channels"]["webhook"]
        self.assertEqual(1, stats["suppressed"])
        self.assertEqual(0, stats["pending"])

    def test_read_and_resolve_cancel_pending_external_delivery(self):
        self._enable_webhook()
        row = self.store.upsert_notification(
            dedupe_key="security:external-cancel", source="security", event_type="incident",
            severity="warning", title="Cancel",
        )
        self.store.mark_notification_read(row["id"], "parent")
        self.assertEqual(1, self.store.notification_external_delivery_stats()["channels"]["webhook"]["cancelled"])
        row2 = self.store.upsert_notification(
            dedupe_key="security:external-resolve", source="security", event_type="incident",
            severity="warning", title="Resolve",
        )
        self.store.resolve_notification("security:external-resolve", actor="monitor")
        self.assertEqual(2, self.store.notification_external_delivery_stats()["channels"]["webhook"]["cancelled"])
        self.assertTrue(self.store.get_notification(row2["id"])["resolved_at"])

    def test_intelligence_escalation_supersedes_normal_external_delivery(self):
        self._enable_webhook()
        self.store.save_notification_intelligence_settings(repeat_escalate_count="2")
        row = self.store.upsert_notification(
            dedupe_key="telemetry:external-escalate", source="telemetry", event_type="incident",
            severity="warning", title="Warning", subject="192.168.2.26",
        )
        self.store.upsert_notification(
            dedupe_key="telemetry:external-escalate", source="telemetry", event_type="incident",
            severity="warning", title="Warning", subject="192.168.2.26",
        )
        result = self.store.evaluate_notification_intelligence()
        self.assertEqual(1, result["escalated"])
        with self.store._db() as db:
            rows = [dict(r) for r in db.execute(
                "SELECT kind,status FROM notification_external_deliveries WHERE notification_id=? ORDER BY id",
                (row["id"],),
            ).fetchall()]
        self.assertEqual("cancelled", rows[0]["status"])
        self.assertTrue(any(item["kind"] == "escalation" and item["status"] == "pending" for item in rows))

    def test_external_retry_is_durable_and_nonretryable_failure_is_terminal(self):
        self._enable_webhook()
        queued = self.store.enqueue_notification_external_test(channel="webhook")
        row = self.store.claim_notification_external_deliveries(limit=1)[0]
        self.assertEqual(queued["delivery_id"], row["id"])
        retry = self.store.fail_notification_external_delivery(row["id"], "temporary", retryable=True)
        self.assertEqual("pending", retry["status"])
        with self.store._db() as db:
            db.execute("UPDATE notification_external_deliveries SET available_at='1970-01-01T00:00:00+00:00' WHERE id=?", (row["id"],))
        claimed = self.store.claim_notification_external_deliveries(limit=1)[0]
        terminal = self.store.fail_notification_external_delivery(claimed["id"], "bad request", retryable=False, http_status=400)
        self.assertEqual("failed", terminal["status"])
        self.assertEqual(400, terminal["http_status"])


class ExternalDeliveryServiceTests(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(prefix="zen-external-worker-", suffix=".db")
        os.close(fd)
        self.store = PolicyStore(self.path)
        self.audit_rows = []

    def tearDown(self):
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass

    def service(self, *, email_sender=None, webhook_sender=None):
        return NotificationExternalDeliveryService(
            policy_store=self.store,
            audit=lambda *args: self.audit_rows.append(args),
            email_sender=email_sender,
            webhook_sender=webhook_sender,
            poll_seconds=2,
        )

    def _enable_webhook(self):
        with patch.dict(os.environ, {"ZEN_WEBHOOK_ALLOW_HTTP": "1"}, clear=False):
            self.store.save_notification_external_delivery_settings(
                webhook_enabled="1", webhook_name="sink", webhook_url="http://webhook-sink:8092/webhook"
            )

    def test_snapshot_never_exposes_smtp_password_or_webhook_secret(self):
        self._enable_webhook()
        with patch.dict(os.environ, {
            "ZEN_SMTP_ENABLED": "1", "ZEN_SMTP_HOST": "mailpit", "ZEN_SMTP_PORT": "1025",
            "ZEN_SMTP_FROM": "zen@example.test", "ZEN_SMTP_TO": "parent@example.test",
            "ZEN_SMTP_PASSWORD": "super-secret-password", "ZEN_WEBHOOK_SIGNING_SECRET": "webhook-secret",
        }, clear=False):
            snapshot = self.service(email_sender=lambda *_: None, webhook_sender=lambda *_: None).snapshot()
        dumped = json.dumps(snapshot)
        self.assertNotIn("super-secret-password", dumped)
        self.assertNotIn("webhook-secret", dumped)
        self.assertTrue(snapshot["channels"]["email"]["ready"])
        self.assertTrue(snapshot["channels"]["webhook"]["ready"])

    def test_worker_delivers_email_and_webhook_with_injected_real_boundaries(self):
        self._enable_webhook()
        delivered = []
        env = {
            "ZEN_SMTP_ENABLED": "1", "ZEN_SMTP_TO": "parent@example.test",
            "ZEN_WEBHOOK_SIGNING_SECRET": "test-secret",
        }
        with patch.dict(os.environ, env, clear=False):
            self.store.upsert_notification(
                dedupe_key="security:fanout", source="security", event_type="incident",
                severity="critical", title="Fanout",
            )
            service = self.service(
                email_sender=lambda payload, destination, row: delivered.append(("email", payload, destination, row["id"])),
                webhook_sender=lambda payload, destination, row: delivered.append(("webhook", payload, destination, row["id"])),
            )
            result = service.run_cycle()
        self.assertEqual("ok", result["result"])
        self.assertEqual(2, result["sent"])
        self.assertEqual({"email", "webhook"}, {item[0] for item in delivered})
        self.assertEqual(2, sum(v["sent"] for v in self.store.notification_external_delivery_stats()["channels"].values()))

    def test_real_webhook_adapter_signs_raw_json_and_idempotency_headers(self):
        self._enable_webhook()
        captured = {}

        class Response:
            status = 204
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                return False

        def fake_urlopen(request, timeout):
            captured["request"] = request
            captured["timeout"] = timeout
            return Response()

        service = self.service()
        payload = {"event": "notification.test", "title": "Signed", "severity": "info"}
        row = {"id": 42, "idempotency_key": "external-test-idempotency"}
        with patch.dict(os.environ, {"ZEN_WEBHOOK_SIGNING_SECRET": "unit-secret"}, clear=False), \
             patch("app.external_delivery.urllib.request.urlopen", side_effect=fake_urlopen):
            service._send_webhook(payload, "https://hooks.example.test/zen", row)
        request = captured["request"]
        timestamp = request.headers["X-zen-timestamp"]
        body = request.data
        import hashlib, hmac
        expected = hmac.new(b"unit-secret", timestamp.encode("ascii") + b"." + body, hashlib.sha256).hexdigest()
        self.assertEqual(f"sha256={expected}", request.headers["X-zen-signature"] )
        self.assertEqual("external-test-idempotency", request.headers["Idempotency-key"])
        self.assertEqual("notification.test", request.headers["X-zen-event"])

    def test_http_410_retires_webhook_destination(self):
        self._enable_webhook()
        self.store.enqueue_notification_external_test(channel="webhook")

        def gone(*_args):
            raise ExternalDeliveryError("gone", status_code=410, retryable=False, retire_destination=True)

        result = self.service(webhook_sender=gone).run_cycle()
        self.assertEqual("degraded", result["result"])
        self.assertEqual(1, result["retired"])
        self.assertFalse(self.store.notification_external_delivery_settings()["webhook_enabled"])

    def test_smtp_readiness_rejects_ssl_and_starttls_together(self):
        with patch.dict(os.environ, {
            "ZEN_SMTP_ENABLED": "1", "ZEN_SMTP_HOST": "smtp.example.test",
            "ZEN_SMTP_FROM": "zen@example.test", "ZEN_SMTP_TO": "parent@example.test",
            "ZEN_SMTP_SSL": "1", "ZEN_SMTP_STARTTLS": "1",
        }, clear=False):
            status = self.service(email_sender=lambda *_: None).readiness()["email"]
        self.assertFalse(status["ready"])
        self.assertIn("cannot both", status["error"])


class ExternalDeliverySurfaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = (ROOT / "app" / "main.py").read_text()
        cls.template = (ROOT / "app" / "templates" / "index.html").read_text()
        cls.compose = (ROOT / "docker-compose.yml").read_text()
        cls.env_example = (ROOT / ".env.example").read_text()
        cls.sink = (ROOT / "test-tools" / "webhook_sink.py").read_text()

    def test_delivery_is_first_class_notification_section_and_api(self):
        self.assertIn('"notifications": ("inbox", "preferences", "intelligence", "delivery", "history")', self.main)
        self.assertIn('@app.get("/api/notifications/delivery")', self.main)
        self.assertIn('@app.post("/local/notifications/delivery")', self.main)
        self.assertIn('@app.post("/local/notifications/delivery/test/{channel}")', self.main)
        self.assertIn('data-ux-group="delivery"', self.template)
        self.assertIn("External delivery", self.template)

    def test_smtp_configuration_is_environment_only_and_documented(self):
        for name in (
            "ZEN_SMTP_ENABLED", "ZEN_SMTP_HOST", "ZEN_SMTP_PORT", "ZEN_SMTP_USERNAME",
            "ZEN_SMTP_PASSWORD", "ZEN_SMTP_FROM", "ZEN_SMTP_FROM_NAME", "ZEN_SMTP_TO",
            "ZEN_SMTP_STARTTLS", "ZEN_SMTP_SSL",
        ):
            self.assertIn(name, self.env_example)
            self.assertIn(name, self.compose)
        self.assertNotIn('name="smtp_password"', self.template)
        self.assertNotIn('name="smtp_username"', self.template)

    def test_optional_test_tools_profile_contains_mailpit_and_signed_webhook_sink(self):
        self.assertIn('profiles: ["test-tools"]', self.compose)
        self.assertIn("axllent/mailpit", self.compose)
        self.assertIn("webhook-sink:", self.compose)
        self.assertIn("X-ZEN-Signature", self.sink)
        self.assertIn("hmac.compare_digest", self.sink)
        self.assertIn("?status=500", self.sink)

    def test_authority_boundary_and_release_identity_are_explicit(self):
        external = (ROOT / "app" / "external_delivery.py").read_text()
        self.assertNotIn("RouterOSAdapter", external)
        self.assertIn("no RouterOS dependency", external)
        self.assertIn('authority": "notification-delivery-only-no-routeros-authority"', external)
        self.assertIn('version="0.58.0"', self.main)


if __name__ == "__main__":
    unittest.main()
