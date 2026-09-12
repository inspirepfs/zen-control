import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from app.policy_store import PolicyStore
from app.summary_delivery import (
    SummaryDeliveryService,
    build_webhook_payload,
    normalize_delivery_time,
    normalize_email_recipients,
    normalize_webhook_url,
    render_summary_text,
)

ROOT = Path(__file__).resolve().parents[1]


def sample_summary(period="yesterday"):
    start_day = 8 if period == "yesterday" else 9
    return {
        "period": period,
        "timezone_name": "Europe/London",
        "window": {
            "start": datetime(2026, 9, start_day, 0, 0, tzinfo=timezone.utc),
            "end": datetime(2026, 9, start_day, 23, 59, tzinfo=timezone.utc),
        },
        "household": {
            "managed_devices": 2,
            "active_devices": 1,
            "new_domains": 3,
            "unclassified_new_domains": 1,
            "quota_warnings": 1,
            "quota_exhausted": 0,
            "current": {
                "total_bytes": 1024,
                "total_human": "1.0 KiB",
                "dns_queries": 20,
                "dns_blocked": 2,
            },
        },
        "devices": [
            {
                "ip": "192.168.2.20",
                "name": "Tablet",
                "current": {"total_bytes": 1024, "total_human": "1.0 KiB", "dns_queries": 20, "dns_blocked": 2},
                "signals": ["blocked_dns", "new_domains"],
            }
        ],
        "attention_domains": [{"domain": "new.example", "tags": ["new"]}],
        "evidence_note": "Summary facts come from retained IPFIX and Pi-hole DNS evidence.",
    }


class DeliveryValidationTests(unittest.TestCase):
    def test_email_recipient_normalization_deduplicates_and_rejects_bad_values(self):
        self.assertEqual(
            normalize_email_recipients("Parent@example.com; parent@example.com, other@example.net"),
            ["Parent@example.com", "other@example.net"],
        )
        with self.assertRaises(ValueError):
            normalize_email_recipients("not-an-email")

    def test_webhook_rejects_embedded_credentials_and_non_http_schemes(self):
        self.assertEqual(normalize_webhook_url("http://homeassistant.local/hook/abc"), "http://homeassistant.local/hook/abc")
        with self.assertRaises(ValueError):
            normalize_webhook_url("http://user:secret@example.test/hook")
        with self.assertRaises(ValueError):
            normalize_webhook_url("file:///tmp/hook")

    def test_delivery_time_is_strict_24_hour_hhmm(self):
        self.assertEqual(normalize_delivery_time("7:05"), "07:05")
        with self.assertRaises(ValueError):
            normalize_delivery_time("25:00")

    def test_rendered_summary_keeps_evidence_boundary(self):
        text = render_summary_text(sample_summary())
        self.assertIn("ZEN Control parent summary", text)
        self.assertIn("not browser history", text)
        self.assertIn("Tablet (192.168.2.20)", text)


class DeliveryStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = PolicyStore(str(Path(self.temp.name) / "policy.db"))

    def tearDown(self):
        self.temp.cleanup()

    def test_delivery_defaults_are_disabled_and_enable_requires_channel(self):
        settings = self.store.get_settings()
        self.assertEqual(settings["summary_delivery_enabled"], "0")
        self.assertEqual(settings["summary_delivery_period"], "yesterday")
        with self.assertRaises(ValueError):
            self.store.save_summary_delivery_settings(enabled="1")

    def test_scheduled_outbox_is_idempotent_per_report_period_channel(self):
        payload = build_webhook_payload(sample_summary())
        first = self.store.enqueue_summary_delivery(
            report_date="2026-09-08", period="yesterday", channel="webhook",
            destination="http://ha.local/hook", payload=payload,
        )
        second = self.store.enqueue_summary_delivery(
            report_date="2026-09-08", period="yesterday", channel="webhook",
            destination="http://ha.local/hook2", payload=payload,
        )
        self.assertTrue(first["created"])
        self.assertFalse(second["created"])
        self.assertEqual(first["id"], second["id"])
        self.assertEqual(second["destination"], "http://ha.local/hook2")
        self.assertEqual(len(self.store.list_summary_deliveries()), 1)

    def test_terminal_failure_can_be_explicitly_retried(self):
        row = self.store.enqueue_summary_delivery(
            report_date="2026-09-08", period="yesterday", channel="webhook",
            destination="http://ha.local/hook", payload={}, kind="test", unique_suffix="one",
        )
        claimed = self.store.claim_summary_deliveries(retry_limit=1)
        self.assertEqual(claimed[0]["attempts"], 1)
        failed = self.store.fail_summary_delivery(row["id"], "boom", retry_limit=1)
        self.assertEqual(failed["status"], "failed")
        retried = self.store.retry_summary_delivery(row["id"])
        self.assertEqual(retried["status"], "pending")
        self.assertEqual(retried["attempts"], 0)

    def test_interrupted_sending_row_is_recovered_without_new_identity(self):
        row = self.store.enqueue_summary_delivery(
            report_date="2026-09-08", period="yesterday", channel="webhook",
            destination="http://ha.local/hook", payload={},
        )
        self.store.claim_summary_deliveries()
        recovered = self.store.recover_summary_deliveries()
        self.assertEqual(recovered, 1)
        current = self.store.list_summary_deliveries()[0]
        self.assertEqual(current["id"], row["id"])
        self.assertEqual(current["status"], "retry")
        self.assertIn("interrupted", current["error"].lower())

    def test_disabling_channel_cancels_unsent_work(self):
        self.store.enqueue_summary_delivery(
            report_date="2026-09-08", period="yesterday", channel="webhook",
            destination="http://ha.local/hook", payload={},
        )
        cancelled = self.store.cancel_disabled_summary_deliveries(
            scheduled_enabled=True, enabled_channels=set()
        )
        self.assertEqual(cancelled, 1)
        self.assertEqual(self.store.list_summary_deliveries()[0]["status"], "cancelled")

    def test_config_backup_restore_preserves_non_secret_delivery_settings(self):
        self.store.save_summary_delivery_settings(
            enabled="0", delivery_time="06:45", period="yesterday",
            email_enabled="1", email_to="parent@example.com",
            webhook_enabled="1", webhook_url="http://ha.local/hook",
            retry_limit="5", retention_days="180",
        )
        payload = self.store.export_config()
        target = PolicyStore(str(Path(self.temp.name) / "restored.db"))
        target.import_config(payload)
        settings = target.get_settings()
        self.assertEqual(settings["summary_delivery_time"], "06:45")
        self.assertEqual(settings["summary_delivery_email_to"], "parent@example.com")
        self.assertEqual(settings["summary_delivery_webhook_url"], "http://ha.local/hook")
        self.assertEqual(settings["summary_delivery_retry_limit"], "5")


class DeliveryServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = PolicyStore(str(Path(self.temp.name) / "policy.db"))
        self.audit_events = []
        self.summary_calls = []
        self.sent = []

    def tearDown(self):
        self.temp.cleanup()

    def builder(self, period):
        self.summary_calls.append(period)
        return sample_summary(period)

    def audit(self, event, actor, detail=""):
        self.audit_events.append((event, actor, detail))

    def test_scheduler_queues_once_after_due_and_does_not_requery_summary(self):
        self.store.save_summary_delivery_settings(
            enabled="1", delivery_time="07:00", period="yesterday",
            webhook_enabled="1", webhook_url="http://ha.local/hook",
        )
        service = SummaryDeliveryService(
            policy_store=self.store, summary_builder=self.builder, audit=self.audit,
            webhook_sender=lambda payload, destination, row: self.sent.append(row["id"]),
        )
        before = datetime(2026, 9, 9, 5, 30, tzinfo=timezone.utc)  # 06:30 BST
        after = datetime(2026, 9, 9, 6, 30, tzinfo=timezone.utc)   # 07:30 BST
        self.assertEqual(service.enqueue_due(now=before), [])
        first = service.enqueue_due(now=after)
        second = service.enqueue_due(now=after)
        self.assertEqual(len(first), 1)
        self.assertTrue(first[0]["created"])
        self.assertEqual(len(second), 1)
        self.assertFalse(second[0]["created"])
        self.assertEqual(self.summary_calls, ["yesterday"])
        self.assertEqual(first[0]["report_date"], "2026-09-08")

    def test_test_email_can_send_while_daily_schedule_is_disabled(self):
        self.store.save_summary_delivery_settings(
            enabled="0", email_enabled="1", email_to="parent@example.com"
        )
        service = SummaryDeliveryService(
            policy_store=self.store, summary_builder=self.builder, audit=self.audit,
            email_sender=lambda payload, destination, row: self.sent.append((destination, row["id"])),
        )
        with patch.dict(os.environ, {"SUMMARY_SMTP_HOST": "smtp.local", "SUMMARY_SMTP_FROM": "zen@example.com"}, clear=False):
            row = service.enqueue_test("email", actor="parent", period="today")
            result = service.process_outbox()
        self.assertEqual(result["sent"], 1)
        self.assertEqual(self.sent[0][0], "parent@example.com")
        current = next(item for item in self.store.list_summary_deliveries() if item["id"] == row["id"])
        self.assertEqual(current["status"], "sent")
        self.assertTrue(any(event[0] == "SUMMARY_DELIVERY_SENT" for event in self.audit_events))

    def test_transport_failure_is_bounded_and_audited(self):
        self.store.save_summary_delivery_settings(
            enabled="0", webhook_enabled="1", webhook_url="http://ha.local/hook", retry_limit="1"
        )
        service = SummaryDeliveryService(
            policy_store=self.store, summary_builder=self.builder, audit=self.audit,
            webhook_sender=lambda payload, destination, row: (_ for _ in ()).throw(RuntimeError("receiver down")),
        )
        service.enqueue_test("webhook", actor="parent", period="today")
        result = service.process_outbox()
        self.assertEqual(result["failed"], 1)
        self.assertEqual(self.store.list_summary_deliveries()[0]["status"], "failed")
        self.assertTrue(any(event[0] == "SUMMARY_DELIVERY_FAILED" for event in self.audit_events))

    def test_summary_generation_failure_uses_backoff_without_blocking_outbox(self):
        self.store.save_summary_delivery_settings(
            enabled="1", delivery_time="00:00", webhook_enabled="1", webhook_url="http://ha.local/hook"
        )
        calls = []
        def broken_builder(period):
            calls.append(period)
            raise RuntimeError("telemetry unavailable")
        service = SummaryDeliveryService(
            policy_store=self.store, summary_builder=broken_builder, audit=self.audit,
            webhook_sender=lambda payload, destination, row: self.sent.append(row["id"]),
        )
        now = datetime(2026, 9, 9, 12, 0, tzinfo=timezone.utc)
        first = service.run_cycle(now=now)
        second = service.run_cycle(now=now)
        self.assertEqual(first["result"], "degraded")
        self.assertEqual(second["result"], "degraded")
        self.assertEqual(calls, ["yesterday"])
        self.assertGreater(service.snapshot()["generation_failures"], 0)
        self.assertTrue(any(event[0] == "SUMMARY_DELIVERY_GENERATION_FAILED" for event in self.audit_events))

    def test_disabled_channel_cannot_escape_from_existing_outbox(self):
        self.store.save_summary_delivery_settings(
            enabled="1", delivery_time="00:00", webhook_enabled="1", webhook_url="http://ha.local/hook"
        )
        service = SummaryDeliveryService(
            policy_store=self.store, summary_builder=self.builder, audit=self.audit,
            webhook_sender=lambda payload, destination, row: self.sent.append(row["id"]),
        )
        service.enqueue_due(now=datetime(2026, 9, 9, 12, 0, tzinfo=timezone.utc))
        self.store.save_summary_delivery_settings(enabled="0", webhook_enabled="0", webhook_url="")
        service.reconcile_configuration()
        service.process_outbox()
        self.assertEqual(self.sent, [])
        self.assertEqual(self.store.list_summary_deliveries()[0]["status"], "cancelled")


class DeliveryUxTests(unittest.TestCase):
    def setUp(self):
        self.main = (ROOT / "app/main.py").read_text()
        self.index = (ROOT / "app/templates/index.html").read_text()
        self.css = (ROOT / "app/static/app.css").read_text()
        self.compose = (ROOT / "docker-compose.yml").read_text()
        self.env = (ROOT / ".env.example").read_text()
        self.readme = (ROOT / "README.md").read_text() + "\n" + (ROOT / "CHANGELOG.md").read_text()

    def test_release_routes_and_automation_ui_are_present(self):
        self.assertIn('version="0.54.5.3"', self.main)
        self.assertIn('@app.get("/api/summary-delivery")', self.main)
        self.assertIn('@app.post("/local/summary-delivery/settings")', self.main)
        self.assertIn('@app.post("/local/summary-delivery/test")', self.main)
        self.assertIn("Parent summary delivery", self.index)
        self.assertIn("30-day delivery", self.index)
        self.assertIn("Delivery history", self.index)

    def test_button_link_has_explicit_high_contrast_text_background_and_visited_state(self):
        self.assertIn('.button-link{display:inline-flex', self.css)
        self.assertIn('background:#26345e;color:#eef2ff', self.css)
        self.assertIn('.button-link:visited{color:#eef2ff}', self.css)
        self.assertIn('.button-link.primary{background:#4f6bf5;color:#fff', self.css)
        self.assertIn('/static/app.css?v=0.54.5.3', self.index)

    def test_transport_secrets_are_environment_based_and_compose_wired(self):
        for key in [
            "SUMMARY_SMTP_HOST", "SUMMARY_SMTP_PASSWORD", "SUMMARY_SMTP_FROM",
            "SUMMARY_WEBHOOK_TOKEN", "SUMMARY_DELIVERY_POLL_SECONDS",
        ]:
            self.assertIn(key, self.env)
            self.assertIn(key, self.compose)
        self.assertIn("environment-only secrets", self.readme)

    def test_ui_states_at_least_once_boundary_instead_of_exactly_once_claim(self):
        self.assertIn("at-least-once duplicate", self.index)
        self.assertIn("unavoidable at-least-once crash boundary", self.readme)


if __name__ == "__main__":
    unittest.main()
