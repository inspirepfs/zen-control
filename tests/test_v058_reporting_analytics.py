import tempfile
import unittest
import sys
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Keep host-side validation independent of psycopg installation.
psycopg = types.ModuleType("psycopg")
psycopg.Error = Exception
psycopg.connect = None
rows = types.ModuleType("psycopg.rows")
rows.dict_row = object()
psycopg.rows = rows
sys.modules.setdefault("psycopg", psycopg)
sys.modules.setdefault("psycopg.rows", rows)

from app.policy_store import PolicyStore
from app.reporting import build_reporting_overview, metric_change, rank_movers

ROOT = Path(__file__).resolve().parents[1]


class ReportingPureContractTests(unittest.TestCase):
    def test_metric_change_does_not_invent_percentage_from_zero_baseline(self):
        item = metric_change(1024, 0, unit="bytes")
        self.assertIsNone(item["delta_percent"])
        self.assertEqual("new", "new" if item["previous"] == 0 and item["current"] else "changed")
        self.assertEqual(1024, item["delta"])

    def test_rank_movers_preserves_new_and_inactive_entities(self):
        current = [
            {"client_ip": "192.0.2.10", "display_name": "Tablet", "total_bytes": 3000},
            {"client_ip": "192.0.2.20", "display_name": "Phone", "total_bytes": 500},
        ]
        previous = [
            {"client_ip": "192.0.2.10", "display_name": "Tablet", "total_bytes": 1000},
            {"client_ip": "192.0.2.30", "display_name": "Console", "total_bytes": 4000},
        ]
        rows = rank_movers(current, previous, key="client_ip", label="display_name", limit=10)
        by_key = {row["key"]: row for row in rows}
        self.assertEqual("new", by_key["192.0.2.20"]["state"])
        self.assertEqual("inactive", by_key["192.0.2.30"]["state"])
        self.assertEqual(200.0, by_key["192.0.2.10"]["delta_percent"])

    def test_overview_preserves_unknown_classification_and_authority_boundary(self):
        report = build_reporting_overview(
            window={"label": "7 days", "start_date": "2026-09-01", "end_date": "2026-09-07"},
            current={"total_bytes": 10, "dns_queries": 0, "dns_blocked": 0},
            previous={"total_bytes": 5, "dns_queries": 0, "dns_blocked": 0},
            daily=[], current_devices=[], previous_devices=[], current_services=[], previous_services=[],
            new_domains=[], blocked_domains=[],
            classification_current={"traffic_percent": None, "dns_percent": None, "traffic_evidence_status": "unavailable", "dns_evidence_status": "no_evidence", "evidence_status": "partial"},
            classification_previous={"traffic_percent": 90.0, "dns_percent": 80.0, "traffic_evidence_status": "observed", "dns_evidence_status": "observed", "evidence_status": "observed"},
            notification_report={}, incident_report={},
            policy_history={"checkpoints": 4, "addresses": 2},
            policy_window={"checkpoints": 2, "quota_active_checkpoints": 1},
            config_analytics={"counts": {"profiles": 3, "device_policy": 4, "services": 5}},
        )
        self.assertEqual("read-only-reporting-no-routeros-authority", report["authority"])
        self.assertIsNone(report["classification"]["traffic"]["current"])
        self.assertEqual("unavailable", report["classification"]["traffic"]["current_status"])
        self.assertIsNone(report["policy_signals"]["dns_block_rate"])
        self.assertIn("not continuous historical RouterOS execution", report["evidence_note"])


class ReportingLifecycleRangeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PolicyStore(str(Path(self.tmp.name) / "policy.db"))
        self.start = datetime(2026, 9, 1, tzinfo=timezone.utc)
        self.end = self.start + timedelta(days=7)

    def tearDown(self):
        self.tmp.cleanup()

    def test_notification_reporting_range_counts_lifecycle_without_hiding_current_state(self):
        created = self.start + timedelta(days=1)
        ack = created + timedelta(minutes=10)
        resolved = created + timedelta(hours=2)
        with self.store._db() as db:
            db.execute(
                """INSERT INTO notifications
                   (dedupe_key,source,event_type,subject,severity,state,title,detail,source_ref,target_url,
                    created_at,first_seen_at,last_seen_at,updated_at,occurrences,read_at,read_by,
                    acknowledged_at,acknowledged_by,dismissed_at,dismissed_by,resolved_at,resolved_by,resolution,
                    attention_eligible_at,source_severity,correlation_key,escalation_level,escalated_at,
                    escalation_reason,reopen_count)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    "report:test", "telemetry:dns", "degraded", "dns", "warning", "acknowledged",
                    "DNS degraded", "detail", "", "", created.isoformat(), created.isoformat(),
                    created.isoformat(), resolved.isoformat(), 3, ack.isoformat(), "parent", ack.isoformat(),
                    "parent", None, "", resolved.isoformat(), "system", "cleared", "", "warning",
                    "telemetry:dns:dns", 1, (created + timedelta(minutes=30)).isoformat(), "age", 0,
                ),
            )
        report = self.store.notification_reporting_range(self.start, self.end)
        self.assertEqual(1, report["created"])
        self.assertEqual(3, report["occurrences_on_created_rows"])
        self.assertEqual(1, report["resolved"])
        self.assertEqual(1, report["acknowledged"])
        self.assertEqual(1, report["escalated"])
        self.assertEqual(600.0, report["median_ack_seconds"])
        self.assertEqual("attention-reporting-only", report["authority"])

    def test_policy_reporting_range_keeps_quota_and_schedule_as_checkpoint_evidence(self):
        captured = self.start + timedelta(days=3)
        with self.store._db() as db:
            db.execute(
                """INSERT INTO policy_state_history
                   (captured_at,ip,state_hash,source,desired_mode,mode_source,bandwidth_preset,blocked_services,
                    policy_groups,schedule_active,schedule_reason,active_date_exception,quota_state,policy_at,identity_id,device_name)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    captured.isoformat(), "192.0.2.50", "abc", "effective-resolver", "blocked", "quota",
                    "normal", "[]", "[]", 1, "schedule", "{}",
                    '{"configured":true,"available":true,"active":true,"service_active":true,"daily_exhausted":false}',
                    captured.isoformat(), "id-1", "Tablet",
                ),
            )
        report = self.store.policy_reporting_range(self.start, self.end)
        self.assertEqual(1, report["checkpoints"])
        self.assertEqual(1, report["schedule_active_checkpoints"])
        self.assertEqual(1, report["blocked_mode_checkpoints"])
        self.assertEqual(1, report["quota_active_checkpoints"])
        self.assertEqual(1, report["quota_service_active_checkpoints"])
        self.assertEqual("desired-policy-checkpoints-only", report["authority"])

    def test_incident_reporting_range_tracks_resolution_sample_and_current_active(self):
        opened = self.start + timedelta(days=2)
        resolved = opened + timedelta(minutes=45)
        with self.store._db() as db:
            db.execute(
                """INSERT INTO incidents
                   (fingerprint,source,subject,severity,status,title,detail,opened_at,first_seen_at,last_seen_at,
                    updated_at,occurrences,acknowledged_at,acknowledged_by,resolved_at,resolved_by,resolution,suppress_until_clear)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    "incident:one", "operations:worker", "worker", "warning", "resolved", "Worker recovered",
                    "detail", opened.isoformat(), opened.isoformat(), resolved.isoformat(), resolved.isoformat(),
                    1, None, "", resolved.isoformat(), "system", "recovered", 0,
                ),
            )
            active = self.end + timedelta(days=1)
            db.execute(
                """INSERT INTO incidents
                   (fingerprint,source,subject,severity,status,title,detail,opened_at,first_seen_at,last_seen_at,
                    updated_at,occurrences,acknowledged_at,acknowledged_by,resolved_at,resolved_by,resolution,suppress_until_clear)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    "incident:two", "security:authority", "router", "critical", "open", "Authority unavailable",
                    "detail", active.isoformat(), active.isoformat(), active.isoformat(), active.isoformat(),
                    1, None, "", None, "", "", 0,
                ),
            )
        report = self.store.incident_reporting_range(self.start, self.end)
        self.assertEqual(1, report["opened"])
        self.assertEqual(1, report["resolved"])
        self.assertEqual(2700.0, report["median_resolution_seconds"])
        self.assertEqual(1, report["active_now"])
        self.assertEqual(1, report["critical_active_now"])
        self.assertEqual("operational-evidence-only", report["authority"])


class V058SourceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = (ROOT / "app" / "main.py").read_text()
        cls.index = (ROOT / "app" / "templates" / "index.html").read_text()
        cls.template = (ROOT / "app" / "templates" / "reporting.html").read_text()
        cls.reporting = (ROOT / "app" / "reporting.py").read_text()
        cls.help = (ROOT / "app" / "help_content.py").read_text()

    def test_release_routes_ui_export_and_prepared_view_are_wired(self):
        self.assertIn('version="0.58.0"', self.main)
        self.assertIn('@app.get("/api/reporting/overview")', self.main)
        self.assertIn('@app.get("/reporting", response_class=HTMLResponse)', self.main)
        self.assertIn('@app.get("/reporting/export.csv")', self.main)
        self.assertIn('("reporting:7d", "analytics:reporting", 300)', self.main)
        self.assertIn('data-ux-group="reports"', self.index)
        self.assertIn("REPORTING &amp; ANALYTICS", self.template)
        self.assertIn("Export CSV", self.template)
        self.assertIn('"activity_reporting"', self.help)

    def test_reporting_is_read_only_and_keeps_evidence_boundaries(self):
        self.assertIn("read-only-reporting-no-routeros-authority", self.reporting)
        self.assertNotIn("RouterOSAdapter", self.reporting)
        self.assertNotIn(".write(", self.reporting)
        self.assertIn("not continuous historical RouterOS execution", self.reporting)
        self.assertIn("UNKNOWN/UNAVAILABLE", self.reporting)


if __name__ == "__main__":
    unittest.main()
