import sys
import types
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Keep host-side validation independent of psycopg installation.
psycopg = types.ModuleType("psycopg")
psycopg.Error = Exception
psycopg.connect = None
rows = types.ModuleType("psycopg.rows")
rows.dict_row = object()
sys.modules.setdefault("psycopg", psycopg)
sys.modules.setdefault("psycopg.rows", rows)

from app.activity import ActivityStore
from app.policy_history import build_policy_intervals, build_policy_correlation_report
from app.policy_store import PolicyStore


class HistoricalPolicyStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PolicyStore(str(Path(self.tmp.name) / "policy.db"))
        self.policy = {
            "mode": "normal",
            "mode_source": "profile: Child",
            "bandwidth_preset": "normal",
            "blocked_services": ["youtube"],
            "blocked_policy_groups": [],
            "schedule_active": False,
            "schedule_reason": None,
            "active_date_exception": None,
            "quota_state": {"configured": False, "enabled": False, "available": True},
            "policy_at": "2026-09-09T20:00+01:00",
        }

    def tearDown(self):
        self.tmp.cleanup()

    def test_policy_checkpoint_is_change_only_and_policy_at_does_not_create_noise(self):
        first = self.store.record_policy_state("192.168.2.10", self.policy, captured_at="2026-09-09T18:00:00+00:00")
        later = dict(self.policy, policy_at="2026-09-09T20:05+01:00")
        second = self.store.record_policy_state("192.168.2.10", later, captured_at="2026-09-09T18:05:00+00:00")
        changed = dict(self.policy, mode="blocked", mode_source="schedule: bedtime")
        third = self.store.record_policy_state("192.168.2.10", changed, captured_at="2026-09-09T18:10:00+00:00")
        self.assertTrue(first["created"])
        self.assertFalse(second["created"])
        self.assertTrue(third["created"])
        rows = self.store.list_policy_state_history("192.168.2.10")
        self.assertEqual(2, len(rows))
        self.assertEqual("blocked", rows[-1]["desired_mode"])

    def test_history_range_includes_last_checkpoint_before_window_start(self):
        self.store.record_policy_state("192.168.2.10", self.policy, captured_at="2026-09-09T17:00:00+00:00")
        changed = dict(self.policy, mode="slow", mode_source="schedule: evening")
        self.store.record_policy_state("192.168.2.10", changed, captured_at="2026-09-09T19:00:00+00:00")
        rows = self.store.list_policy_state_history(
            "192.168.2.10", "2026-09-09T18:00:00+00:00", "2026-09-09T20:00:00+00:00"
        )
        self.assertEqual(2, len(rows))
        self.assertEqual("normal", rows[0]["desired_mode"])
        self.assertEqual("slow", rows[1]["desired_mode"])

    def test_database_integrity_includes_policy_history(self):
        report = self.store.database_integrity_report()
        self.assertTrue(report["ok"])
        self.assertIn("policy_state_history", report["table_counts"])


class HistoricalPolicyCompositionTests(unittest.TestCase):
    def test_pre_checkpoint_time_is_explicitly_unknown(self):
        history = [{
            "captured_at": "2026-09-09T19:00:00+00:00",
            "state_hash": "a",
            "desired_mode": "blocked",
            "mode_source": "schedule: bedtime",
            "bandwidth_preset": "normal",
            "blocked_services": [],
            "policy_groups": [],
        }]
        intervals = build_policy_intervals(
            history, "2026-09-09T18:00:00+00:00", "2026-09-09T20:00:00+00:00"
        )
        self.assertEqual(2, len(intervals))
        self.assertFalse(intervals[0]["known"])
        self.assertTrue(intervals[1]["known"])

    def test_report_correlates_usage_without_claiming_routeros_execution(self):
        history = [{
            "captured_at": "2026-09-09T18:00:00+00:00", "state_hash": "a",
            "desired_mode": "normal", "mode_source": "profile: Child", "bandwidth_preset": "normal",
            "blocked_services": ["youtube"], "policy_groups": [],
        }, {
            "captured_at": "2026-09-09T19:00:00+00:00", "state_hash": "b",
            "desired_mode": "blocked", "mode_source": "schedule: bedtime", "bandwidth_preset": "normal",
            "blocked_services": ["youtube"], "policy_groups": [],
        }]
        usage = [
            {"index": 0, "total_bytes": 1000, "total_bytes_human": "1000 B", "dns_blocked": 2},
            {"index": 1, "total_bytes": 100, "total_bytes_human": "100 B", "dns_blocked": 7},
        ]
        report = build_policy_correlation_report(
            device_ip="192.168.2.10", device_name="Tablet", history=history, usage=usage,
            start="2026-09-09T18:00:00+00:00", end="2026-09-09T20:00:00+00:00",
            timezone_name="Europe/London",
        )
        self.assertEqual("zen_policy_correlation_v1", report["schema"])
        self.assertEqual(100.0, report["coverage_percent"])
        self.assertEqual(1000, report["mode_bytes"]["normal"])
        self.assertEqual(100, report["mode_bytes"]["blocked"])
        self.assertEqual(7 + 2, report["total_dns_blocked"])
        self.assertIn("not historical RouterOS execution", report["evidence_note"])


class IntervalUsageQueryTests(unittest.TestCase):
    def test_interval_usage_uses_two_queries_not_n_plus_one(self):
        store = ActivityStore()
        calls = []

        def fake_query(sql, params=()):
            calls.append(sql)
            count = 3
            if "flow_5m" in sql:
                return [{"idx": i, "total_bytes": 0, "download_bytes": 0, "upload_bytes": 0, "classified_bytes": 0, "flows": 0} for i in range(count)]
            return [{"idx": i, "dns_queries": 0, "dns_blocked": 0, "unique_domains": 0} for i in range(count)]

        store._query = fake_query
        base = datetime(2026, 9, 9, 18, tzinfo=timezone.utc)
        intervals = [
            {"start": (base + timedelta(hours=i)).isoformat(), "end": (base + timedelta(hours=i + 1)).isoformat()}
            for i in range(3)
        ]
        rows = store.policy_interval_usage("192.168.2.10", intervals)
        self.assertEqual(3, len(rows))
        self.assertEqual(2, len(calls))


class HistoricalPolicyUxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = Path("app/main.py").read_text()
        cls.store = Path("app/policy_store.py").read_text()
        cls.template = Path("app/templates/policy_history.html").read_text()
        cls.index = Path("app/templates/index.html").read_text()
        cls.device360 = Path("app/templates/device_360.html").read_text()
        cls.css = Path("app/static/policy-history.css").read_text()

    def test_release_routes_and_stable_api_are_present(self):
        self.assertIn('version="0.54.5.2"', self.main)
        self.assertIn('@app.get("/activity/policy-history"', self.main)
        self.assertIn('@app.get("/api/activity/policy-history")', self.main)
        self.assertIn("zen_policy_correlation_v1", Path("app/policy_history.py").read_text())

    def test_history_is_captured_from_real_resolver_not_simulation(self):
        start = self.main.index('@timed("policy.effective_policy")')
        end = self.main.index('@timed("policy.live_plan")')
        source = self.main[start:end]
        self.assertIn("record_policy_state", source)
        self.assertIn("<= 300", source)
        self.assertIn("Future/past what-if", source)

    def test_startup_seeds_policy_history_without_routeros_authority(self):
        self.assertIn("Seed v0.33 policy history", self.main)
        module = Path("app/policy_history.py").read_text()
        self.assertNotIn("RouterOSAdapter", module)
        self.assertNotIn("set_device", module)

    def test_ui_exposes_correlation_from_history_and_device_surfaces(self):
        self.assertIn("Policy correlation", self.index)
        self.assertIn("/activity/policy-history?period=7d", self.index)
        self.assertIn("Policy history", self.device360)
        self.assertIn("Historical policy gap", self.template)
        self.assertIn("Why this state now?", self.template)

    def test_ui_preserves_evidence_boundary_and_has_no_write_form(self):
        self.assertIn("proof that every desired RouterOS action executed successfully", self.template)
        self.assertNotIn('method="post"', self.template.lower())
        self.assertIn("will not reconstruct this interval", self.template)

    def test_css_is_dense_and_tablet_responsive(self):
        self.assertIn("grid-template-columns:repeat(6", self.css)
        self.assertIn("@media(max-width:1050px)", self.css)
        self.assertIn("@media(max-width:650px)", self.css)

    def test_policy_history_table_is_not_part_of_configuration_export_identity(self):
        # Historical evidence is operational data, not desired configuration to restore elsewhere.
        export_section = self.store[self.store.index("def export_config"):self.store.index("def import_config")]
        self.assertNotIn("policy_state_history", export_section)


if __name__ == "__main__":
    unittest.main()
