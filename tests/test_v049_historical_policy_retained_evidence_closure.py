
import sys
import types
import sqlite3
import tempfile
import unittest
from pathlib import Path

psycopg = types.ModuleType("psycopg")
psycopg.Error = Exception
psycopg.connect = None
rows = types.ModuleType("psycopg.rows")
rows.dict_row = object()
sys.modules.setdefault("psycopg", psycopg)
sys.modules.setdefault("psycopg.rows", rows)

from app.activity import ActivityError, ActivityStore
from app.policy_history import build_policy_intervals, build_policy_correlation_report
from app.policy_store import PolicyStore


class V049PolicyIdentityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PolicyStore(str(Path(self.tmp.name) / "policy.db"))
        self.ip = "192.168.2.77"
        self.policy = {
            "mode": "blocked",
            "mode_source": "profile: Child",
            "bandwidth_preset": "normal",
            "blocked_services": ["youtube"],
            "blocked_policy_groups": [],
            "schedule_active": False,
            "schedule_reason": "",
            "active_date_exception": {},
            "quota_state": {"configured": False, "enabled": False, "available": True},
            "policy_at": "2026-09-10T12:00:00+01:00",
        }

    def tearDown(self):
        self.tmp.cleanup()

    def test_ip_reuse_gets_new_management_identity_and_same_policy_still_checkpoints(self):
        self.store.update_device(self.ip, alias="Old tablet")
        first_identity = self.store.get_managed_device_identity(self.ip)
        first = self.store.record_policy_state(
            self.ip, self.policy, captured_at="2026-09-10T11:00:00+00:00"
        )
        self.assertTrue(first["created"])

        self.store.retire_device_state(self.ip)
        self.store.update_device(self.ip, alias="Replacement tablet")
        second_identity = self.store.get_managed_device_identity(self.ip)
        self.assertNotEqual(first_identity["identity_id"], second_identity["identity_id"])

        second = self.store.record_policy_state(
            self.ip, self.policy, captured_at="2026-09-10T12:00:00+00:00"
        )
        self.assertTrue(second["created"])
        current = self.store.list_policy_state_history(
            self.ip, identity_id=second_identity["identity_id"]
        )
        self.assertEqual(1, len(current))
        self.assertEqual("Replacement tablet", current[0]["device_name"])

    def test_alias_change_is_retained_without_fake_policy_state_change(self):
        self.store.update_device(self.ip, alias="Tablet A")
        identity = self.store.get_managed_device_identity(self.ip)
        self.store.record_policy_state(
            self.ip, self.policy, captured_at="2026-09-10T11:00:00+00:00"
        )
        self.store.update_device(self.ip, alias="Tablet B")
        renamed = self.store.record_policy_state(
            self.ip, self.policy, captured_at="2026-09-10T11:30:00+00:00"
        )
        self.assertTrue(renamed["created"])
        rows = self.store.list_policy_state_history(
            self.ip, identity_id=identity["identity_id"]
        )
        self.assertEqual(["Tablet A", "Tablet B"], [row["device_name"] for row in rows])
        report_identity = dict(identity)
        report_identity["managed_since"] = "2026-09-10T11:00:00+00:00"
        report = build_policy_correlation_report(
            device_ip=self.ip,
            device_name="Tablet B",
            history=rows,
            usage=[
                {"index": 0, "total_bytes": 1, "traffic_evidence_status": "measured", "dns_evidence_status": "no_evidence"},
                {"index": 1, "total_bytes": 1, "traffic_evidence_status": "measured", "dns_evidence_status": "no_evidence"},
            ],
            start="2026-09-10T11:00:00+00:00",
            end="2026-09-10T12:00:00+00:00",
            timezone_name="Europe/London",
            identity=report_identity,
        )
        self.assertEqual(0, report["state_changes"])
        self.assertEqual(["Tablet A", "Tablet B"], [item["historical_name"] for item in report["intervals"]])


    def test_upgrade_starts_fresh_identity_without_backbinding_legacy_ip_history(self):
        legacy_path = Path(self.tmp.name) / "legacy-policy.db"
        db = sqlite3.connect(legacy_path)
        try:
            db.execute(
                """CREATE TABLE device_policy (
                       ip TEXT PRIMARY KEY, alias TEXT NOT NULL DEFAULT '',
                       notes TEXT NOT NULL DEFAULT '', profile_id INTEGER NULL,
                       mode_override TEXT NOT NULL DEFAULT 'inherit'
                   )"""
            )
            db.execute(
                """CREATE TABLE policy_state_history (
                       id INTEGER PRIMARY KEY AUTOINCREMENT, captured_at TEXT NOT NULL,
                       ip TEXT NOT NULL, state_hash TEXT NOT NULL,
                       source TEXT NOT NULL DEFAULT 'effective-resolver',
                       desired_mode TEXT NOT NULL, mode_source TEXT NOT NULL DEFAULT '',
                       bandwidth_preset TEXT NOT NULL DEFAULT 'normal',
                       blocked_services TEXT NOT NULL DEFAULT '[]',
                       policy_groups TEXT NOT NULL DEFAULT '[]',
                       schedule_active INTEGER NOT NULL DEFAULT 0,
                       schedule_reason TEXT NOT NULL DEFAULT '',
                       active_date_exception TEXT NOT NULL DEFAULT '{}',
                       quota_state TEXT NOT NULL DEFAULT '{}',
                       policy_at TEXT NOT NULL DEFAULT ''
                   )"""
            )
            db.execute(
                "INSERT INTO device_policy (ip, alias) VALUES (?, ?)",
                (self.ip, "Legacy tablet"),
            )
            db.execute(
                """INSERT INTO policy_state_history
                   (captured_at, ip, state_hash, desired_mode)
                   VALUES (?, ?, ?, ?)""",
                ("2026-10-25T01:30:00+01:00", self.ip, "legacy", "normal"),
            )
            db.commit()
        finally:
            db.close()

        upgraded = PolicyStore(str(legacy_path))
        identity = upgraded.get_managed_device_identity(self.ip)
        self.assertTrue(identity["identity_id"].startswith("mdi_"))
        db = sqlite3.connect(legacy_path)
        try:
            db.row_factory = sqlite3.Row
            legacy = db.execute(
                "SELECT captured_at, identity_id, device_name FROM policy_state_history"
            ).fetchone()
        finally:
            db.close()
        self.assertEqual("2026-10-25T00:30:00+00:00", legacy["captured_at"])
        self.assertEqual("", legacy["identity_id"])
        self.assertEqual("", legacy["device_name"])
        self.assertEqual(
            [],
            upgraded.list_policy_state_history(
                self.ip, identity_id=identity["identity_id"]
            ),
        )

    def test_management_identity_does_not_change_configuration_digest(self):
        self.store.update_device(self.ip, alias="Tablet")
        before = self.store.config_digest()
        first_identity = self.store.get_managed_device_identity(self.ip)["identity_id"]
        self.store.retire_device_state(self.ip)
        self.store.update_device(self.ip, alias="Tablet")
        second_identity = self.store.get_managed_device_identity(self.ip)["identity_id"]
        self.assertNotEqual(first_identity, second_identity)
        self.assertEqual(before, self.store.config_digest())

    def test_identity_metadata_is_operational_not_configuration_export_identity(self):
        self.store.update_device(self.ip, alias="Tablet")
        payload = self.store.export_config()
        row = next(item for item in payload["device_policy"] if item["ip"] == self.ip)
        self.assertNotIn("identity_id", row)
        self.assertNotIn("managed_since", row)


class V049TimeBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PolicyStore(str(Path(self.tmp.name) / "policy.db"))
        self.ip = "192.168.2.88"
        self.store.update_device(self.ip, alias="DST tablet")
        self.identity = self.store.get_managed_device_identity(self.ip)
        self.policy = {
            "mode": "normal", "mode_source": "default", "bandwidth_preset": "normal",
            "blocked_services": [], "blocked_policy_groups": [], "schedule_active": False,
            "schedule_reason": "", "active_date_exception": {},
            "quota_state": {"configured": False, "enabled": False, "available": True},
            "policy_at": "",
        }

    def tearDown(self):
        self.tmp.cleanup()

    def test_recorded_and_query_boundaries_are_canonical_utc_not_text_offset_order(self):
        self.store.record_policy_state(
            self.ip, self.policy, captured_at="2026-10-25T01:30:00+01:00"
        )
        rows = self.store.list_policy_state_history(
            self.ip,
            start="2026-10-25T00:15:00+00:00",
            end="2026-10-25T00:45:00+00:00",
            identity_id=self.identity["identity_id"],
        )
        self.assertEqual(1, len(rows))
        self.assertEqual("2026-10-25T00:30:00+00:00", rows[0]["captured_at"])

    def test_interval_sorting_uses_physical_instants_across_fallback_offsets(self):
        history = [
            {"captured_at": "2026-10-25T01:15:00+00:00", "state_hash": "b", "desired_mode": "blocked"},
            {"captured_at": "2026-10-25T01:30:00+01:00", "state_hash": "a", "desired_mode": "normal"},
        ]
        intervals = build_policy_intervals(
            history,
            "2026-10-25T00:00:00+00:00",
            "2026-10-25T02:00:00+00:00",
        )
        known = [item for item in intervals if item["known"]]
        self.assertEqual("normal", known[0]["state"]["desired_mode"])
        self.assertEqual("blocked", known[-1]["state"]["desired_mode"])

    def test_fallback_25_hour_day_coverage_is_physical_time(self):
        history = [{
            "captured_at": "2026-10-24T23:00:00+00:00", "state_hash": "a",
            "desired_mode": "normal", "device_name": "DST tablet",
        }]
        report = build_policy_correlation_report(
            device_ip=self.ip, device_name="DST tablet", history=history, usage=[{"index": 0}],
            start="2026-10-24T23:00:00+00:00", end="2026-10-26T00:00:00+00:00",
            timezone_name="Europe/London",
        )
        self.assertEqual(100.0, report["coverage_percent"])
        self.assertEqual(1500.0, report["intervals"][0]["duration_minutes"])

    def test_spring_forward_23_hour_day_coverage_is_physical_time(self):
        history = [{
            "captured_at": "2026-03-29T00:00:00+00:00", "state_hash": "a",
            "desired_mode": "normal", "device_name": "DST tablet",
        }]
        report = build_policy_correlation_report(
            device_ip=self.ip, device_name="DST tablet", history=history, usage=[{"index": 0}],
            start="2026-03-29T00:00:00+00:00", end="2026-03-29T23:00:00+00:00",
            timezone_name="Europe/London",
        )
        self.assertEqual(100.0, report["coverage_percent"])
        self.assertEqual(1380.0, report["intervals"][0]["duration_minutes"])


class V049RetainedTelemetryTests(unittest.TestCase):
    def _intervals(self, count=1):
        return [
            {"start": f"2026-09-10T{10+i:02d}:00:00+00:00", "end": f"2026-09-10T{11+i:02d}:00:00+00:00"}
            for i in range(count)
        ]

    def test_zero_denominator_is_no_evidence_not_zero_percent(self):
        store = ActivityStore()
        def fake_query(sql, params=()):
            if "flow_5m" in sql:
                return [{"idx": 0, "total_bytes": 0, "download_bytes": 0, "upload_bytes": 0,
                         "classified_bytes": 0, "unclassified_bytes": 0, "flows": 0}]
            return [{"idx": 0, "dns_queries": 0, "dns_classified_queries": 0,
                     "dns_unclassified_queries": 0, "dns_blocked": 0, "unique_domains": 0}]
        store._query = fake_query
        row = store.policy_interval_usage("192.168.2.2", self._intervals())[0]
        self.assertEqual("no_evidence", row["traffic_evidence_status"])
        self.assertEqual("no_evidence", row["dns_evidence_status"])
        self.assertIsNone(row["classified_percent"])

    def test_ipfix_query_failure_preserves_dns_evidence(self):
        store = ActivityStore()
        def fake_query(sql, params=()):
            if "flow_5m" in sql:
                raise ActivityError("flow source failed")
            return [{"idx": 0, "dns_queries": 4, "dns_classified_queries": 3,
                     "dns_unclassified_queries": 1, "dns_blocked": 2, "unique_domains": 3}]
        store._query = fake_query
        row = store.policy_interval_usage("192.168.2.2", self._intervals())[0]
        self.assertEqual("unavailable", row["traffic_evidence_status"])
        self.assertEqual("measured", row["dns_evidence_status"])
        self.assertEqual("partial", row["evidence_status"])
        self.assertEqual(2, row["dns_blocked"])

    def test_dns_query_failure_preserves_ipfix_evidence(self):
        store = ActivityStore()
        def fake_query(sql, params=()):
            if "flow_5m" in sql:
                return [{"idx": 0, "total_bytes": 100, "download_bytes": 80, "upload_bytes": 20,
                         "classified_bytes": 75, "unclassified_bytes": 25, "flows": 3}]
            raise ActivityError("dns source failed")
        store._query = fake_query
        row = store.policy_interval_usage("192.168.2.2", self._intervals())[0]
        self.assertEqual("measured", row["traffic_evidence_status"])
        self.assertEqual("unavailable", row["dns_evidence_status"])
        self.assertEqual(75.0, row["classified_percent"])
        self.assertEqual("partial", row["evidence_status"])

    def test_both_query_failures_are_unavailable_not_fabricated_zero(self):
        store = ActivityStore()
        store._query = lambda *args, **kwargs: (_ for _ in ()).throw(ActivityError("postgres unavailable"))
        row = store.policy_interval_usage("192.168.2.2", self._intervals())[0]
        self.assertEqual("unavailable", row["evidence_status"])
        self.assertIsNone(row["classified_percent"])
        self.assertIsNone(row["total_bytes"])
        self.assertIsNone(row["dns_queries"])

    def test_inconsistent_classification_accounting_withholds_percentage(self):
        store = ActivityStore()
        def fake_query(sql, params=()):
            if "flow_5m" in sql:
                return [{"idx": 0, "total_bytes": 100, "download_bytes": 100, "upload_bytes": 0,
                         "classified_bytes": 90, "unclassified_bytes": 20, "flows": 1}]
            return [{"idx": 0, "dns_queries": 1, "dns_classified_queries": 1,
                     "dns_unclassified_queries": 0, "dns_blocked": 0, "unique_domains": 1}]
        store._query = fake_query
        row = store.policy_interval_usage("192.168.2.2", self._intervals())[0]
        self.assertEqual("inconsistent", row["traffic_evidence_status"])
        self.assertEqual("inconsistent", row["evidence_status"])
        self.assertIsNone(row["classified_percent"])


    def test_negative_retained_counters_are_inconsistent_and_presented_bounded(self):
        store = ActivityStore()
        def fake_query(sql, params=()):
            if "flow_5m" in sql:
                return [{"idx": 0, "total_bytes": -10, "download_bytes": -8,
                         "upload_bytes": -2, "classified_bytes": -5,
                         "unclassified_bytes": -5, "flows": -1}]
            return [{"idx": 0, "dns_queries": 0, "dns_classified_queries": 0,
                     "dns_unclassified_queries": 0, "dns_blocked": -1,
                     "unique_domains": -1}]
        store._query = fake_query
        row = store.policy_interval_usage("192.168.2.2", self._intervals())[0]
        self.assertEqual("inconsistent", row["traffic_evidence_status"])
        self.assertEqual("inconsistent", row["evidence_status"])
        self.assertIsNone(row["classified_percent"])
        self.assertEqual(0, row["total_bytes"])
        self.assertEqual(0, row["classified_bytes"])
        self.assertEqual(0, row["download_bytes"])
        self.assertEqual(0, row["dns_blocked"])

    def test_real_accumulated_history_allows_more_than_100_transitions(self):
        store = ActivityStore()
        store._query = lambda sql, params=(): [
            {"idx": i, "total_bytes": 0, "download_bytes": 0, "upload_bytes": 0,
             "classified_bytes": 0, "unclassified_bytes": 0, "flows": 0}
            for i in range(101)
        ] if "flow_5m" in sql else [
            {"idx": i, "dns_queries": 0, "dns_classified_queries": 0,
             "dns_unclassified_queries": 0, "dns_blocked": 0, "unique_domains": 0}
            for i in range(101)
        ]
        intervals = [{"start": "2026-09-10T10:00:00+00:00", "end": "2026-09-10T10:01:00+00:00"} for _ in range(101)]
        self.assertEqual(101, len(store.policy_interval_usage("192.168.2.2", intervals)))


class V049CorrelationContractTests(unittest.TestCase):
    def test_identity_boundary_does_not_attribute_old_ip_evidence_to_current_device(self):
        identity = {
            "identity_id": "dev-current",
            "managed_since": "2026-09-10T11:00:00+00:00",
            "current_name": "New tablet",
        }
        history = [{
            "captured_at": "2026-09-10T11:15:00+00:00", "identity_id": "dev-current",
            "device_name": "New tablet", "state_hash": "a", "desired_mode": "normal",
            "mode_source": "default", "bandwidth_preset": "normal", "blocked_services": [], "policy_groups": [],
        }]
        intervals = build_policy_intervals(
            history, "2026-09-10T10:00:00+00:00", "2026-09-10T12:00:00+00:00",
            identity_start=identity["managed_since"],
        )
        self.assertEqual("identity_unproven", intervals[0]["gap_reason"])
        self.assertEqual("policy_unobserved", intervals[1]["gap_reason"])
        self.assertTrue(intervals[-1]["known"])
        report = build_policy_correlation_report(
            device_ip="192.168.2.10", device_name="New tablet", history=history,
            usage=[
                {"index": 0, "total_bytes": 900, "traffic_evidence_status": "measured", "dns_evidence_status": "no_evidence"},
                {"index": 1, "total_bytes": 50, "traffic_evidence_status": "measured", "dns_evidence_status": "no_evidence"},
                {"index": 2, "total_bytes": 100, "traffic_evidence_status": "measured", "dns_evidence_status": "no_evidence"},
            ],
            start="2026-09-10T10:00:00+00:00", end="2026-09-10T12:00:00+00:00",
            timezone_name="Europe/London", identity=identity,
        )
        self.assertEqual(900, report["identity_unproven_bytes"])
        self.assertEqual(150, report["current_identity_bytes"])
        self.assertEqual(100, report["mode_bytes"]["normal"])
        self.assertEqual(950, report["mode_bytes"]["unknown"])
        self.assertLess(report["identity_coverage_percent"], 100)


    def test_real_policy_hash_transitions_are_counted_but_name_only_events_are_not(self):
        history = [
            {"captured_at": "2026-09-10T10:00:00+00:00", "state_hash": "a",
             "desired_mode": "normal", "device_name": "Tablet A"},
            {"captured_at": "2026-09-10T10:20:00+00:00", "state_hash": "a",
             "desired_mode": "normal", "device_name": "Tablet B"},
            {"captured_at": "2026-09-10T10:40:00+00:00", "state_hash": "b",
             "desired_mode": "blocked", "device_name": "Tablet B"},
        ]
        report = build_policy_correlation_report(
            device_ip="192.168.2.10", device_name="Tablet B", history=history,
            usage=[
                {"index": 0, "traffic_evidence_status": "no_evidence", "dns_evidence_status": "no_evidence"},
                {"index": 1, "traffic_evidence_status": "no_evidence", "dns_evidence_status": "no_evidence"},
                {"index": 2, "traffic_evidence_status": "no_evidence", "dns_evidence_status": "no_evidence"},
            ],
            start="2026-09-10T10:00:00+00:00",
            end="2026-09-10T11:00:00+00:00",
            timezone_name="Europe/London",
        )
        self.assertEqual(1, report["state_changes"])
        self.assertEqual(["Tablet A", "Tablet B", "Tablet B"],
                         [item["historical_name"] for item in report["intervals"]])

    def test_routeros_execution_is_explicitly_not_proven_in_structured_contract(self):
        report = build_policy_correlation_report(
            device_ip="192.168.2.10", device_name="Tablet", history=[], usage=[{"index": 0}],
            start="2026-09-10T10:00:00+00:00", end="2026-09-10T11:00:00+00:00",
            timezone_name="Europe/London",
        )
        self.assertEqual("desired_policy_checkpoint", report["policy_evidence_kind"])
        self.assertEqual("not_recorded", report["routeros_execution_proof"])
        self.assertFalse(report["historical_enforcement_proven"])

    def test_stale_current_collection_status_does_not_rewrite_retained_interval_evidence(self):
        report = build_policy_correlation_report(
            device_ip="192.168.2.10", device_name="Tablet",
            history=[{"captured_at": "2026-09-10T10:00:00+00:00", "state_hash": "a", "desired_mode": "normal", "device_name": "Tablet"}],
            usage=[{"index": 0, "total_bytes": 10, "traffic_evidence_status": "measured", "dns_evidence_status": "no_evidence", "evidence_status": "measured"}],
            start="2026-09-10T10:00:00+00:00", end="2026-09-10T11:00:00+00:00",
            timezone_name="Europe/London",
            collection_status={"availability": "stale", "dns_source": "unknown", "ipfix_source": "unknown", "age_seconds": 90},
        )
        self.assertEqual("stale", report["current_collection_status"]["availability"])
        self.assertEqual("measured", report["intervals"][0]["usage"]["traffic_evidence_status"])

    def test_report_summarizes_partial_and_unavailable_telemetry_without_zero_coercion(self):
        history = [{"captured_at": "2026-09-10T10:00:00+00:00", "state_hash": "a", "desired_mode": "normal", "device_name": "Tablet"}]
        report = build_policy_correlation_report(
            device_ip="192.168.2.10", device_name="Tablet", history=history,
            usage=[{"index": 0, "total_bytes": None, "dns_queries": 4, "dns_blocked": 1,
                    "traffic_evidence_status": "unavailable", "dns_evidence_status": "measured", "evidence_status": "partial"}],
            start="2026-09-10T10:00:00+00:00", end="2026-09-10T11:00:00+00:00",
            timezone_name="Europe/London",
        )
        self.assertEqual("partial", report["telemetry_evidence_status"])
        self.assertEqual("unavailable", report["traffic_evidence_status"])
        self.assertEqual("measured", report["dns_evidence_status"])
        self.assertEqual(1, report["total_dns_blocked"])


class V049ReleaseSurfaceTests(unittest.TestCase):
    def test_release_and_help_surface_identity_and_evidence_boundaries(self):
        root = Path(__file__).resolve().parents[1]
        main = (root / "app/main.py").read_text()
        template = (root / "app/templates/policy_history.html").read_text()
        help_text = (root / "app/help_content.py").read_text()
        readme = (root / "README.md").read_text()
        self.assertIn('version="0.54.5"', main)
        self.assertIn("IDENTITY UNPROVEN", template)
        self.assertIn("RouterOS execution proof", template)
        self.assertIn("current management identity", help_text)
        self.assertIn("v0.54.5", readme)


if __name__ == "__main__":
    unittest.main()
