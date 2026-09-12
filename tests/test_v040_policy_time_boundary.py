import sys
import tempfile
import types
import unittest
from datetime import date, datetime, time as dt_time, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

# Keep host-side validation independent of psycopg installation.
psycopg = types.ModuleType("psycopg")
psycopg.Error = Exception
psycopg.connect = None
rows = types.ModuleType("psycopg.rows")
rows.dict_row = object()
psycopg.rows = rows
sys.modules.setdefault("psycopg", psycopg)
sys.modules.setdefault("psycopg.rows", rows)

from app.activity import ActivityStore, resolve_activity_window
from app.policy_store import PolicyStore
from app.policy_time import normalize_policy_datetime, resolve_local_wall_time


class PolicyTimeHelperTests(unittest.TestCase):
    def test_spring_gap_moves_to_first_valid_local_instant(self):
        zone = ZoneInfo("Europe/London")
        value, meta = resolve_local_wall_time(date(2026, 3, 29), dt_time(1, 30), zone)
        self.assertEqual(value.isoformat(timespec="minutes"), "2026-03-29T02:00+01:00")
        self.assertTrue(meta["adjusted"])
        self.assertEqual(meta["kind"], "nonexistent_forward")
        self.assertEqual(meta["shift_minutes"], 30)

    def test_autumn_fold_uses_first_physical_occurrence(self):
        zone = ZoneInfo("Europe/London")
        value, meta = resolve_local_wall_time(date(2026, 10, 25), dt_time(1, 30), zone)
        self.assertEqual(value.isoformat(timespec="minutes"), "2026-10-25T01:30+01:00")
        self.assertTrue(meta["ambiguous"])
        self.assertEqual(meta["kind"], "ambiguous_first")

    def test_explicit_second_fold_offset_preserves_physical_instant(self):
        zone = ZoneInfo("Europe/London")
        value, meta = normalize_policy_datetime("2026-10-25T01:30:00+00:00", zone)
        self.assertEqual(value.fold, 1)
        self.assertEqual(value.utcoffset().total_seconds(), 0)
        self.assertEqual(meta["kind"], "absolute")



class PolicyBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PolicyStore(str(Path(self.tmp.name) / "policy.db"))
        self.ip = "192.168.2.22"
        self.profile = self.store.create_profile("Child", "normal", "normal")
        self.store.update_device(self.ip, profile_id=self.profile["id"])

    def tearDown(self):
        self.tmp.cleanup()

    def test_spring_gap_schedule_executes_at_first_valid_instant(self):
        self.store.create_schedule_plan(
            "DST bedtime", "device", self.ip, "mode", "blocked", "01:30", ["sun"]
        )
        before = self.store.compute_effective_policy(self.ip, at="2026-03-29T00:59:00+00:00")
        action = before["next_policy_action"]
        self.assertEqual(action["at"], "2026-03-29T02:00+01:00")
        self.assertEqual(action["requested_time"], "01:30")
        self.assertTrue(action["wall_resolution"]["adjusted"])
        after = self.store.compute_effective_policy(self.ip, at="2026-03-29T01:01:00+00:00")
        self.assertEqual(after["mode"], "blocked")
        self.assertEqual(after["mode_source"], "schedule: DST bedtime")

    def test_autumn_fold_schedule_runs_once_at_first_occurrence(self):
        self.store.create_schedule_plan(
            "Fold bedtime", "device", self.ip, "mode", "blocked", "01:30", ["sun"]
        )
        before = self.store.compute_effective_policy(self.ip, at="2026-10-25T00:20:00+00:00")
        self.assertEqual(before["next_policy_action"]["at"], "2026-10-25T01:30+01:00")
        first_after = self.store.compute_effective_policy(self.ip, at="2026-10-25T00:40:00+00:00")
        second_fold = self.store.compute_effective_policy(self.ip, at="2026-10-25T01:20:00+00:00")
        self.assertEqual(first_after["mode"], "blocked")
        self.assertEqual(second_fold["mode"], "blocked")
        self.assertNotEqual(second_fold["next_policy_action"]["date"], "2026-10-25")

    def test_restart_style_recalculation_has_no_transition_memory_dependency(self):
        self.store.create_schedule_plan(
            "Thursday reset", "device", self.ip, "mode", "normal", "23:30", ["thu"]
        )
        self.store.create_schedule_plan(
            "Midnight block", "device", self.ip, "mode", "blocked", "00:00", ["fri"]
        )
        before = self.store.compute_effective_policy(self.ip, at="2026-09-10T23:59:00+01:00")
        after = self.store.compute_effective_policy(self.ip, at="2026-09-11T00:01:00+01:00")
        self.assertEqual(before["mode"], "normal")
        self.assertEqual(after["mode"], "blocked")

    def test_date_exception_uses_hypothetical_profile_context(self):
        alternate = self.store.create_profile("Holiday", "normal", "normal")
        self.store.save_date_exception(
            "Holiday block", "2026-09-10", "2026-09-10",
            "profile", str(alternate["id"]), "blocked"
        )
        baseline = self.store.compute_effective_policy(self.ip, at="2026-09-10T12:00:00+01:00")
        scenario = self.store.simulate_effective_policy(
            self.ip, at="2026-09-10T12:00:00+01:00",
            profile_id=alternate["id"], keep_profile=False,
        )
        self.assertEqual(baseline["mode"], "normal")
        self.assertEqual(scenario["mode"], "blocked")
        self.assertEqual(scenario["mode_source"], "date exception: Holiday block")

    def test_hypothetical_profile_does_not_keep_old_profile_exception(self):
        self.store.save_date_exception(
            "Original only", "2026-09-10", "2026-09-10",
            "profile", str(self.profile["id"]), "blocked"
        )
        alternate = self.store.create_profile("Alternate", "normal", "normal")
        scenario = self.store.simulate_effective_policy(
            self.ip, at="2026-09-10T12:00:00+01:00",
            profile_id=alternate["id"], keep_profile=False,
        )
        self.assertEqual(scenario["mode"], "normal")
        self.assertIsNone(scenario["active_date_exception"])

    def test_schedule_template_rejects_invalid_wall_clock(self):
        for bad in ("24:00", "23:60", "99:99"):
            with self.subTest(bad=bad):
                with self.assertRaisesRegex(ValueError, "valid 24-hour HH:MM"):
                    self.store.save_schedule_template(
                        "Bad", "", [{"days": ["sun"], "time": bad, "mode": "blocked"}]
                    )

    def test_exception_template_uses_dst_gap_contract(self):
        template_id = self.store.save_schedule_template(
            "DST template", "", [{"days": ["sun"], "time": "01:30", "mode": "blocked"}]
        )
        self.store.save_date_exception(
            "DST day", "2026-03-29", "2026-03-29", "device", self.ip,
            "template", template_id=template_id,
        )
        policy = self.store.compute_effective_policy(self.ip, at="2026-03-29T00:59:00+00:00")
        self.assertEqual(policy["next_policy_action"]["at"], "2026-03-29T02:00+01:00")
        self.assertTrue(policy["next_policy_action"]["wall_resolution"]["adjusted"])

    def test_naive_simulation_in_dst_gap_reports_resolved_policy_clock(self):
        policy = self.store.compute_effective_policy(self.ip, at="2026-03-29T01:30:00")
        self.assertEqual(policy["policy_at"], "2026-03-29T02:00+01:00")
        self.assertTrue(policy["policy_time_resolution"]["adjusted"])
        self.assertEqual(policy["policy_time_resolution"]["requested_local"], "2026-03-29T01:30")


class ActivityBoundaryTests(unittest.TestCase):
    def test_yesterday_spring_transition_is_23_hours(self):
        window = resolve_activity_window(
            "yesterday", "Europe/London", now=datetime(2026, 3, 30, 12, tzinfo=timezone.utc)
        )
        self.assertEqual(window["duration_hours"], 23.0)

    def test_yesterday_autumn_transition_is_25_hours(self):
        window = resolve_activity_window(
            "yesterday", "Europe/London", now=datetime(2026, 10, 26, 12, tzinfo=timezone.utc)
        )
        self.assertEqual(window["duration_hours"], 25.0)

    def test_daily_quota_window_tracks_23_hour_local_day(self):
        store = ActivityStore()
        calls = []
        def query(sql, params=()):
            calls.append(params)
            if "GROUP BY service_name" in sql:
                return []
            return [{"total_bytes": 0, "download_bytes": 0, "upload_bytes": 0, "flows": 0, "latest_bucket": None}]
        store._query = query
        result = store.daily_usage("192.168.2.22", "Europe/London", at="2026-03-29T12:00:00+01:00")
        self.assertEqual(result["window_hours"], 23.0)
        self.assertEqual(calls[0][1].isoformat(), "2026-03-29T00:00:00+00:00")
        self.assertEqual(calls[0][2].isoformat(), "2026-03-29T23:00:00+00:00")

    def test_daily_quota_window_tracks_25_hour_local_day(self):
        store = ActivityStore()
        def query(sql, params=()):
            if "GROUP BY service_name" in sql:
                return []
            return [{"total_bytes": 0, "download_bytes": 0, "upload_bytes": 0, "flows": 0, "latest_bucket": None}]
        store._query = query
        result = store.daily_usage("192.168.2.22", "Europe/London", at="2026-10-25T12:00:00+00:00")
        self.assertEqual(result["window_hours"], 25.0)


class PolicyTimeUxContractTests(unittest.TestCase):
    def test_schedule_ui_and_help_explain_dst_contract(self):
        root = Path(__file__).resolve().parents[1]
        index = (root / "app/templates/index.html").read_text()
        help_text = (root / "app/help_content.py").read_text()
        explain = (root / "app/templates/policy_explain.html").read_text()
        simulation = (root / "app/templates/simulation.html").read_text()
        self.assertIn("ambiguous autumn wall time", index)
        self.assertIn("nonexistent time moves to the first valid local instant", help_text)
        self.assertIn("DST adjusted from", explain)
        self.assertIn("was DST-adjusted to", simulation)



if __name__ == "__main__":
    unittest.main()
