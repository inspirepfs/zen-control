import copy
import tempfile
import unittest
from pathlib import Path

from app.policy_groups import POLICY_GROUPS
from app.policy_quality import build_policy_quality_report
from app.policy_store import PolicyStore


class ConflictShadowHostileReportTests(unittest.TestCase):
    def base(self):
        services = [
            {"key": key, "name": key.replace("_", " ").title(), "builtin": 1, "enforcement_approved": True}
            for key in ("youtube", "roblox", "steam", "xbox", "playstation", "tiktok", "discord")
        ]
        return {
            "profiles": [{
                "id": 1, "name": "Child", "desired_mode": "normal",
                "bandwidth_preset": "normal", "blocked_services": [],
                "daily_quota_mb": 0, "service_quotas": {},
            }],
            "devices": {
                "192.168.2.20": {
                    "ip": "192.168.2.20", "alias": "Tablet",
                    "profile_id": 1, "mode_override": "inherit",
                }
            },
            "schedules": [],
            "schedule_templates": [],
            "date_exceptions": [],
            "service_groups": [],
            "services": services,
            "settings": {"quota_engine_enabled": "1"},
            "policy_groups": copy.deepcopy(POLICY_GROUPS),
        }

    def report(self, **overrides):
        data = self.base()
        data.update(overrides)
        return build_policy_quality_report(**data)

    @staticmethod
    def titles(report):
        return [item["title"] for item in report["findings"]]

    def test_missing_profile_schedule_is_not_claimed_to_shadow_all_target(self):
        result = self.report(schedules=[
            {"id": 1, "label": "House", "enabled": True, "target_type": "all", "target_value": "", "action_type": "mode", "action_value": "blocked", "clock_time": "20:00", "days": ["mon"]},
            {"id": 2, "label": "Ghost profile", "enabled": True, "target_type": "profile", "target_value": "99", "action_type": "mode", "action_value": "normal", "clock_time": "20:00", "days": ["mon"]},
        ])
        self.assertIn("Schedule targets a missing profile", self.titles(result))
        self.assertNotIn("More-specific schedule overrides a broader schedule", self.titles(result))

    def test_unmanaged_device_schedule_is_not_claimed_to_shadow_all_target(self):
        result = self.report(schedules=[
            {"id": 1, "label": "House", "enabled": True, "target_type": "all", "target_value": "", "action_type": "mode", "action_value": "blocked", "clock_time": "20:00", "days": ["mon"]},
            {"id": 2, "label": "Old phone", "enabled": True, "target_type": "device", "target_value": "192.168.2.99", "action_type": "mode", "action_value": "normal", "clock_time": "20:00", "days": ["mon"]},
        ])
        self.assertIn("Schedule targets an unmanaged device", self.titles(result))
        self.assertNotIn("More-specific schedule overrides a broader schedule", self.titles(result))

    def test_missing_profile_exception_is_not_claimed_to_shadow_all_target(self):
        result = self.report(date_exceptions=[
            {"id": 1, "label": "House holiday", "target_type": "all", "target_value": "", "start_date": "2026-12-20", "end_date": "2026-12-25", "mode": "blocked", "template_id": None, "template_name": None},
            {"id": 2, "label": "Ghost holiday", "target_type": "profile", "target_value": "99", "start_date": "2026-12-20", "end_date": "2026-12-25", "mode": "normal", "template_id": None, "template_name": None},
        ])
        self.assertIn("Date exception targets a missing profile", self.titles(result))
        self.assertNotIn("More-specific date exception overrides a broader exception", self.titles(result))

    def test_unmanaged_device_exception_is_not_claimed_to_shadow_all_target(self):
        result = self.report(date_exceptions=[
            {"id": 1, "label": "House holiday", "target_type": "all", "target_value": "", "start_date": "2026-12-20", "end_date": "2026-12-25", "mode": "blocked", "template_id": None, "template_name": None},
            {"id": 2, "label": "Old phone holiday", "target_type": "device", "target_value": "192.168.2.99", "start_date": "2026-12-20", "end_date": "2026-12-25", "mode": "normal", "template_id": None, "template_name": None},
        ])
        self.assertIn("Date exception targets an unmanaged device", self.titles(result))
        self.assertNotIn("More-specific date exception overrides a broader exception", self.titles(result))

    def test_profile_missing_block_key_is_critical_conflict(self):
        profiles = self.base()["profiles"]
        profiles[0]["blocked_services"] = ["removed_service"]
        result = self.report(profiles=profiles)
        finding = next(item for item in result["findings"] if item["title"] == "Profile references missing policy services")
        self.assertEqual("conflict", finding["category"])
        self.assertIn("removed_service", finding["evidence"][0])

    def test_profile_missing_quota_key_is_critical_conflict(self):
        profiles = self.base()["profiles"]
        profiles[0]["service_quotas"] = {"removed_service": 100}
        result = self.report(profiles=profiles)
        finding = next(item for item in result["findings"] if item["title"] == "Profile quota references missing policy services")
        self.assertEqual("conflict", finding["category"])
        self.assertIn("removed_service", finding["evidence"][0])

    def test_invalid_service_schedule_is_critical_conflict(self):
        result = self.report(schedules=[
            {"id": 7, "label": "Old service", "enabled": True, "target_type": "device", "target_value": "192.168.2.20", "action_type": "service", "action_value": "removed_service:block", "action_service": "", "action_state": "invalid", "clock_time": "20:00", "days": ["mon"]},
        ])
        finding = next(item for item in result["findings"] if item["title"] == "Service schedule references an invalid or missing policy service")
        self.assertEqual("conflict", finding["category"])
        self.assertIn("removed_service", " ".join(finding["evidence"]))

    def test_builtin_aggregate_group_missing_member_is_conflict(self):
        groups = copy.deepcopy(POLICY_GROUPS)
        groups["gaming"] = {**groups["gaming"], "members": ("roblox", "removed_service")}
        result = self.report(policy_groups=groups)
        finding = next(item for item in result["findings"] if item["title"] == "Aggregate policy group contains missing services")
        self.assertEqual("conflict", finding["category"])
        self.assertIn("removed_service", finding["evidence"][0])

    def test_same_value_device_override_is_redundant_not_shadow(self):
        devices = copy.deepcopy(self.base()["devices"])
        devices["192.168.2.20"]["mode_override"] = "normal"
        result = self.report(devices=devices)
        finding = next(item for item in result["findings"] if "Device mode override" in item["title"])
        self.assertEqual("redundant", finding["category"])
        self.assertNotIn("shadows its profile mode", finding["title"].lower())

    def test_different_device_override_remains_shadow(self):
        devices = copy.deepcopy(self.base()["devices"])
        devices["192.168.2.20"]["mode_override"] = "blocked"
        result = self.report(devices=devices)
        finding = next(item for item in result["findings"] if "Device mode override" in item["title"])
        self.assertEqual("shadow", finding["category"])

    def test_existing_ambiguous_schedule_template_is_reported_as_conflict(self):
        result = self.report(schedule_templates=[{
            "id": 4, "name": "Bad template", "entries": [
                {"days": ["mon"], "time": "20:00", "mode": "normal"},
                {"days": ["mon"], "time": "20:00", "mode": "blocked"},
            ],
        }])
        finding = next(item for item in result["findings"] if item["title"] == "Schedule template has contradictory same-time modes")
        self.assertEqual("conflict", finding["category"])
        self.assertIn("mon 20:00", " ".join(finding["evidence"]).lower())

    def test_existing_duplicate_template_effect_is_redundant(self):
        result = self.report(schedule_templates=[{
            "id": 4, "name": "Noisy template", "entries": [
                {"days": ["mon"], "time": "20:00", "mode": "blocked"},
                {"days": ["mon"], "time": "20:00", "mode": "blocked"},
            ],
        }])
        finding = next(item for item in result["findings"] if item["title"] == "Schedule template duplicates a same-time mode")
        self.assertEqual("redundant", finding["category"])

    def test_same_clock_different_days_is_not_template_conflict(self):
        result = self.report(schedule_templates=[{
            "id": 4, "name": "Valid template", "entries": [
                {"days": ["mon"], "time": "20:00", "mode": "blocked"},
                {"days": ["tue"], "time": "20:00", "mode": "normal"},
            ],
        }])
        self.assertFalse(any("Schedule template" in title for title in self.titles(result)))

    def test_template_inventory_is_exposed(self):
        result = self.report(schedule_templates=[{
            "id": 1, "name": "Week", "entries": [{"days": ["mon"], "time": "20:00", "mode": "blocked"}],
        }])
        self.assertEqual(1, result["inventory"]["schedule_templates"])

    def test_clean_hostile_baseline_remains_clean(self):
        result = self.report()
        self.assertEqual("clean", result["state"])
        self.assertEqual(0, result["counts"]["total"])

    def test_disabled_invalid_service_schedule_is_not_a_live_conflict(self):
        result = self.report(schedules=[
            {"id": 7, "label": "Retired rule", "enabled": False, "target_type": "device", "target_value": "192.168.2.20", "action_type": "service", "action_value": "removed_service:block", "action_service": "", "action_state": "invalid", "clock_time": "20:00", "days": ["mon"]},
        ])
        self.assertEqual("clean", result["state"])

    def test_two_orphan_contradictory_schedules_do_not_invent_live_ambiguity(self):
        result = self.report(schedules=[
            {"id": 1, "label": "Ghost A", "enabled": True, "target_type": "profile", "target_value": "99", "action_type": "mode", "action_value": "blocked", "clock_time": "20:00", "days": ["mon"]},
            {"id": 2, "label": "Ghost B", "enabled": True, "target_type": "profile", "target_value": "99", "action_type": "mode", "action_value": "normal", "clock_time": "20:00", "days": ["mon"]},
        ])
        self.assertEqual(0, result["counts"]["conflict"])
        self.assertEqual(2, sum(item["title"] == "Schedule targets a missing profile" for item in result["findings"]))

    def test_malformed_existing_template_entry_is_critical_conflict(self):
        result = self.report(schedule_templates=[{
            "id": 4, "name": "Broken template", "entries": [
                {"days": ["funday"], "time": "25:00", "mode": "warp"},
            ],
        }])
        finding = next(item for item in result["findings"] if item["title"] == "Schedule template contains invalid stored policy data")
        self.assertEqual("critical", finding["severity"])


class ScheduleTemplateConflictPreventionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PolicyStore(str(Path(self.tmp.name) / "policy.db"))
        self.profile = self.store.create_profile("Child", "normal", "normal")
        self.ip = "192.168.2.20"
        self.store.update_device(self.ip, profile_id=self.profile["id"])

    def tearDown(self):
        self.tmp.cleanup()

    def test_conflicting_same_day_time_modes_are_rejected_at_save(self):
        with self.assertRaisesRegex(ValueError, "conflicting modes"):
            self.store.save_schedule_template("Bad", "", [
                {"days": ["mon"], "time": "20:00", "mode": "blocked"},
                {"days": ["mon"], "time": "20:00", "mode": "normal"},
            ])

    def test_overlapping_days_expose_conflict_even_when_day_lists_differ(self):
        with self.assertRaisesRegex(ValueError, "conflicting modes"):
            self.store.save_schedule_template("Bad", "", [
                {"days": ["mon", "tue"], "time": "20:00", "mode": "blocked"},
                {"days": ["tue", "wed"], "time": "20:00", "mode": "normal"},
            ])

    def test_same_time_different_days_remains_valid(self):
        template_id = self.store.save_schedule_template("Valid", "", [
            {"days": ["mon"], "time": "20:00", "mode": "blocked"},
            {"days": ["tue"], "time": "20:00", "mode": "normal"},
        ])
        self.assertGreater(template_id, 0)

    def test_duplicate_same_mode_template_effect_remains_valid(self):
        template_id = self.store.save_schedule_template("Noisy but safe", "", [
            {"days": ["mon"], "time": "20:00", "mode": "blocked"},
            {"days": ["mon"], "time": "20:00", "mode": "blocked"},
        ])
        self.assertGreater(template_id, 0)

    def test_import_rejects_ambiguous_template_before_mutating_live_configuration(self):
        self.store.create_profile("Keep me", "slow", "normal")
        before = self.store.config_digest()
        payload = self.store.export_config()
        payload["schedule_templates"] = [{
            "id": 900, "name": "Ambiguous", "description": "", "entries": [
                {"days": ["mon"], "time": "20:00", "mode": "blocked"},
                {"days": ["mon"], "time": "20:00", "mode": "normal"},
            ],
        }]
        with self.assertRaisesRegex(ValueError, "conflicting modes"):
            self.store.import_config(payload)
        self.assertEqual(before, self.store.config_digest())
        self.assertIsNotNone(next((p for p in self.store.list_profiles() if p["name"] == "Keep me"), None))

    def test_import_rejects_missing_exception_template_before_mutation(self):
        self.store.create_profile("Keep me", "slow", "normal")
        before = self.store.config_digest()
        payload = self.store.export_config()
        payload["schedule_templates"] = []
        payload["date_exceptions"] = [{
            "id": 1, "label": "Broken", "start_date": "2026-12-20", "end_date": "2026-12-21",
            "target_type": "all", "target_value": "", "mode": "template", "template_id": 999, "notes": "",
        }]
        with self.assertRaisesRegex(ValueError, "missing schedule template"):
            self.store.import_config(payload)
        self.assertEqual(before, self.store.config_digest())

    def test_import_duplicate_template_identity_fails_before_mutation(self):
        before = self.store.config_digest()
        payload = self.store.export_config()
        payload["schedule_templates"] = [
            {"id": 5, "name": "One", "entries": [{"days": ["mon"], "time": "20:00", "mode": "blocked"}]},
            {"id": 5, "name": "Two", "entries": [{"days": ["tue"], "time": "20:00", "mode": "normal"}]},
        ]
        with self.assertRaisesRegex(ValueError, "duplicate schedule template id"):
            self.store.import_config(payload)
        self.assertEqual(before, self.store.config_digest())

    def test_import_duplicate_template_name_fails_before_mutation(self):
        before = self.store.config_digest()
        payload = self.store.export_config()
        payload["schedule_templates"] = [
            {"id": 5, "name": "Holiday", "entries": [{"days": ["mon"], "time": "20:00", "mode": "blocked"}]},
            {"id": 6, "name": "holiday", "entries": [{"days": ["tue"], "time": "20:00", "mode": "normal"}]},
        ]
        with self.assertRaisesRegex(ValueError, "duplicate schedule template name"):
            self.store.import_config(payload)
        self.assertEqual(before, self.store.config_digest())

    def test_import_valid_template_and_exception_still_round_trip(self):
        payload = self.store.export_config()
        payload["schedule_templates"] = [{
            "id": 900, "name": "Holiday", "description": "", "entries": [
                {"days": ["mon"], "time": "20:00", "mode": "blocked"},
            ],
        }]
        payload["date_exceptions"] = [{
            "id": 1, "label": "Holiday week", "start_date": "2026-12-20", "end_date": "2026-12-28",
            "target_type": "all", "target_value": "", "mode": "template", "template_id": 900, "notes": "",
        }]
        self.store.import_config(payload)
        self.assertEqual("Holiday", self.store.list_schedule_templates()[0]["name"])
        self.assertEqual("Holiday week", self.store.list_date_exceptions()[0]["label"])


class ConflictShadowReleaseIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        cls.main = (cls.root / "app/main.py").read_text(encoding="utf-8")
        cls.quality = (cls.root / "app/policy_quality.py").read_text(encoding="utf-8")
        cls.readme = (cls.root / "README.md").read_text(encoding="utf-8")

    def test_quality_snapshot_includes_schedule_templates(self):
        helper = self.main.split("def _policy_quality_snapshot():", 1)[1].split('@app.get("/policy/quality"', 1)[0]
        self.assertIn("schedule_templates=policy_store.list_schedule_templates()", helper)

    def test_analyzer_remains_static_and_routeros_free(self):
        self.assertNotIn("from app.router", self.quality)
        self.assertNotIn("import app.router", self.quality)
        self.assertNotIn("router.", self.quality)
        helper = self.main.split("def _policy_quality_snapshot():", 1)[1].split('@app.get("/policy/quality"', 1)[0]
        self.assertNotIn("router.", helper)

    def test_schedule_restore_preflight_runs_before_destructive_replacement(self):
        store = (self.root / "app/policy_store.py").read_text(encoding="utf-8")
        block = store.split("def import_config(self, payload):", 1)[1]
        self.assertLess(
            block.index("_preflight_import_schedule_contract"),
            block.index('db.execute(f"DELETE FROM {table}")'),
        )

    def test_release_readiness_matrix_records_conflict_shadow_closure(self):
        release = (self.root / "app/release_readiness.py").read_text(encoding="utf-8")
        self.assertIn('("policy_quality", "Policy Conflict & Shadow hostile closure", "0.50.1")', release)

    def test_release_documents_hostile_closure_without_new_authority(self):
        self.assertIn("v0.50.1", self.readme)
        self.assertIn("Conflict & Shadow hostile closure", self.readme)
        self.assertIn("no RouterOS authority", self.readme)


if __name__ == "__main__":
    unittest.main()
