import json
import tempfile
import unittest
from pathlib import Path

from app.policy_store import PolicyStore
from app.quota import bytes_for_mb, service_quota_pairs
from app.policy_engine import build_device_policy_plan


class DailyQuotaTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmp.name) / "policy.db")
        self.store = PolicyStore(self.db_path)
        self.ip = "192.168.2.22"
        self.profile = self.store.create_profile(
            "Quota Child",
            "normal",
            "normal",
            "quota test",
            [],
            100,
            "blocked",
            {"youtube": 25, "netflix": 50},
        )
        self.store.update_device(self.ip, profile_id=self.profile["id"])

    def tearDown(self):
        self.tmp.cleanup()

    def usage(self, total_mb=0, youtube_mb=0, netflix_mb=0):
        return {
            "available": True,
            "day": "2026-09-08",
            "timezone": "Europe/London",
            "total_bytes": bytes_for_mb(total_mb),
            "service_bytes": {
                "youtube": bytes_for_mb(youtube_mb),
                "netflix": bytes_for_mb(netflix_mb),
            },
        }

    def test_engine_is_disabled_by_default_and_fail_open(self):
        policy = self.store.compute_effective_policy(
            self.ip, quota_usage=self.usage(total_mb=500, youtube_mb=100)
        )
        self.assertEqual(policy["mode"], "normal")
        self.assertNotIn("youtube", policy["blocked_services"])
        self.assertFalse(policy["quota_state"]["enabled"])
        self.assertFalse(policy["quota_active"])

    def test_total_quota_blocks_after_limit(self):
        self.store.save_quota_settings("1", "80")
        below = self.store.compute_effective_policy(
            self.ip, quota_usage=self.usage(total_mb=99)
        )
        self.assertEqual(below["mode"], "normal")
        self.assertFalse(below["quota_state"]["daily"]["exhausted"])

        exhausted = self.store.compute_effective_policy(
            self.ip, quota_usage=self.usage(total_mb=100)
        )
        self.assertEqual(exhausted["mode"], "blocked")
        self.assertTrue(exhausted["quota_active"])
        self.assertTrue(exhausted["quota_state"]["mode_active"])
        self.assertIn("daily quota", exhausted["mode_source"])

    def test_slow_quota_never_weakens_a_more_restrictive_mode(self):
        self.store.update_profile(
            self.profile["id"], "Quota Child", "blocked", "normal", "", [],
            100, "slow", {},
        )
        self.store.save_quota_settings("1", "80")
        policy = self.store.compute_effective_policy(
            self.ip, quota_usage=self.usage(total_mb=150)
        )
        self.assertEqual(policy["mode"], "blocked")
        self.assertTrue(policy["quota_state"]["mode_active"])
        self.assertTrue(policy["quota_active"])
        self.assertTrue(policy["mode_source"].startswith("profile:"))

    def test_service_quota_adds_hard_service_block(self):
        self.store.save_quota_settings("1", "80")
        policy = self.store.compute_effective_policy(
            self.ip,
            quota_usage=self.usage(total_mb=40, youtube_mb=25, netflix_mb=10),
        )
        self.assertEqual(policy["mode"], "normal")
        self.assertIn("youtube", policy["blocked_services"])
        self.assertNotIn("netflix", policy["blocked_services"])
        self.assertTrue(policy["quota_state"]["service_active"])
        self.assertEqual(policy["quota_state"]["active_service_blocks"], ["youtube"])

    def test_telemetry_failure_is_fail_open(self):
        self.store.save_quota_settings("1", "80")
        policy = self.store.compute_effective_policy(
            self.ip,
            quota_usage={"available": False, "error": "database down"},
        )
        self.assertEqual(policy["mode"], "normal")
        self.assertNotIn("youtube", policy["blocked_services"])
        self.assertFalse(policy["quota_state"]["available"])
        self.assertIn("database down", policy["quota_state"]["telemetry_error"])

    def test_warning_threshold_is_reported_without_enforcement(self):
        self.store.save_quota_settings("1", "80")
        policy = self.store.compute_effective_policy(
            self.ip, quota_usage=self.usage(total_mb=80, youtube_mb=20)
        )
        self.assertEqual(policy["mode"], "normal")
        self.assertTrue(policy["quota_state"]["daily"]["warning"])
        youtube = next(q for q in policy["quota_state"]["services"] if q["key"] == "youtube")
        self.assertTrue(youtube["warning"])
        self.assertFalse(youtube["exhausted"])

    def test_config_round_trip_preserves_profile_quotas_and_settings(self):
        self.store.save_quota_settings("1", "90")
        self.store.save_template_from_profile("Quota Template", self.profile["id"])
        exported = self.store.export_config()

        restored_path = str(Path(self.tmp.name) / "restored.db")
        restored = PolicyStore(restored_path)
        restored.import_config(json.loads(json.dumps(exported)))

        profile = restored.list_profiles()[0]
        self.assertEqual(profile["daily_quota_mb"], 100)
        self.assertEqual(profile["daily_quota_action"], "blocked")
        self.assertEqual(profile["service_quotas"], {"netflix": 50, "youtube": 25})
        self.assertEqual(restored.get_settings()["quota_engine_enabled"], "1")
        self.assertEqual(restored.get_settings()["quota_warning_percent"], "90")
        templates = restored.list_templates()
        self.assertEqual(len(templates), 1)
        self.assertEqual(templates[0]["daily_quota_mb"], 100)
        self.assertEqual(templates[0]["service_quotas"]["youtube"], 25)

    def test_policy_template_applies_quota_settings(self):
        template_id = self.store.save_template_from_profile(
            "Quota Template", self.profile["id"]
        )
        other = self.store.create_profile("Other", "normal", "normal")
        self.store.apply_template(template_id, other["id"])
        applied = self.store.get_profile(other["id"])
        self.assertEqual(applied["daily_quota_mb"], 100)
        self.assertEqual(applied["service_quotas"], {"netflix": 50, "youtube": 25})


    def test_quota_policy_becomes_normal_reconciliation_drift(self):
        self.store.save_quota_settings("1", "80")
        desired = self.store.compute_effective_policy(
            self.ip, quota_usage=self.usage(total_mb=120, youtube_mb=30)
        )
        live_services = {
            "blocked_services": [],
            "unavailable_services": [],
            "services": {
                key: {"available": True, "blocked": False}
                for key in (
                    "youtube", "chatgpt", "openai", "netflix", "prime_video",
                    "bbc_iplayer", "tiktok", "discord", "roblox", "steam",
                    "xbox", "playstation",
                )
            },
        }
        plan = build_device_policy_plan(
            self.ip,
            desired,
            {"mode": "normal"},
            {"active": False},
            live_services,
            {"active": False, "valid": True, "max_limit": None},
            "normal",
        )
        self.assertEqual(plan["desired_mode"], "blocked")
        self.assertTrue(plan["mode_drift"])
        self.assertTrue(plan["service_drift"])
        self.assertTrue(plan["policy_actionable"])
        self.assertTrue(plan["quota_active"])

    def test_unmapped_custom_services_cannot_be_service_quotas(self):
        with self.assertRaisesRegex(ValueError, "not backed by a live policy contract"):
            service_quota_pairs(["custom_unmapped"], ["100"])


if __name__ == "__main__":
    unittest.main()
