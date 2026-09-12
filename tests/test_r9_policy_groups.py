import tempfile
import unittest
from pathlib import Path

from app.policy_engine import build_device_policy_plan
from app.policy_groups import POLICY_GROUPS
from app.policy_store import PolicyStore
from app.quota import bytes_for_mb, service_quota_pairs
from app.service_catalog import SERVICE_ENFORCEMENT


class PolicyGroupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PolicyStore(str(Path(self.tmp.name) / "policy.db"))
        self.ip = "192.168.2.22"

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def usage(**mb):
        return {
            "available": True,
            "day": "2026-09-08",
            "timezone": "Europe/London",
            "total_bytes": sum(bytes_for_mb(v) for v in mb.values()),
            "service_bytes": {key: bytes_for_mb(value) for key, value in mb.items()},
        }

    def make_profile(self, blocked=(), quotas=None):
        profile = self.store.create_profile(
            "Child",
            "normal",
            "normal",
            "R9 group test",
            blocked,
            0,
            "blocked",
            quotas or {},
        )
        self.store.update_device(self.ip, profile_id=profile["id"])
        return profile

    def test_gaming_profile_expands_to_concrete_routeros_services(self):
        self.make_profile(["gaming"])
        policy = self.store.compute_effective_policy(self.ip)
        self.assertEqual(policy["blocked_policy_groups"], ["gaming"])
        self.assertEqual(
            set(policy["blocked_services"]),
            set(POLICY_GROUPS["gaming"]["members"]),
        )
        self.assertEqual(policy["unsupported_policy_keys"], [])
        gaming = next(g for g in policy["policy_group_states"] if g["key"] == "gaming")
        self.assertTrue(gaming["requested"])
        self.assertTrue(gaming["fully_blocked"])

    def test_social_group_and_direct_service_compose(self):
        self.make_profile(["social_media", "youtube"])
        policy = self.store.compute_effective_policy(self.ip)
        self.assertEqual(
            set(policy["blocked_services"]),
            {"youtube", "tiktok", "discord"},
        )

    def test_group_allow_schedule_removes_group_but_keeps_direct_block(self):
        profile = self.make_profile(["gaming", "youtube"])
        self.store.create_schedule_plan(
            "Allow gaming",
            "device",
            self.ip,
            "service",
            "gaming:allow",
            "18:00",
            ["tue"],
        )
        policy = self.store.compute_effective_policy(
            self.ip, at="2026-09-08T19:00:00+01:00"
        )
        self.assertEqual(policy["blocked_policy_groups"], [])
        self.assertEqual(policy["blocked_services"], ["youtube"])
        self.assertEqual(policy["scheduled_service_overrides"][0]["service"], "gaming")
        self.assertTrue(policy["scheduled_service_overrides"][0]["policy_group"])

    def test_concrete_allow_schedule_overrides_aggregate_group(self):
        self.make_profile(["gaming"])
        self.store.create_schedule_plan(
            "Roblox exception",
            "device",
            self.ip,
            "service",
            "roblox:allow",
            "18:00",
            ["tue"],
        )
        policy = self.store.compute_effective_policy(
            self.ip, at="2026-09-08T19:00:00+01:00"
        )
        self.assertNotIn("roblox", policy["blocked_services"])
        self.assertTrue({"steam", "xbox", "playstation"}.issubset(policy["blocked_services"]))
        gaming = next(g for g in policy["policy_group_states"] if g["key"] == "gaming")
        self.assertTrue(gaming["active"])
        self.assertFalse(gaming["fully_blocked"])

    def test_group_quota_sums_member_usage_and_blocks_all_members(self):
        self.make_profile([], {"gaming": 100})
        self.store.save_quota_settings("1", "80")
        policy = self.store.compute_effective_policy(
            self.ip,
            quota_usage=self.usage(roblox=40, steam=35, xbox=25, playstation=0),
        )
        self.assertEqual(
            set(policy["blocked_services"]),
            set(POLICY_GROUPS["gaming"]["members"]),
        )
        self.assertTrue(policy["quota_active"])
        entry = next(q for q in policy["quota_state"]["services"] if q["key"] == "gaming")
        self.assertEqual(entry["kind"], "group")
        self.assertTrue(entry["exhausted"])
        gaming = next(g for g in policy["policy_group_states"] if g["key"] == "gaming")
        self.assertTrue(gaming["quota_active"])

    def test_group_quota_form_is_now_live(self):
        self.assertEqual(service_quota_pairs(["gaming"], ["250"]), {"gaming": 250})

    def test_policy_plan_sees_only_concrete_group_members(self):
        self.make_profile(["social_media"])
        desired = self.store.compute_effective_policy(self.ip)
        live_services = {
            "blocked_services": [],
            "services": {
                key: {"available": True, "blocked": False}
                for key in SERVICE_ENFORCEMENT
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
        self.assertEqual(plan["unsupported_blocked_services"], [])
        self.assertEqual(set(plan["desired_supported_blocked_services"]), {"tiktok", "discord"})
        self.assertTrue(plan["service_drift"])
        self.assertEqual(plan["blocked_policy_groups"], ["social_media"])

    def test_custom_collection_can_apply_and_remove_live_sets(self):
        profile = self.make_profile([])
        group_id = self.store.save_service_group(
            "Entertainment",
            "R9 macro",
            ["youtube", "gaming"],
        )
        updated = self.store.apply_service_group(group_id, profile["id"], "block")
        self.assertEqual(set(updated["blocked_services"]), {"youtube", "gaming"})
        policy = self.store.compute_effective_policy(self.ip)
        self.assertIn("youtube", policy["blocked_services"])
        self.assertTrue(set(POLICY_GROUPS["gaming"]["members"]).issubset(policy["blocked_services"]))

        updated = self.store.apply_service_group(group_id, profile["id"], "allow")
        self.assertEqual(updated["blocked_services"], [])
        self.assertEqual(self.store.compute_effective_policy(self.ip)["blocked_services"], [])


if __name__ == "__main__":
    unittest.main()
