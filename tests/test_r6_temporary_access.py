import sys
import types
import unittest

sys.modules.setdefault("routeros_api", types.SimpleNamespace())

from app.policy_engine import build_device_policy_plan
from app.router import RouterOSAdapter


class DeviceTemporaryAccessHelpersTest(unittest.TestCase):
    def setUp(self):
        self.router = RouterOSAdapter.__new__(RouterOSAdapter)
        self.router.device_slow_limit = "128k/256k"

    def test_comment_metadata_round_trip_shape(self):
        comment = (
            "MC|TEMP_DEVICE|192.168.2.22|restore=blocked|minutes=30|"
            "started=2026-09-08T20:30:00+01:00"
        )
        parsed = self.router._parse_device_temp_comment(comment)
        self.assertEqual(parsed["address"], "192.168.2.22")
        self.assertEqual(parsed["restore"], "blocked")
        self.assertEqual(parsed["minutes"], "30")

    def test_blocked_restore_establishes_block_before_slow_cleanup(self):
        source = self.router._device_temp_restore_source(
            "192.168.2.22", "blocked"
        )
        add_block = source.index("address-list add")
        remove_slow = source.index('list="MC_Mode_Slow"')
        self.assertLess(add_block, remove_slow)
        self.assertIn('name="MC-BW-192-168-2-22"', source)

    def test_slow_restore_builds_queue_before_releasing_block(self):
        source = self.router._device_temp_restore_source(
            "192.168.2.22", "slow"
        )
        add_queue = source.index("/queue simple add")
        remove_block = source.rindex('list="MC_Mode_Blocked"')
        self.assertLess(add_queue, remove_block)
        self.assertIn('max-limit="128k/256k"', source)

    def test_policy_plan_temporary_is_non_actionable(self):
        desired = {
            "mode": "blocked",
            "mode_source": "schedule",
            "bandwidth_preset": "normal",
            "blocked_services": [],
        }
        live = {"mode": "normal"}
        plan = build_device_policy_plan(
            "192.168.2.22",
            desired,
            live,
            temporary_access={
                "active": True,
                "restore_mode": "blocked",
                "restore_time": "sep/08/2026 21:00:00",
            },
            live_services={
                "blocked_services": [],
                "unavailable_services": [],
                "services": {},
            },
            live_bandwidth={
                "active": False,
                "valid": True,
                "max_limit": None,
                "error": None,
            },
            global_mode="normal",
        )
        self.assertEqual(plan["status"], "temporary")
        self.assertTrue(plan["temporary_override"])
        self.assertFalse(plan["policy_actionable"])
        self.assertFalse(plan["mode_drift"])


if __name__ == "__main__":
    unittest.main()
