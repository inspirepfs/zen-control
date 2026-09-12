import unittest

from app.reconciler import AutoReconciler
from app.security import (
    encoded_ipv4_from_name,
    fasttrack_excludes_restricted,
    posture_score,
    queue_target_ipv4,
)


class SecurityHelperTests(unittest.TestCase):
    def test_fasttrack_requires_bidirectional_restricted_exclusion(self):
        self.assertTrue(fasttrack_excludes_restricted({
            "src-address-list": "!Restricted_Devices",
            "dst-address-list": "!Restricted_Devices",
        }))
        self.assertFalse(fasttrack_excludes_restricted({
            "src-address-list": "!Restricted_Devices",
        }))
        self.assertFalse(fasttrack_excludes_restricted({}))

    def test_managed_name_ip_decode_is_bounded(self):
        self.assertEqual(
            encoded_ipv4_from_name(
                "MC-TEMP-DEV-192-168-2-22", ("MC-TEMP-DEV-",)
            ),
            "192.168.2.22",
        )
        self.assertIsNone(
            encoded_ipv4_from_name("MC-TEMP-DEV-not-an-ip", ("MC-TEMP-DEV-",))
        )

    def test_queue_target_accepts_only_single_ipv4_32(self):
        self.assertEqual(queue_target_ipv4("192.168.2.22/32"), "192.168.2.22")
        self.assertIsNone(queue_target_ipv4("192.168.2.0/24"))
        self.assertIsNone(queue_target_ipv4("192.168.2.22/32,192.168.2.23/32"))

    def test_posture_score_weights_critical_checks(self):
        checks = [
            {"severity": "critical", "status": "pass"},
            {"severity": "critical", "status": "fail"},
            {"severity": "warning", "status": "pass"},
        ]
        self.assertEqual(posture_score(checks), 60)


class _Settings:
    def get_settings(self):
        return {
            "auto_reconcile_mode": "enforce",
            "auto_reconcile_interval_seconds": "30",
            "auto_reconcile_failure_threshold": "3",
            "auto_reconcile_cooldown_seconds": "300",
        }


class _RouterSecurityHeld:
    def __init__(self):
        self.writes = 0

    def get_security_posture(self):
        return {
            "enforcement_ready": False,
            "checks": [
                {
                    "name": "Managed-device FastTrack exclusion",
                    "severity": "critical",
                    "status": "fail",
                }
            ],
        }

    def set_device_mode(self, *args, **kwargs):
        self.writes += 1
        raise AssertionError("security-held reconciler must not write")


class _RouterReady(_RouterSecurityHeld):
    def get_security_posture(self):
        return {"enforcement_ready": True, "checks": []}

    def set_device_mode(self, address, mode, description=""):
        self.writes += 1
        return {"mode": mode}


class ReconcilerSecurityGateTests(unittest.TestCase):
    @staticmethod
    def _plan_loader(address):
        return {
            "address": address,
            "temporary_override": False,
            "policy_actionable": True,
            "status": "drift",
            "mode_drift": True,
            "live_mode": "normal",
            "desired_mode": "blocked",
            "bandwidth_drift": False,
            "service_drift": False,
        }

    def _make(self, router):
        return AutoReconciler(
            policy_store=_Settings(),
            router=router,
            device_loader=lambda: [{"ip": "192.168.2.22"}],
            plan_loader=self._plan_loader,
            audit=lambda *args: None,
        )

    def test_enforce_is_held_before_any_device_write(self):
        router = _RouterSecurityHeld()
        worker = self._make(router)
        result = worker.run_cycle(mode_override="enforce")
        self.assertEqual(result["result"], "security_hold")
        self.assertEqual(router.writes, 0)

    def test_observe_remains_available_while_security_is_degraded(self):
        router = _RouterSecurityHeld()
        worker = self._make(router)
        result = worker.run_cycle(mode_override="observe")
        self.assertEqual(result["result"], "drift")
        self.assertEqual(result["counts"]["drift"], 1)
        self.assertEqual(router.writes, 0)


if __name__ == "__main__":
    unittest.main()
