import sys
import types
import unittest
from unittest.mock import patch

sys.modules.setdefault("routeros_api", types.SimpleNamespace())

from app.router import RouterOSAdapter
from app.security import forward_authority_order, infer_global_mode


class AuthorityHelperTests(unittest.TestCase):
    def test_global_master_disabled_is_normal_when_slow_is_disabled(self):
        self.assertEqual(infer_global_mode(False, False), ("normal", True))

    def test_global_master_disabled_is_slow_when_slow_queue_enabled(self):
        self.assertEqual(infer_global_mode(False, True), ("slow", True))

    def test_master_and_slow_enabled_together_is_invalid(self):
        self.assertEqual(infer_global_mode(True, True), ("invalid", False))

    def test_managed_rules_do_not_require_strict_relative_order(self):
        rules = [
            {"comment": "MC - Per Device Block", "chain": "forward"},
            {"comment": "MASTER - Block Restricted Internet", "chain": "forward"},
            {"comment": "Restricted Devices - Web Policy", "chain": "forward"},
            {"comment": "defconf: accept established,related,untracked", "chain": "forward"},
        ]
        result = forward_authority_order(
            rules,
            [
                "MASTER - Block Restricted Internet",
                "MC - Per Device Block",
                "Restricted Devices - Web Policy",
            ],
            "defconf: accept established,related,untracked",
            required_comments=[
                "MC - Per Device Block",
                "Restricted Devices - Web Policy",
            ],
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["late"], [])

    def test_active_managed_rule_after_established_is_rejected(self):
        rules = [
            {"comment": "Restricted Devices - Web Policy", "chain": "forward"},
            {"comment": "defconf: accept established,related,untracked", "chain": "forward"},
            {"comment": "MC - Per Device Block", "chain": "forward"},
        ]
        result = forward_authority_order(
            rules,
            ["MC - Per Device Block", "Restricted Devices - Web Policy"],
            "defconf: accept established,related,untracked",
            required_comments=["MC - Per Device Block", "Restricted Devices - Web Policy"],
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["late"], ["MC - Per Device Block"])


class _Resource:
    def __init__(self, rows):
        self.rows = rows

    def get(self, **kwargs):
        if not kwargs:
            return [dict(row) for row in self.rows]
        return [
            dict(row)
            for row in self.rows
            if all(str(row.get(key, "")) == str(value) for key, value in kwargs.items())
        ]


class _Api:
    def __init__(self, rules, queues):
        self.resources = {
            "/ip/firewall/filter": _Resource(rules),
            "/ip/firewall/address-list": _Resource([]),
            "/queue/simple": _Resource(queues),
            "/system/scheduler": _Resource([]),
            "/system/script": _Resource([]),
        }

    def get_resource(self, path):
        return self.resources[path]


class _Pool:
    def disconnect(self):
        pass


class _Adapter(RouterOSAdapter):
    def __init__(self, rules, queues):
        self._api = _Api(rules, queues)

    def _connect(self):
        return _Pool(), self._api


class AuthorityPostureRegressionTests(unittest.TestCase):
    @staticmethod
    def _rules(master_disabled="true", master_position=1):
        master = {
            "comment": "MASTER - Block Restricted Internet",
            "chain": "forward",
            "action": "drop",
            "src-address-list": "Restricted_Devices",
            "out-interface-list": "WAN",
            "disabled": master_disabled,
        }
        device = {
            "comment": "MC - Per Device Block",
            "chain": "forward",
            "action": "drop",
            "src-address-list": "MC_Mode_Blocked",
            "out-interface-list": "WAN",
            "disabled": "false",
        }
        web = {
            "comment": "Restricted Devices - Web Policy",
            "chain": "forward",
            "action": "jump",
            "jump-target": "restricted-web",
            "src-address-list": "Restricted_Devices",
            "disabled": "false",
        }
        established = {
            "comment": "defconf: accept established,related,untracked",
            "chain": "forward",
            "action": "accept",
            "disabled": "false",
        }
        forward = [device, web, established]
        forward.insert(master_position, master)
        return forward + [
            {
                "comment": "RW01 - Block QUIC HTTP3",
                "chain": "restricted-web",
                "action": "drop",
                "protocol": "udp",
                "dst-port": "443",
                "disabled": "false",
            },
            {
                "comment": "MC - Block Restricted DoT",
                "chain": "restricted-web",
                "action": "drop",
                "protocol": "tcp",
                "dst-port": "853",
                "src-address-list": "Restricted_Devices",
                "disabled": "false",
            },
            {
                "comment": "MC - Block Restricted DoQ",
                "chain": "restricted-web",
                "action": "drop",
                "protocol": "udp",
                "dst-port": "853",
                "src-address-list": "Restricted_Devices",
                "disabled": "false",
            },
            {
                "comment": "RW99 - Return",
                "chain": "restricted-web",
                "action": "return",
                "disabled": "false",
            },
        ]

    @staticmethod
    def _queues(slow_disabled="true"):
        return [{
            "name": "Restricted Slow Internet",
            "disabled": slow_disabled,
            "max-limit": "128k/256k",
        }]

    def _posture(self, *, master_disabled="true", master_position=1, slow_disabled="true"):
        adapter = _Adapter(
            self._rules(master_disabled=master_disabled, master_position=master_position),
            self._queues(slow_disabled=slow_disabled),
        )
        with patch("app.router.DOH_ROUTER_RULES", []), patch("app.router.SERVICE_ENFORCEMENT", {}):
            return adapter.get_security_posture()

    def test_normal_mode_disabled_master_is_enforcement_ready(self):
        posture = self._posture(master_disabled="true", master_position=1, slow_disabled="true")
        by_key = {check["key"]: check for check in posture["checks"]}
        self.assertTrue(posture["enforcement_ready"])
        self.assertEqual(posture["authority"]["global_mode"], "normal")
        self.assertEqual(by_key["master"]["status"], "pass")
        self.assertEqual(by_key["global_mode_state"]["status"], "pass")
        self.assertEqual(by_key["forward_order"]["status"], "pass")

    def test_slow_mode_disabled_master_is_enforcement_ready(self):
        posture = self._posture(master_disabled="true", master_position=1, slow_disabled="false")
        self.assertTrue(posture["enforcement_ready"])
        self.assertEqual(posture["authority"]["global_mode"], "slow")

    def test_blocked_mode_master_must_precede_established(self):
        # Insert enabled MASTER after established; this must close the gate.
        posture = self._posture(master_disabled="false", master_position=3, slow_disabled="true")
        by_key = {check["key"]: check for check in posture["checks"]}
        self.assertFalse(posture["enforcement_ready"])
        self.assertEqual(posture["authority"]["global_mode"], "blocked")
        self.assertEqual(by_key["forward_order"]["status"], "fail")

    def test_disabled_master_after_established_is_warning_not_false_critical(self):
        posture = self._posture(master_disabled="true", master_position=3, slow_disabled="true")
        by_key = {check["key"]: check for check in posture["checks"]}
        self.assertTrue(posture["enforcement_ready"])
        self.assertEqual(by_key["inactive_master_placement"]["status"], "warn")


if __name__ == "__main__":
    unittest.main()
