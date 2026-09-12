import sys
import types
import unittest
from unittest.mock import patch

sys.modules.setdefault("routeros_api", types.SimpleNamespace())

from app.router import RouterOSAdapter
from app.security import chain_rules, forward_authority_order, same_comment_other_chains


ESTABLISHED = "defconf: accept established,related,untracked"
MASTER = "MASTER - Block Restricted Internet"
DEVICE = "MC - Per Device Block"
WEB = "Restricted Devices - Web Policy"


class ChainHelperTests(unittest.TestCase):
    def test_chain_rules_preserves_relative_order(self):
        rules = [
            {"comment": "input-a", "chain": "input"},
            {"comment": DEVICE, "chain": "forward"},
            {"comment": "custom", "chain": "restricted-web"},
            {"comment": WEB, "chain": "forward"},
            {"comment": ESTABLISHED, "chain": "forward"},
        ]
        self.assertEqual(
            [r["comment"] for r in chain_rules(rules, "forward")],
            [DEVICE, WEB, ESTABLISHED],
        )

    def test_input_established_with_same_comment_is_ignored(self):
        rules = [
            {"comment": ESTABLISHED, "chain": "input"},
            {"comment": DEVICE, "chain": "forward"},
            {"comment": WEB, "chain": "forward"},
            {"comment": ESTABLISHED, "chain": "forward"},
        ]
        result = forward_authority_order(
            rules,
            [DEVICE, WEB],
            ESTABLISHED,
            required_comments=[DEVICE, WEB],
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["positions"][ESTABLISHED], 2)
        self.assertEqual(result["other_chain_collisions"], {ESTABLISHED: ["input"]})

    def test_input_anchor_only_does_not_satisfy_forward_contract(self):
        rules = [
            {"comment": ESTABLISHED, "chain": "input"},
            {"comment": DEVICE, "chain": "forward"},
            {"comment": WEB, "chain": "forward"},
        ]
        result = forward_authority_order(
            rules,
            [DEVICE, WEB],
            ESTABLISHED,
            required_comments=[DEVICE, WEB],
        )
        self.assertFalse(result["ok"])
        self.assertIn(ESTABLISHED, result["missing_required"])

    def test_actual_late_forward_rule_still_fails(self):
        rules = [
            {"comment": ESTABLISHED, "chain": "input"},
            {"comment": DEVICE, "chain": "forward"},
            {"comment": ESTABLISHED, "chain": "forward"},
            {"comment": WEB, "chain": "forward"},
        ]
        result = forward_authority_order(
            rules,
            [DEVICE, WEB],
            ESTABLISHED,
            required_comments=[DEVICE, WEB],
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["late"], [WEB])

    def test_restricted_web_rows_do_not_distort_forward_positions(self):
        rules = [
            {"comment": DEVICE, "chain": "forward"},
            {"comment": "RW01", "chain": "restricted-web"},
            {"comment": "RW02", "chain": "restricted-web"},
            {"comment": WEB, "chain": "forward"},
            {"comment": "RW03", "chain": "restricted-web"},
            {"comment": ESTABLISHED, "chain": "forward"},
        ]
        result = forward_authority_order(
            rules,
            [DEVICE, WEB],
            ESTABLISHED,
            required_comments=[DEVICE, WEB],
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["positions"], {DEVICE: 0, WEB: 1, ESTABLISHED: 2})
        self.assertEqual(result["chain_rule_count"], 3)

    def test_duplicate_forward_anchor_is_rejected_even_with_input_collision(self):
        rules = [
            {"comment": ESTABLISHED, "chain": "input"},
            {"comment": DEVICE, "chain": "forward"},
            {"comment": WEB, "chain": "forward"},
            {"comment": ESTABLISHED, "chain": "forward"},
            {"comment": ESTABLISHED, "chain": "forward"},
        ]
        result = forward_authority_order(
            rules,
            [DEVICE, WEB],
            ESTABLISHED,
            required_comments=[DEVICE, WEB],
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["duplicates"][ESTABLISHED], 2)

    def test_same_comment_other_chains_reports_unique_chains(self):
        rules = [
            {"comment": ESTABLISHED, "chain": "input"},
            {"comment": ESTABLISHED, "chain": "output"},
            {"comment": ESTABLISHED, "chain": "input"},
            {"comment": ESTABLISHED, "chain": "forward"},
        ]
        self.assertEqual(
            same_comment_other_chains(rules, ESTABLISHED, "forward"),
            ["input", "output"],
        )


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
    def __init__(self, rules):
        self._api = _Api(
            rules,
            [{"name": "Restricted Slow Internet", "disabled": "true", "max-limit": "128k/256k"}],
        )

    def _connect(self):
        return _Pool(), self._api


def base_rules(*, web_after_forward_established=False, add_input_established=True, input_rw99=False):
    rules = []
    if add_input_established:
        # This is the real-world collision that triggered R12.1's false failure.
        rules.append({
            "comment": ESTABLISHED,
            "chain": "input",
            "action": "accept",
            "connection-state": "established,related,untracked",
            "disabled": "false",
        })
    rules.extend([
        {
            "comment": MASTER,
            "chain": "forward",
            "action": "drop",
            "src-address-list": "Restricted_Devices",
            "out-interface-list": "WAN",
            "disabled": "true",
        },
        {
            "comment": DEVICE,
            "chain": "forward",
            "action": "drop",
            "src-address-list": "MC_Mode_Blocked",
            "out-interface-list": "WAN",
            "disabled": "false",
        },
    ])
    forward_established = {
        "comment": ESTABLISHED,
        "chain": "forward",
        "action": "accept",
        "connection-state": "established,related,untracked",
        "disabled": "false",
    }
    web = {
        "comment": WEB,
        "chain": "forward",
        "action": "jump",
        "jump-target": "restricted-web",
        "src-address-list": "Restricted_Devices",
        "disabled": "false",
    }
    if web_after_forward_established:
        rules.extend([forward_established, web])
    else:
        rules.extend([web, forward_established])

    if input_rw99:
        rules.append({"comment": "RW99 - Return", "chain": "input", "action": "return", "disabled": "false"})

    rules.extend([
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
        {"comment": "RW99 - Return", "chain": "restricted-web", "action": "return", "disabled": "false"},
    ])
    return rules


class ChainAwarePostureTests(unittest.TestCase):
    def _posture(self, rules):
        adapter = _Adapter(rules)
        with patch("app.router.DOH_ROUTER_RULES", []), patch("app.router.SERVICE_ENFORCEMENT", {}):
            return adapter.get_security_posture()

    def test_real_world_input_forward_comment_collision_no_longer_closes_gate(self):
        posture = self._posture(base_rules(add_input_established=True))
        by_key = {check["key"]: check for check in posture["checks"]}
        self.assertTrue(posture["enforcement_ready"])
        self.assertEqual(by_key["forward_order"]["status"], "pass")
        self.assertIn("input", by_key["forward_order"]["detail"])
        self.assertEqual(posture["authority"]["forward_positions"][ESTABLISHED], 3)

    def test_true_forward_chain_ordering_defect_still_closes_gate(self):
        posture = self._posture(base_rules(web_after_forward_established=True))
        by_key = {check["key"]: check for check in posture["checks"]}
        self.assertFalse(posture["enforcement_ready"])
        self.assertEqual(by_key["forward_order"]["status"], "fail")
        self.assertIn(WEB, by_key["forward_order"]["detail"])

    def test_input_rw99_comment_does_not_break_restricted_web_anchor(self):
        posture = self._posture(base_rules(input_rw99=True))
        by_key = {check["key"]: check for check in posture["checks"]}
        self.assertEqual(by_key["restricted_web_order"]["status"], "pass")
        self.assertTrue(posture["enforcement_ready"])

    def test_custom_managed_rule_after_rw99_closes_gate(self):
        rules = base_rules()
        rules.append({
            "comment": "MC|SVC|minecraft|BLOCK|01",
            "chain": "restricted-web",
            "action": "drop",
            "disabled": "false",
        })
        posture = self._posture(rules)
        by_key = {check["key"]: check for check in posture["checks"]}
        self.assertFalse(posture["enforcement_ready"])
        self.assertEqual(by_key["restricted_web_order"]["status"], "fail")
        self.assertIn("MC|SVC|minecraft|BLOCK|01", by_key["restricted_web_order"]["detail"])

    def test_forward_rule_count_is_chain_local(self):
        rules = base_rules(add_input_established=True, input_rw99=True)
        posture = self._posture(rules)
        self.assertEqual(posture["authority"]["forward_chain_rule_count"], 4)


if __name__ == "__main__":
    unittest.main()
