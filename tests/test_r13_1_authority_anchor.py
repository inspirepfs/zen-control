import sys
import types
import unittest
from unittest.mock import patch

sys.modules.setdefault("routeros_api", types.SimpleNamespace())

from app.router import RouterOSAdapter
from app.security import (
    connection_states,
    established_related_accept_candidates,
    forward_authority_order,
)


LEGACY = "defconf: accept established,related,untracked"
MASTER = "MASTER - Block Restricted Internet"
DEVICE = "MC - Per Device Block"
WEB = "Restricted Devices - Web Policy"


class StructuralAnchorHelperTests(unittest.TestCase):
    def test_connection_state_normalises_spacing_and_case(self):
        self.assertEqual(
            connection_states({"connection-state": "Established, related ,UNTRACKED"}),
            {"established", "related", "untracked"},
        )

    def test_renamed_forward_anchor_is_discovered_structurally(self):
        rules = [
            {"comment": LEGACY, "chain": "input", "action": "accept", "connection-state": "established,related,untracked"},
            {"comment": DEVICE, "chain": "forward", "action": "drop"},
            {"comment": WEB, "chain": "forward", "action": "jump"},
            {"comment": "defconf accept established/related", "chain": "forward", "action": "accept", "connection-state": "established,related,untracked"},
        ]
        result = forward_authority_order(
            rules, [DEVICE, WEB], LEGACY, required_comments=[DEVICE, WEB]
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["established_index"], 2)
        self.assertEqual(result["established_anchor"]["source"], "structural")
        self.assertEqual(result["established_anchor"]["comment"], "defconf accept established/related")
        self.assertNotIn(LEGACY, result["missing_required"])

    def test_commentless_forward_anchor_is_discovered_structurally(self):
        rules = [
            {"comment": DEVICE, "chain": "forward", "action": "drop"},
            {"comment": WEB, "chain": "forward", "action": "jump"},
            {"chain": "forward", "action": "accept", "connection-state": "related,established"},
        ]
        result = forward_authority_order(
            rules, [DEVICE, WEB], LEGACY, required_comments=[DEVICE, WEB]
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["established_anchor"]["comment"], "")
        self.assertEqual(result["established_anchor"]["connection_state"], ["established", "related"])

    def test_disabled_structural_candidate_is_ignored(self):
        rules = [
            {"comment": DEVICE, "chain": "forward", "action": "drop"},
            {"chain": "forward", "action": "accept", "connection-state": "established,related", "disabled": "true"},
            {"comment": WEB, "chain": "forward", "action": "jump"},
            {"comment": "active anchor", "chain": "forward", "action": "accept", "connection-state": "established,related", "disabled": "false"},
        ]
        candidates = established_related_accept_candidates(rules)
        self.assertEqual([(i, r.get("comment")) for i, r in candidates], [(3, "active anchor")])
        result = forward_authority_order(
            rules, [DEVICE, WEB], LEGACY, required_comments=[DEVICE, WEB]
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["established_index"], 3)

    def test_earliest_structural_accept_is_conservative_boundary(self):
        rules = [
            {"comment": DEVICE, "chain": "forward", "action": "drop"},
            {"comment": "first established accept", "chain": "forward", "action": "accept", "connection-state": "established,related"},
            {"comment": WEB, "chain": "forward", "action": "jump"},
            {"comment": "second established accept", "chain": "forward", "action": "accept", "connection-state": "established,related,untracked"},
        ]
        result = forward_authority_order(
            rules, [DEVICE, WEB], LEGACY, required_comments=[DEVICE, WEB]
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["established_index"], 1)
        self.assertEqual(result["late"], [WEB])
        self.assertEqual(result["established_anchor"]["candidate_count"], 2)


class _Resource:
    def __init__(self, rows):
        self.rows = rows

    def get(self, **kwargs):
        if not kwargs:
            return [dict(row) for row in self.rows]
        return [
            dict(row) for row in self.rows
            if all(str(row.get(key, "")) == str(value) for key, value in kwargs.items())
        ]


class _Api:
    def __init__(self, rules):
        self.resources = {
            "/ip/firewall/filter": _Resource(rules),
            "/ip/firewall/address-list": _Resource([]),
            "/queue/simple": _Resource([
                {"name": "Restricted Slow Internet", "disabled": "true", "max-limit": "128k/256k"}
            ]),
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
        self._api = _Api(rules)

    def _connect(self):
        return _Pool(), self._api


def posture_rules_with_renamed_forward_anchor():
    return [
        {"comment": LEGACY, "chain": "input", "action": "accept", "connection-state": "established,related,untracked", "disabled": "false"},
        {"comment": MASTER, "chain": "forward", "action": "drop", "src-address-list": "Restricted_Devices", "out-interface-list": "WAN", "disabled": "true"},
        {"comment": DEVICE, "chain": "forward", "action": "drop", "src-address-list": "MC_Mode_Blocked", "out-interface-list": "WAN", "disabled": "false"},
        {"comment": WEB, "chain": "forward", "action": "jump", "jump-target": "restricted-web", "src-address-list": "Restricted_Devices", "disabled": "false"},
        # Real defect reproduction: the FORWARD rule is structurally correct but
        # does not use RouterOSAdapter.ESTABLISHED_RULE_COMMENT.
        {"comment": "defconf accept established,related,untracked", "chain": "forward", "action": "accept", "connection-state": "established,related,untracked", "disabled": "false"},
        {"comment": "RW01 - Block QUIC HTTP3", "chain": "restricted-web", "action": "drop", "protocol": "udp", "dst-port": "443", "disabled": "false"},
        {"comment": "MC - Block Restricted DoT", "chain": "restricted-web", "action": "drop", "protocol": "tcp", "dst-port": "853", "src-address-list": "Restricted_Devices", "disabled": "false"},
        {"comment": "MC - Block Restricted DoQ", "chain": "restricted-web", "action": "drop", "protocol": "udp", "dst-port": "853", "src-address-list": "Restricted_Devices", "disabled": "false"},
        {"comment": "RW99 - Return", "chain": "restricted-web", "action": "return", "disabled": "false"},
    ]


class StructuralAnchorPostureRegressionTests(unittest.TestCase):
    def test_user_reported_renamed_forward_comment_no_longer_closes_gate(self):
        adapter = _Adapter(posture_rules_with_renamed_forward_anchor())
        with patch("app.router.DOH_ROUTER_RULES", []), patch("app.router.SERVICE_ENFORCEMENT", {}):
            posture = adapter.get_security_posture()
        by_key = {check["key"]: check for check in posture["checks"]}
        self.assertTrue(posture["enforcement_ready"])
        self.assertEqual(by_key["forward_order"]["status"], "pass")
        self.assertIn("Structural anchor", by_key["forward_order"]["detail"])
        self.assertIn("defconf accept established,related,untracked", by_key["forward_order"]["detail"])
        self.assertEqual(posture["authority"]["forward_established_anchor"]["source"], "structural")


if __name__ == "__main__":
    unittest.main()
