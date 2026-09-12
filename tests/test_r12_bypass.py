import sys
import types
import unittest
from datetime import datetime, timezone

try:
    import psycopg  # noqa: F401
except ModuleNotFoundError:
    psycopg_stub = types.ModuleType("psycopg")
    psycopg_stub.Error = Exception
    psycopg_stub.connect = lambda *args, **kwargs: None
    rows_stub = types.ModuleType("psycopg.rows")
    rows_stub.dict_row = object()
    psycopg_stub.rows = rows_stub
    sys.modules["psycopg"] = psycopg_stub
    sys.modules["psycopg.rows"] = rows_stub

from app.activity import ActivityStore
from app.bypass import (
    DOH_ROUTER_RULES,
    classify_doh_domain,
    classify_port_signal,
    summarize_bypass_evidence,
)


class BypassClassifierTests(unittest.TestCase):
    def test_known_doh_subdomain_matches_cloudflare_suffix(self):
        signal = classify_doh_domain("family.cloudflare-dns.com", source="flow")
        self.assertIsNotNone(signal)
        self.assertEqual(signal["key"], "known_doh_flow")
        self.assertEqual(signal["confidence"], "high")

    def test_generic_https_is_not_guessed(self):
        self.assertIsNone(classify_port_signal("TCP", 443))
        self.assertIsNone(classify_doh_domain("example.com", source="flow"))

    def test_wireguard_default_is_medium_confidence_only(self):
        signal = classify_port_signal("udp", 51820)
        self.assertEqual(signal["key"], "wireguard_default")
        self.assertEqual(signal["confidence"], "medium")
        self.assertIn("any UDP port", signal["detail"])

    def test_external_dns_is_high_confidence_bypass_evidence(self):
        signal = classify_port_signal("UDP", 53)
        self.assertEqual(signal["key"], "external_dns")
        self.assertEqual(signal["confidence"], "high")

    def test_router_doh_catalog_comments_are_unique(self):
        comments = [item["comment"] for item in DOH_ROUTER_RULES]
        self.assertEqual(len(comments), len(set(comments)))
        self.assertGreaterEqual(len(comments), 7)


class BypassSummaryTests(unittest.TestCase):
    def test_repeated_same_signal_is_bounded(self):
        rows = [
            {
                "client_ip": "192.168.2.22",
                "key": "wireguard_default",
                "category": "vpn",
                "confidence": "medium",
                "weight": 8,
                "flows": 20,
                "last_seen": "2026-09-08T20:00:00+00:00",
            },
            {
                "client_ip": "192.168.2.22",
                "key": "wireguard_default",
                "category": "vpn",
                "confidence": "medium",
                "weight": 8,
                "flows": 30,
                "last_seen": "2026-09-08T20:05:00+00:00",
            },
        ]
        result = summarize_bypass_evidence(rows)
        self.assertLess(result["score"], 25)
        self.assertEqual(result["affected_devices"], 1)
        self.assertEqual(result["devices"][0]["flows"], 50)

    def test_mixed_high_confidence_signals_escalate(self):
        rows = [
            {
                "client_ip": "192.168.2.22",
                "key": "known_doh_flow",
                "category": "dns",
                "confidence": "high",
                "weight": 18,
                "flows": 2,
            },
            {
                "client_ip": "192.168.2.22",
                "key": "external_dns",
                "category": "dns",
                "confidence": "high",
                "weight": 16,
                "flows": 3,
            },
            {
                "client_ip": "192.168.2.22",
                "key": "ipsec_natt",
                "category": "vpn",
                "confidence": "medium",
                "weight": 9,
                "flows": 1,
            },
        ]
        result = summarize_bypass_evidence(rows)
        self.assertIn(result["status"], {"elevated", "high"})
        self.assertEqual(result["high_confidence"], 2)


class _FakeActivity(ActivityStore):
    def __init__(self):
        pass

    def _query(self, sql, params=()):
        now = datetime(2026, 9, 8, 20, 0, tzinfo=timezone.utc)
        if "dst_port = ANY" in sql:
            return [
                {
                    "client_ip": "192.168.2.22",
                    "remote_ip": "8.8.8.8",
                    "dst_port": 53,
                    "protocol": "UDP",
                    "total_bytes": 500,
                    "packets": 4,
                    "flows": 2,
                    "last_seen": now,
                },
                {
                    "client_ip": "192.168.2.22",
                    "remote_ip": "203.0.113.10",
                    "dst_port": 51820,
                    "protocol": "UDP",
                    "total_bytes": 5000,
                    "packets": 20,
                    "flows": 3,
                    "last_seen": now,
                },
            ]
        if "FROM flows_raw" in sql and "domain <> ''" in sql:
            return [
                {
                    "client_ip": "192.168.2.22",
                    "remote_ip": "1.1.1.1",
                    "dst_port": 443,
                    "protocol": "TCP",
                    "domain": "family.cloudflare-dns.com",
                    "total_bytes": 900,
                    "packets": 6,
                    "flows": 2,
                    "last_seen": now,
                }
            ]
        if "FROM dns_queries" in sql:
            return [
                {
                    "client_ip": "192.168.2.22",
                    "domain": "family.cloudflare-dns.com",
                    "queries": 2,
                    "last_seen": now,
                },
                {
                    "client_ip": "192.168.2.22",
                    "domain": "dns.nextdns.io",
                    "queries": 1,
                    "last_seen": now,
                },
            ]
        raise AssertionError(sql)


class ActivityBypassEvidenceTests(unittest.TestCase):
    def test_activity_combines_port_flow_and_lookup_evidence(self):
        rows = _FakeActivity().bypass_evidence(["192.168.2.22"], 24, 50)
        keys = [item["key"] for item in rows]
        self.assertIn("external_dns", keys)
        self.assertIn("wireguard_default", keys)
        self.assertIn("known_doh_flow", keys)
        self.assertIn("known_doh_lookup", keys)
        # Cloudflare DNS lookup is suppressed because stronger correlated flow
        # evidence exists for the same client/domain.
        cloudflare = [item for item in rows if item.get("domain") == "family.cloudflare-dns.com"]
        self.assertEqual(len(cloudflare), 1)
        self.assertEqual(cloudflare[0]["key"], "known_doh_flow")

    def test_invalid_clients_return_no_evidence_without_query(self):
        self.assertEqual(_FakeActivity().bypass_evidence(["not-an-ip"]), [])


if __name__ == "__main__":
    unittest.main()
