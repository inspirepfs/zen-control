import sys
import types
import unittest
from datetime import datetime, timezone


psycopg = types.ModuleType("psycopg")
psycopg.Error = Exception
psycopg.connect = None
rows = types.ModuleType("psycopg.rows")
rows.dict_row = object()
sys.modules.setdefault("psycopg", psycopg)
sys.modules.setdefault("psycopg.rows", rows)

from app.activity import ActivityStore, build_service_intelligence


class _MatrixStore(ActivityStore):
    def __init__(self):
        self.calls = []

    def _query(self, sql, params=()):
        self.calls.append((sql, params))
        if "FROM flow_5m" in sql:
            return [{"service_name": "Video", "total_bytes": 20, "flows": 2,
                     "traffic_devices": 1, "last_flow": datetime(2026, 9, 1, tzinfo=timezone.utc)}]
        return [{"service_name": "Video", "queries": 3, "blocked": 1,
                 "dns_devices": 1, "domains": 2, "last_dns": datetime(2026, 9, 2, tzinfo=timezone.utc)}]


class ConcreteServiceMatrixTests(unittest.TestCase):
    def test_bounded_parameterized_matrix_uses_two_catalogue_aggregates(self):
        traffic, dns = _MatrixStore().service_matrix(24, 100)
        store = _MatrixStore()
        store.service_matrix(24, 100)
        self.assertEqual(len(store.calls), 2)
        self.assertTrue(all("%s" in sql and params == (24, 100) for sql, params in store.calls))
        self.assertEqual(traffic[0]["traffic_devices"], 1)
        self.assertEqual(dns[0]["domains"], 2)

    def test_capability_and_all_advisory_contract_states_are_separate(self):
        definition = {"key": "video", "name": "Video", "category": "media",
                      "routeros_managed": True, "enforcement_approved": True,
                      "tls_patterns": ["*video*"], "dns_suffixes": ["video.test"]}
        states = {
            "fresh": "healthy", "stale": "stale", "missing": "missing", "failed": "unverified",
        }
        for observation, expected in states.items():
            with self.subTest(observation=observation):
                health = {"services": [{"key": "video", "healthy": True}]} if observation == "fresh" else {"services": []}
                row = build_service_intelligence([definition], [], [], health,
                                                 router_observation_state=observation)[0]
                self.assertEqual(row["routeros_contract_state"], expected)
                self.assertEqual(row["signature_capability"], "combined")
        degraded = build_service_intelligence([definition], [], [], {"services": [{"key": "video", "healthy": False}]}, router_observation_state="fresh")[0]
        self.assertEqual(degraded["routeros_contract_state"], "degraded")
        self.assertEqual(build_service_intelligence([{**definition, "routeros_managed": False}], [], [], {}, router_observation_state="fresh")[0]["routeros_contract_state"], "not-applicable")

    def test_aggregate_is_a_summary_without_contract_or_classifier_evidence(self):
        rows = build_service_intelligence(
            [{"key": "video", "name": "Video", "tls_patterns": ["*video*"], "routeros_managed": True}],
            [{"service_name": "Video", "total_bytes": 8, "flows": 1}], [],
            {"services": [{"key": "video", "healthy": True}]},
            {"media": {"name": "Media", "members": ["video"]}},
            router_observation_state="fresh",
        )
        group = next(row for row in rows if row["key"] == "media")
        self.assertEqual(group["signature_capability"], "aggregate-summary")
        self.assertEqual(group["routeros_contract_state"], "not-applicable")
        self.assertFalse(group["routeros_managed"])


if __name__ == "__main__":
    unittest.main()
