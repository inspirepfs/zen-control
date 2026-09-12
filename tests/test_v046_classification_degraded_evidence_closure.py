import sys
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Host-side validation remains independent of psycopg installation.
psycopg = types.ModuleType("psycopg")
psycopg.Error = Exception
psycopg.connect = None
rows = types.ModuleType("psycopg.rows")
rows.dict_row = object()
sys.modules.setdefault("psycopg", psycopg)
sys.modules.setdefault("psycopg.rows", rows)

from app.activity import ActivityError, ActivityStore
from app.classification_intelligence import build_candidate_reviews, build_classification_workbench, read_classifier_consumer_status
from app.ux import build_connected_overview

ROOT = Path(__file__).resolve().parents[1]


class _CoverageStore(ActivityStore):
    def __init__(self, flow=None, dns=None, fail_flow=False, fail_dns=False):
        self.flow = flow if flow is not None else {}
        self.dns = dns if dns is not None else {}
        self.fail_flow = fail_flow
        self.fail_dns = fail_dns
        self.calls = []

    def _query(self, sql, params=()):
        self.calls.append(sql)
        if "FROM flow_5m" in sql:
            if self.fail_flow:
                raise ActivityError("Telemetry database unavailable: flow probe")
            return [dict(self.flow)]
        if "FROM dns_queries" in sql:
            if self.fail_dns:
                raise ActivityError("Telemetry database unavailable: dns probe")
            return [dict(self.dns)]
        raise AssertionError(sql)


def _window():
    start = datetime(2026, 9, 10, tzinfo=timezone.utc)
    return start, start + timedelta(hours=1)


class ClassificationEvidenceClosureTests(unittest.TestCase):
    def test_empty_denominators_are_no_evidence_not_zero_percent(self):
        store = _CoverageStore(
            flow={"total_bytes": 0, "classified_bytes": 0, "unclassified_bytes": 0, "service_labels": 0},
            dns={"queries": 0, "classified_queries": 0, "unclassified_queries": 0, "unknown_domains": 0},
        )
        result = store.classification_coverage_range(*_window())
        self.assertEqual(result["evidence_status"], "no_evidence")
        self.assertIsNone(result["traffic_percent"])
        self.assertIsNone(result["dns_percent"])
        self.assertFalse(result["traffic_observed"])
        self.assertFalse(result["dns_observed"])
        self.assertTrue(result["traffic_accounting_valid"])
        self.assertTrue(result["dns_accounting_valid"])
        self.assertEqual(result["traffic_evidence_status"], "no_evidence")
        self.assertEqual(result["dns_evidence_status"], "no_evidence")

    def test_dns_failure_preserves_valid_ipfix_coverage(self):
        store = _CoverageStore(
            flow={"total_bytes": 1000, "classified_bytes": 800, "unclassified_bytes": 200, "service_labels": 3},
            fail_dns=True,
        )
        result = store.classification_coverage_range(*_window())
        self.assertEqual(result["evidence_status"], "partial")
        self.assertTrue(result["traffic_available"])
        self.assertFalse(result["dns_available"])
        self.assertEqual(result["traffic_percent"], 80.0)
        self.assertIsNone(result["dns_percent"])
        self.assertEqual(result["evidence_errors"][0]["source"], "dns")
        self.assertEqual(result["traffic_evidence_status"], "measured")
        self.assertEqual(result["dns_evidence_status"], "unavailable")

    def test_ipfix_failure_preserves_valid_dns_coverage(self):
        store = _CoverageStore(
            dns={"queries": 20, "classified_queries": 15, "unclassified_queries": 5, "unknown_domains": 4},
            fail_flow=True,
        )
        result = store.classification_coverage_range(*_window())
        self.assertEqual(result["evidence_status"], "partial")
        self.assertFalse(result["traffic_available"])
        self.assertTrue(result["dns_available"])
        self.assertIsNone(result["traffic_percent"])
        self.assertEqual(result["dns_percent"], 75.0)

    def test_both_sources_unavailable_are_not_zero_activity(self):
        store = _CoverageStore(fail_flow=True, fail_dns=True)
        result = store.classification_coverage_range(*_window())
        self.assertEqual(result["evidence_status"], "unavailable")
        self.assertIsNone(result["traffic_percent"])
        self.assertIsNone(result["dns_percent"])
        self.assertEqual(len(result["evidence_errors"]), 2)

    def test_inconsistent_accounting_withholds_percentage(self):
        store = _CoverageStore(
            flow={"total_bytes": 1000, "classified_bytes": 900, "unclassified_bytes": 200, "service_labels": 2},
            dns={"queries": 10, "classified_queries": 8, "unclassified_queries": 2, "unknown_domains": 1},
        )
        result = store.classification_coverage_range(*_window())
        self.assertEqual(result["evidence_status"], "inconsistent")
        self.assertFalse(result["traffic_accounting_valid"])
        self.assertIsNone(result["traffic_percent"])
        self.assertEqual(result["dns_percent"], 80.0)

    def test_inconsistent_available_source_is_not_hidden_by_other_source_failure(self):
        store = _CoverageStore(
            flow={"total_bytes": 1000, "classified_bytes": 900, "unclassified_bytes": 200, "service_labels": 2},
            fail_dns=True,
        )
        result = store.classification_coverage_range(*_window())
        self.assertEqual(result["evidence_status"], "inconsistent")
        self.assertEqual(result["traffic_evidence_status"], "inconsistent")
        self.assertEqual(result["dns_evidence_status"], "unavailable")
        self.assertIsNone(result["traffic_percent"])

    def test_negative_retained_counter_is_inconsistent_not_no_evidence(self):
        store = _CoverageStore(
            flow={"total_bytes": -1, "classified_bytes": 0, "unclassified_bytes": 0, "service_labels": 0},
            dns={"queries": 0, "classified_queries": 0, "unclassified_queries": 0, "unknown_domains": 0},
        )
        result = store.classification_coverage_range(*_window())
        self.assertEqual(result["evidence_status"], "inconsistent")
        self.assertEqual(result["traffic_evidence_status"], "inconsistent")
        self.assertFalse(result["traffic_accounting_valid"])
        self.assertIsNone(result["traffic_percent"])

    def test_workbench_does_not_invent_delta_without_comparable_evidence(self):
        payload = build_classification_workbench(
            {
                "traffic_percent": 80.0, "dns_percent": None,
                "traffic_available": True, "dns_available": False,
                "traffic_observed": True, "dns_observed": False,
                "traffic_accounting_valid": True, "dns_accounting_valid": False,
                "evidence_status": "partial", "dns_unclassified_queries": 0,
            },
            {"traffic_percent": 70.0, "dns_percent": 90.0},
            [], [], [], hours=24,
        )
        self.assertEqual(payload["deltas"]["traffic_pp"], 10.0)
        self.assertIsNone(payload["deltas"]["dns_pp"])
        self.assertEqual(payload["trend"], "improving")
        self.assertEqual(payload["evidence"]["status"], "partial")
        self.assertTrue(payload["evidence"]["accounting_valid"])

    def test_no_current_or_previous_evidence_makes_trend_unknown(self):
        payload = build_classification_workbench(
            {"traffic_percent": None, "dns_percent": None, "dns_unclassified_queries": 0},
            {"traffic_percent": None, "dns_percent": None}, [], [], [], hours=24,
        )
        self.assertIsNone(payload["deltas"]["traffic_pp"])
        self.assertIsNone(payload["deltas"]["dns_pp"])
        self.assertEqual(payload["trend"], "unknown")

    def test_bounded_candidate_list_reconciles_to_unknown_query_denominator(self):
        services = []
        payload = build_classification_workbench(
            {"dns_unclassified_queries": 100}, {}, [],
            [{"domain": "a.example", "queries": 30}, {"domain": "b.example", "queries": 20}],
            services, hours=24,
        )
        accounting = payload["candidate_accounting"]
        self.assertEqual(accounting["listed_queries"], 50)
        self.assertEqual(accounting["listed_share_percent"], 50.0)
        self.assertTrue(accounting["valid"])

    def test_candidate_over_accounting_is_flagged_not_normalised(self):
        payload = build_classification_workbench(
            {"dns_unclassified_queries": 10}, {}, [],
            [{"domain": "a.example", "queries": 8}, {"domain": "b.example", "queries": 7}],
            [], hours=24,
        )
        self.assertFalse(payload["candidate_accounting"]["valid"])
        self.assertIsNone(payload["candidate_accounting"]["listed_share_percent"])
        self.assertEqual(payload["candidate_accounting"]["computed_share_percent"], 150.0)
        self.assertTrue(all(item["unknown_query_share"] is None for item in payload["candidates"]))
        self.assertFalse(payload["evidence"]["accounting_valid"])

    def test_late_candidate_rows_with_zero_captured_denominator_withhold_shares(self):
        payload = build_classification_workbench(
            {"dns_unclassified_queries": 0}, {}, [],
            [{"domain": "late.example", "queries": 3}], [], hours=24,
        )
        self.assertFalse(payload["candidate_accounting"]["valid"])
        self.assertIsNone(payload["candidate_accounting"]["listed_share_percent"])
        self.assertIsNone(payload["candidates"][0]["unknown_query_share"])

    def test_candidate_review_state_follows_current_catalogue_without_rewriting_history(self):
        candidate = [{"domain": "edge.example.net", "queries": 4}]
        before = build_candidate_reviews(candidate, [], 4)[0]
        promoted = build_candidate_reviews(candidate, [{
            "key": "example", "name": "Example Service", "dns_suffixes": ["example.net"],
            "classifier_enabled": True,
        }], 4)[0]
        removed = build_candidate_reviews(candidate, [], 4)[0]
        self.assertEqual(before["review_state"], "unmatched")
        self.assertEqual(promoted["review_state"], "signature_match")
        self.assertEqual(promoted["signature_matches"][0]["key"], "example")
        self.assertEqual(removed["review_state"], "unmatched")
        self.assertEqual(candidate[0], {"domain": "edge.example.net", "queries": 4})


class ClassifierConsumerHeartbeatTests(unittest.TestCase):
    def test_fresh_live_heartbeat_is_available(self):
        import json, tempfile
        now = datetime(2026, 9, 10, 9, 0, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "classifier-status.json"
            path.write_text(json.dumps({
                "schema": "zen_classifier_consumer_status_v1",
                "observed_at": (now - timedelta(seconds=4)).isoformat(),
                "source": "live", "services": 12, "signatures": 31,
                "has_live": True, "error": "",
            }))
            result = read_classifier_consumer_status(path, now=now, stale_after_seconds=30)
        self.assertEqual(result["availability"], "available")
        self.assertEqual(result["source"], "live")
        self.assertEqual(result["age_seconds"], 4.0)
        self.assertEqual(result["signatures"], 31)
        self.assertFalse(result["degraded"])

    def test_stale_live_consumer_state_is_preserved_and_visible(self):
        import json, tempfile
        now = datetime(2026, 9, 10, 9, 0, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "classifier-status.json"
            path.write_text(json.dumps({
                "schema": "zen_classifier_consumer_status_v1",
                "observed_at": (now - timedelta(seconds=3)).isoformat(),
                "source": "stale_live", "services": 12, "signatures": 31,
                "has_live": True, "error": "JSONDecodeError: replacement invalid",
            }))
            result = read_classifier_consumer_status(path, now=now)
        self.assertEqual(result["availability"], "available")
        self.assertEqual(result["source"], "stale_live")
        self.assertTrue(result["has_live"])
        self.assertTrue(result["degraded"])
        self.assertIn("JSONDecodeError", result["error"])

    def test_valid_empty_live_catalogue_is_healthy_not_fallback(self):
        import json, tempfile
        now = datetime(2026, 9, 10, 9, 0, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "classifier-status.json"
            path.write_text(json.dumps({
                "schema": "zen_classifier_consumer_status_v1",
                "observed_at": (now - timedelta(seconds=2)).isoformat(),
                "source": "live", "services": 0, "signatures": 0,
                "has_live": True, "error": "",
            }))
            result = read_classifier_consumer_status(path, now=now)
        self.assertEqual(result["availability"], "available")
        self.assertEqual(result["source"], "live")
        self.assertTrue(result["has_live"])
        self.assertFalse(result["degraded"])

    def test_bootstrap_fallback_is_available_but_explicitly_degraded(self):
        import json, tempfile
        now = datetime(2026, 9, 10, 9, 0, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "classifier-status.json"
            path.write_text(json.dumps({
                "schema": "zen_classifier_consumer_status_v1",
                "observed_at": (now - timedelta(seconds=2)).isoformat(),
                "source": "fallback", "services": 8, "signatures": 18,
                "has_live": False, "error": "catalogue not published yet",
            }))
            result = read_classifier_consumer_status(path, now=now)
        self.assertEqual(result["availability"], "available")
        self.assertEqual(result["source"], "fallback")
        self.assertFalse(result["has_live"])
        self.assertTrue(result["degraded"])

    def test_old_heartbeat_is_stale_not_healthy(self):
        import json, tempfile
        now = datetime(2026, 9, 10, 9, 0, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "classifier-status.json"
            path.write_text(json.dumps({
                "schema": "zen_classifier_consumer_status_v1",
                "observed_at": (now - timedelta(seconds=90)).isoformat(),
                "source": "live", "services": 10, "signatures": 20,
                "has_live": True, "error": "",
            }))
            result = read_classifier_consumer_status(path, now=now, stale_after_seconds=30)
        self.assertEqual(result["availability"], "stale")
        self.assertEqual(result["source"], "live")
        self.assertEqual(result["age_seconds"], 90.0)
        self.assertTrue(result["degraded"])

    def test_missing_or_malformed_heartbeat_is_unavailable(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "classifier-status.json"
            missing = read_classifier_consumer_status(path)
            path.write_text("{bad-json")
            malformed = read_classifier_consumer_status(path)
        self.assertEqual(missing["availability"], "unavailable")
        self.assertEqual(malformed["availability"], "unavailable")
        self.assertTrue(missing["degraded"])
        self.assertTrue(malformed["degraded"])

    def test_compose_shares_only_sanitized_classifier_state_read_only(self):
        compose = (ROOT / "docker-compose.yml").read_text()
        ingest = (ROOT / "telemetry/ingest/ingest.py").read_text()
        self.assertIn("CLASSIFIER_STATUS_FILE: /state/classifier-status.json", compose)
        self.assertIn("telemetry-state:/telemetry-state:ro", compose)
        self.assertIn("CLASSIFIER_STATUS_FILE: /telemetry-state/classifier-status.json", compose)
        self.assertIn('"schema":"zen_classifier_consumer_status_v1"', ingest)
        for forbidden in ('"domain"', '"client_ip"', '"device"', '"queries"', '"bytes"'):
            status_block = ingest.split("def publish_classifier_status", 1)[1].split("def retention_worker", 1)[0]
            self.assertNotIn(forbidden, status_block)


class ClassificationEvidenceUxClosureTests(unittest.TestCase):
    def test_workbench_surfaces_no_evidence_partial_and_accounting_boundaries(self):
        template = (ROOT / "app/templates/classification.html").read_text()
        for phrase in (
            "NO EVIDENCE",
            "UNAVAILABLE",
            "INCONSISTENT",
            "DEGRADED EVIDENCE",
            "Classification accounting mismatch detected",
            "bounded candidate list",
            "Telemetry consumer",
        ):
            self.assertIn(phrase, template)

    def test_activity_and_dashboard_preserve_classification_evidence_states(self):
        main = (ROOT / "app/main.py").read_text()
        index = (ROOT / "app/templates/index.html").read_text()
        self.assertNotIn('float(activity_coverage.get("traffic_percent") or 0.0)', main)
        self.assertNotIn('float(activity_coverage.get("dns_percent") or 0.0)', main)
        self.assertIn('"traffic_classification_status"', main)
        self.assertIn('"dns_classification_status"', main)
        self.assertIn("activity_coverage.traffic_accounting_valid is sameas false", index)
        self.assertIn("activity_coverage.dns_accounting_valid is sameas false", index)
        self.assertIn("activity_insights.dns_classification_status", index)

    def test_connected_overview_never_turns_no_evidence_or_partial_failure_into_zero(self):
        common = {
            "live_status": {"mode": "NORMAL"},
            "devices": [{"ip": "192.0.2.10"}],
            "policy_plans": {"192.0.2.10": {"status": "in_sync"}},
            "security_posture": {"enforcement_ready": True, "critical_count": 0, "warning_count": 0},
            "reconciler_status": {"mode": "enforce", "worker_alive": True, "hold_active": False},
            "service_contract_health": {"available": True, "healthy": 1, "total": 1, "degraded": 0, "reporting_only": 0},
            "telemetry_available": True,
            "database_integrity": {"ok": True},
            "operations_startup": {"status": "ready"},
            "incident_counts": {"active": 0, "resolved": 0},
            "audit_total": 0,
        }
        no_evidence = build_connected_overview(**common, activity_insights={
            "managed_devices_seen": 0,
            "traffic_classified_percent": None,
            "dns_classified_percent": None,
            "traffic_classification_status": "no_evidence",
            "dns_classification_status": "no_evidence",
            "unknown_domains": 0,
        })
        activity = next(row for row in no_evidence["areas"] if row["key"] == "activity")
        self.assertIn("traffic NO EVIDENCE", activity["facts"])
        self.assertIn("DNS NO EVIDENCE", activity["facts"])
        self.assertNotIn("traffic 0.0% classified", activity["facts"])

        partial = build_connected_overview(**common, activity_insights={
            "managed_devices_seen": 1,
            "traffic_classified_percent": 80.0,
            "dns_classified_percent": None,
            "traffic_classification_status": "measured",
            "dns_classification_status": "unavailable",
            "unknown_domains": 0,
        })
        activity = next(row for row in partial["areas"] if row["key"] == "activity")
        self.assertEqual(activity["state"], "warning")
        self.assertIn("traffic 80.0% classified", activity["facts"])
        self.assertIn("DNS UNAVAILABLE", activity["facts"])
        self.assertIn("unknown domains UNAVAILABLE", activity["facts"])

    def test_help_states_zero_denominator_and_partial_failure_semantics(self):
        help_text = (ROOT / "app/help_content.py").read_text()
        self.assertIn("Zero observed bytes or DNS queries are NO EVIDENCE", help_text)
        self.assertIn("Missing IPFIX or DNS stays unavailable rather than becoming zero", help_text)
        self.assertIn("Activity, dashboard and Classification Intelligence preserve the same", help_text)

    def test_workbench_partial_component_queries_are_guarded(self):
        main = (ROOT / "app/main.py").read_text()
        segment = main.split("def _classification_workbench_payload", 1)[1].split('@app.get("/api/activity/classification")', 1)[0]
        self.assertIn('"candidate_dns"', segment)
        self.assertIn('"service_movement"', segment)
        self.assertIn('payload["degraded_evidence"]', segment)
        self.assertIn('current.get("dns_available", True)', segment)
        self.assertIn('read_classifier_consumer_status()', segment)
        self.assertIn('classifier_consumer.get("degraded")', segment)
        self.assertIn('bootstrap fallback catalogue', segment)


if __name__ == "__main__":
    unittest.main()
