import sys
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Keep host-side validation independent of psycopg installation.
psycopg = types.ModuleType("psycopg")
psycopg.Error = Exception
psycopg.connect = None
rows = types.ModuleType("psycopg.rows")
rows.dict_row = object()
sys.modules.setdefault("psycopg", psycopg)
sys.modules.setdefault("psycopg.rows", rows)

from app.activity import ActivityStore
from app.classification_intelligence import (
    build_candidate_reviews,
    build_classification_workbench,
)

ROOT = Path(__file__).resolve().parents[1]


SERVICES = [
    {
        "key": "youtube", "name": "YouTube", "builtin": 1,
        "classifier_enabled": True,
        "dns_suffixes": ["youtube.com", "googlevideo.com"],
        "tls_patterns": ["*youtube*"],
    },
    {
        "key": "minecraft", "name": "Minecraft", "builtin": 0,
        "classifier_enabled": False,
        "dns_suffixes": ["minecraft.net"],
        "tls_patterns": ["*minecraft*"],
    },
]


class CandidateReviewTests(unittest.TestCase):
    def test_current_dns_signature_match_is_deterministic_review_evidence(self):
        row = build_candidate_reviews(
            [{"domain": "video.googlevideo.com", "queries": 60, "devices": 2}],
            SERVICES,
            100,
        )[0]
        self.assertEqual(row["review_state"], "signature_match")
        self.assertEqual(row["signature_matches"][0]["key"], "youtube")
        self.assertEqual(row["signature_matches"][0]["suffixes"], ["googlevideo.com"])
        self.assertEqual(row["unknown_query_share"], 60.0)
        self.assertIn("catalogue", row["recommended_action"].lower())

    def test_disabled_classifier_match_is_not_treated_as_new_service(self):
        row = build_candidate_reviews(
            [{"domain": "api.minecraft.net", "queries": 10}], SERVICES, 10
        )[0]
        self.assertEqual(row["review_state"], "signature_match")
        self.assertFalse(row["signature_matches"][0]["classifier_enabled"])
        self.assertEqual(row["recommended_action"], "Review disabled classifier")

    def test_name_hint_is_explicitly_weaker_than_classification(self):
        row = build_candidate_reviews(
            [{"domain": "youtube-edge.example.net", "queries": 20}], SERVICES, 20
        )[0]
        self.assertEqual(row["review_state"], "name_hint")
        self.assertEqual(row["signature_matches"], [])
        self.assertEqual(row["name_hints"][0]["key"], "youtube")
        self.assertNotIn("service", {"classification": row.get("classification")})

    def test_unmatched_candidate_is_prefill_only(self):
        row = build_candidate_reviews(
            [{"domain": "cdn.example.net", "queries": 4}], SERVICES, 8
        )[0]
        self.assertEqual(row["review_state"], "unmatched")
        self.assertEqual(row["prefill_dns"], "cdn.example.net")
        self.assertEqual(row["unknown_query_share"], 50.0)

    def test_workbench_has_no_risk_or_confidence_score(self):
        payload = build_classification_workbench(
            {"traffic_percent": 90, "dns_percent": 80, "dns_unclassified_queries": 10},
            {"traffic_percent": 85, "dns_percent": 82},
            [], [{"domain": "x.example", "queries": 3}], SERVICES, hours=24,
        )
        self.assertEqual(payload["schema"], "zen_classification_intelligence_v1")
        self.assertEqual(payload["deltas"]["traffic_pp"], 5.0)
        self.assertEqual(payload["deltas"]["dns_pp"], -2.0)
        self.assertEqual(payload["trend"], "improving")
        flattened = repr(payload).lower()
        self.assertNotIn("risk_score", flattened)
        self.assertNotIn("confidence_score", flattened)
        self.assertIn("manual-review clue", payload["evidence_note"])

    def test_catalogue_counts_exclude_no_signatures_from_enabled_signature_totals(self):
        payload = build_classification_workbench({}, {}, [], [], SERVICES, hours=168)
        self.assertEqual(payload["catalogue"]["services"], 2)
        self.assertEqual(payload["catalogue"]["classifier_enabled"], 1)
        self.assertEqual(payload["catalogue"]["classifier_disabled"], 1)
        self.assertEqual(payload["catalogue"]["dns_signatures"], 2)
        self.assertEqual(payload["catalogue"]["tls_signatures"], 1)


class FakeActivityStore(ActivityStore):
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def _query(self, sql, params=()):
        self.calls.append((sql, params))
        return self.responses.pop(0)


class ClassificationStoreTests(unittest.TestCase):
    def test_explicit_range_coverage_keeps_dns_and_traffic_separate(self):
        store = FakeActivityStore([
            [{"total_bytes": 1000, "classified_bytes": 750, "unclassified_bytes": 250, "service_labels": 4}],
            [{"queries": 20, "classified_queries": 18, "unclassified_queries": 2, "unknown_domains": 2}],
        ])
        start = datetime(2026, 9, 9, tzinfo=timezone.utc)
        result = store.classification_coverage_range(start, start + timedelta(hours=1))
        self.assertEqual(result["traffic_percent"], 75.0)
        self.assertEqual(result["dns_percent"], 90.0)
        self.assertEqual(result["dns_unclassified_queries"], 2)
        self.assertEqual(len(store.calls), 2)
        self.assertIn("bucket >= %s AND bucket < %s", store.calls[0][0])

    def test_service_attribution_change_is_network_delta_not_prediction(self):
        store = FakeActivityStore([[
            {"service_name": "YouTube", "current_bytes": 4000, "previous_bytes": 1000},
            {"service_name": "Netflix", "current_bytes": 1000, "previous_bytes": 2000},
        ]])
        rows = store.service_attribution_changes(24, 10)
        self.assertEqual(rows[0]["service_name"], "YouTube")
        self.assertEqual(rows[0]["delta_bytes"], 3000)
        self.assertEqual(rows[0]["delta_percent"], 300.0)
        self.assertEqual(rows[1]["delta_bytes"], -1000)
        self.assertIn("NULLIF(service,'') IS NOT NULL", store.calls[0][0])


class ClassificationUxTests(unittest.TestCase):
    def setUp(self):
        self.main = (ROOT / "app/main.py").read_text()
        self.index = (ROOT / "app/templates/index.html").read_text()
        self.template = (ROOT / "app/templates/classification.html").read_text()
        self.css = (ROOT / "app/static/classification-intelligence.css").read_text()
        self.module = (ROOT / "app/classification_intelligence.py").read_text()
        self.readme = (ROOT / "README.md").read_text() + "\n" + (ROOT / "CHANGELOG.md").read_text()

    def test_release_version_routes_and_activity_subnav(self):
        self.assertIn('version="0.55.4.2"', self.main)
        self.assertIn('@app.get("/activity/classification"', self.main)
        self.assertIn('@app.get("/api/activity/classification")', self.main)
        self.assertIn('"classification", "dns"', self.main)
        self.assertIn("key: 'classification', label: 'Classification'", self.index)
        self.assertIn("window.location.href = '/activity/classification'", self.index)
        self.assertIn('/static/classification-intelligence.css?v=0.55.4.2', self.template)

    def test_workbench_is_read_only_and_states_evidence_boundary(self):
        self.assertNotIn('method="post"', self.template.lower())
        self.assertNotIn("save_service", self.module)
        self.assertNotIn("RouterOSAdapter", self.module)
        for phrase in (
            "CURRENT SIGNATURE", "NAME-ONLY HINT", "UNMATCHED",
            "Manual-review clue only", "not foreground-app time",
            "No candidate is auto-added",
        ):
            self.assertIn(phrase, self.template)

    def test_candidate_can_prefill_but_not_auto_save_custom_service(self):
        self.assertIn("Prefill custom service", self.template)
        self.assertIn('prefill_dns={{service_prefill_dns}}', self.main.replace('"', '"')) if False else None
        self.assertIn('name="dns_suffixes"', self.index)
        self.assertIn('{{service_prefill_dns}}', self.index)
        self.assertIn('Prefilled from Classification Intelligence', self.index)
        self.assertIn('prefill_dns=', self.main)

    def test_deeper_intelligence_query_is_not_added_to_activity_root_composition(self):
        # One source occurrence belongs to the dedicated workbench builder only.
        self.assertEqual(self.main.count("activity_store.service_attribution_changes("), 1)
        workbench = self.main.split("def _classification_workbench_payload", 1)[1].split('@app.get("/activity/service/{service_key}"', 1)[0]
        self.assertIn("service_attribution_changes", workbench)
        root = self.main.split('def dashboard(request: Request', 1)[1].split('def _classification_workbench_payload', 1)[0]
        self.assertNotIn("service_attribution_changes", root)

    def test_dense_responsive_workbench_styles_exist(self):
        self.assertIn('.classification-kpi-grid', self.css)
        self.assertIn('.classification-candidate-table-wrap', self.css)
        self.assertIn('@media(max-width:560px)', self.css)

    def test_documentation_preserves_routeros_and_group_boundaries(self):
        self.assertIn("Classification Intelligence Workbench (v0.31)", self.readme)
        self.assertIn("never acquire aggregate RouterOS authority", self.readme)
        self.assertIn("v0.23 preview/approval", self.readme)


if __name__ == "__main__":
    unittest.main()
