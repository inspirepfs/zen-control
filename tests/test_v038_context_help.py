import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_help_module():
    spec = importlib.util.spec_from_file_location("zen_help_content", ROOT / "app" / "help_content.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ContextHelpContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.help = load_help_module()
        cls.main = (ROOT / "app" / "main.py").read_text()
        cls.index = (ROOT / "app" / "templates" / "index.html").read_text()
        cls.help_template = (ROOT / "app" / "templates" / "help.html").read_text()
        cls.help_partial = (ROOT / "app" / "templates" / "_context_help.jinja").read_text()
        cls.help_css = (ROOT / "app" / "static" / "help.css").read_text()
        cls.worker = (ROOT / "app" / "static" / "service-worker.js").read_text()
        cls.templates = {
            path.name: path.read_text() for path in (ROOT / "app" / "templates").glob("*.html")
        }

    def test_release_is_v038(self):
        self.assertIn('version="0.54.5.2"', self.main)
        self.assertIn('/static/help.css?v=0.54.5.2', (ROOT / "app" / "templates" / "_pwa_head.jinja").read_text())

    def test_main_views_keep_subsection_help_mapping_behind_top_level_help(self):
        self.assertIn('data-tab="help"', self.index)
        self.assertNotIn('{% include "_context_help.jinja" %}', self.index)
        expected = {
            ("dashboard", "overview"): "dashboard_overview",
            ("devices", "managed"): "devices_managed",
            ("policies", "services"): "policies_services",
            ("schedules", "planner"): "schedules_planner",
            ("activity", "history"): "activity_history",
            ("settings", "security"): "settings_security",
        }
        for context, key in expected.items():
            with self.subTest(context=context):
                self.assertEqual(key, self.help.help_for_context(*context)["key"])

    def test_all_complex_standalone_surfaces_have_context_help(self):
        exempt = {"index.html", "login.html", "recovery_codes.html", "help.html"}
        for name, text in self.templates.items():
            if name in exempt:
                continue
            with self.subTest(template=name):
                self.assertIn('{% include "_context_help.jinja" %}', text)
                self.assertIn("zen_help('", text)

    def test_help_api_contract_is_static_private_and_read_only(self):
        payload = self.help.help_api_payload("activity_overview")
        self.assertEqual("zen_help_catalog_v1", payload["schema"])
        self.assertFalse(payload["privacy"]["contains_household_data"])
        self.assertFalse(payload["privacy"]["contains_credentials"])
        self.assertTrue(payload["privacy"]["read_only"])
        route_block = self.main[self.main.index('@app.get("/api/help")'):self.main.index('@app.get("/health/live")')]
        self.assertNotIn("router.", route_block)
        self.assertNotIn("policy_store.", route_block)
        self.assertNotRegex(route_block, r'@app\.post\(')

    def test_activity_help_preserves_browser_history_evidence_boundary(self):
        topic = self.help.get_help_topic("activity_overview")
        joined = " ".join(topic["watch"] + [topic["evidence"]]).lower()
        self.assertIn("not browser history", joined)
        self.assertIn("proof of user intent", joined)
        self.assertIn("unknown", joined)

    def test_policy_history_help_does_not_claim_historical_enforcement(self):
        topic = self.help.get_help_topic("policy_history")
        joined = " ".join(topic["watch"] + [topic["evidence"]]).lower()
        self.assertIn("not proof", joined)
        self.assertIn("routeros enforcement", joined)
        self.assertIn("unknown", joined)

    def test_service_help_preserves_reporting_only_boundary(self):
        topic = self.help.get_help_topic("policies_services")
        joined = " ".join(topic["watch"]).lower()
        self.assertIn("reporting-only", joined)
        self.assertIn("cannot be claimed as enforced", joined)
        self.assertIn("never silently creates firewall authority", joined)

    def test_aggregate_group_help_denies_aggregate_routeros_authority(self):
        topic = self.help.get_help_topic("aggregate_groups")
        joined = " ".join(topic["watch"]).lower()
        self.assertIn("mc_block_<group>", joined)
        self.assertIn("routeros enforcement stays concrete-service based", joined)
        self.assertIn("nested groups are rejected", joined)

    def test_glossary_explains_desired_live_drift_unknown_and_reporting_only(self):
        topic = self.help.get_help_topic("glossary")
        joined = " ".join(topic["does"] + [topic["evidence"]])
        for token in ("Desired:", "Live:", "DRIFT:", "UNKNOWN/UNAVAILABLE:", "REPORTING ONLY:", "Aggregate policy group:"):
            self.assertIn(token, joined)

    def test_context_strip_is_compact_and_links_to_exact_topic_and_glossary(self):
        self.assertIn("CONTEXT HELP", self.help_partial)
        self.assertIn('/help?topic={{ page_help.key }}&amp;return_to={{ help_return|urlencode }}', self.help_partial)
        self.assertIn('/help?topic=glossary&amp;return_to={{ help_return|urlencode }}', self.help_partial)
        self.assertIn('request.url.path', self.help_partial)
        for token in (".context-help-strip", "grid-template-columns:minmax(0,1fr) auto", "@media(max-width:600px)"):
            self.assertIn(token, self.help_css)

    def test_help_center_has_search_index_related_links_and_owner_return(self):
        for token in (
            'id="helpSearch"',
            'id="helpTopicList"',
            "Filter by feature or term.",
            "Related",
            "Back to {{back_label}}",
            '/api/help?topic={{selected.key}}',
        ):
            self.assertIn(token, self.help_template)
        self.assertIn("data-search=", self.help_template)

    def test_help_topics_have_unique_keys_and_core_coverage(self):
        topics = self.help.help_catalog()
        keys = [topic["key"] for topic in topics]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertGreaterEqual(len(keys), 35)
        for key in (
            "getting_started", "devices_managed", "policies_profiles", "aggregate_groups",
            "activity_overview", "policy_explain", "policy_simulation", "policy_quality",
            "policy_history", "diagnostics", "performance", "pwa", "glossary",
        ):
            self.assertIn(key, keys)

    def test_help_unknown_topic_falls_back_without_error(self):
        self.assertEqual("getting_started", self.help.get_help_topic("definitely-not-a-topic")["key"])

    def test_complex_controls_have_targeted_inline_help_links(self):
        for token in (
            '/help?topic=policies_services',
            '/help?topic=aggregate_groups',
            '/help?topic=pwa',
            'How service authority works',
            'Group help',
            'PWA / tablet help',
        ):
            self.assertIn(token, self.index)

    def test_context_help_preserves_exact_local_return_path_and_rejects_open_redirects(self):
        self.assertIn("def _safe_help_return", self.main)
        self.assertIn("return_to: str = """, self.main)
        # Exercise the helper without importing the full application/dependencies.
        import ast
        tree = ast.parse(self.main)
        node = next(item for item in tree.body if isinstance(item, ast.FunctionDef) and item.name == "_safe_help_return")
        module = ast.Module(body=[node], type_ignores=[])
        namespace = {}
        exec(compile(module, "<safe-help-return>", "exec"), namespace)
        helper = namespace["_safe_help_return"]
        self.assertEqual("/?view=policies&section=services", helper("/?view=policies&section=services"))
        self.assertEqual("/devices/192.168.2.10?foo=bar", helper("/devices/192.168.2.10?foo=bar"))
        for unsafe in ("https://evil.example/", "//evil.example/", "\\evil.example", "evil.example/path"):
            self.assertEqual("", helper(unsafe))

    def test_pwa_shell_only_caches_help_presentation_asset_not_help_responses(self):
        self.assertIn("`/static/help.css?v=${RELEASE}`", self.worker)
        self.assertIn("safePresentationAsset", self.worker)
        self.assertNotIn("/api/help", self.worker)
        self.assertNotIn("'/help'", self.worker)
        self.assertIn("request.mode === 'navigate'", self.worker)
        self.assertIn("fetch(request, {cache: 'no-store'})", self.worker)


if __name__ == "__main__":
    unittest.main()
