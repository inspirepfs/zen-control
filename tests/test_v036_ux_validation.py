import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class V036UXValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = (ROOT / "app/main.py").read_text()
        cls.index = (ROOT / "app/templates/index.html").read_text()
        cls.layout = (ROOT / "app/static/layout.css").read_text()
        cls.app_css = (ROOT / "app/static/app.css").read_text()
        cls.templates = {
            path.name: path.read_text() for path in (ROOT / "app/templates").glob("*.html")
        }

    def test_release_is_v036_and_all_css_assets_are_cache_busted(self):
        self.assertIn('version="0.55.1"', self.main)
        joined = "\n".join(self.templates.values())
        self.assertNotIn("?v=0.35.0", joined)
        self.assertIn("?v=0.55.1", joined)

    def test_parent_unlock_and_lock_preserve_current_context(self):
        self.assertGreaterEqual(
            self.index.count('name="next_tab" value="{{ active_view }}/{{ active_section }}"'),
            2,
        )
        self.assertNotIn('name="next_tab" value="dashboard"', self.index)

    def test_main_navigation_tracks_accessibility_and_keeps_active_tabs_visible(self):
        self.assertIn("btn.setAttribute('aria-current', active ? 'page' : 'false')", self.index)
        self.assertIn("activeTab.scrollIntoView", self.index)
        self.assertIn("activeSubtab.scrollIntoView", self.index)
        self.assertIn("#audit/recent", self.index)

    def test_user_facing_device_terminology_is_consistent(self):
        self.assertIn("Add managed device", self.index)
        self.assertIn("<h2>Managed devices</h2>", self.index)
        self.assertIn("No managed devices.", self.index)
        self.assertNotIn("Add restricted device", self.index)
        self.assertNotIn("<h2>Restricted devices</h2>", self.index)
        self.assertIn("RouterOS restricted entries", self.index)

    def test_standalone_pages_have_explicit_owner_return_links(self):
        expected = {
            "activity_analytics.html": "Back to Activity",
            "activity_device.html": "Back to Activity",
            "activity_service.html": "Back to Activity",
            "activity_summary.html": "Back to Activity",
            "classification.html": "Back to Activity",
            "device_360.html": "Back to Devices",
            "diagnostics.html": "Back to Operations",
            "import_preview.html": "Back to Operations",
            "performance.html": "Back to Operations",
            "policy_explain.html": "Back to Device 360",
            "policy_history.html": "Back to Activity",
            "policy_quality.html": "Back to Policy tools",
            "policy_summary.html": "Back to Dashboard",
            "simulation.html": "Back to Policy tools",
        }
        for name, label in expected.items():
            with self.subTest(template=name):
                text = self.templates[name]
                self.assertIn(label, text)
                self.assertIn("back-link", text)

    def test_all_non_auth_standalone_pages_share_responsive_chrome(self):
        exempt = {"index.html", "login.html", "recovery_codes.html"}
        for name, text in self.templates.items():
            if name in exempt:
                continue
            with self.subTest(template=name):
                self.assertIn('class="standalone-page"', text)
                self.assertIn('/static/layout.css?v=0.55.1', text)

    def test_dynamic_browser_titles_include_product_name(self):
        for name in (
            "activity_device.html",
            "activity_service.html",
            "device_360.html",
            "policy_explain.html",
            "import_preview.html",
        ):
            with self.subTest(template=name):
                title = self.templates[name].split("<title>", 1)[1].split("</title>", 1)[0]
                self.assertIn("ZEN Control", title)

    def test_import_preview_is_consistent_and_cancel_first(self):
        text = self.templates["import_preview.html"]
        self.assertIn("Configuration Import Preview · ZEN Control", text)
        self.assertIn("Nothing is changed until you explicitly apply this preview.", text)
        self.assertLess(text.index("Cancel import"), text.index("Apply import"))
        self.assertIn("standalone-form-actions", text)

    def test_policy_summary_has_header_return_path_and_empty_state(self):
        text = self.templates["policy_summary.html"]
        self.assertIn("Back to Dashboard", text)
        self.assertIn("across managed devices", text)
        self.assertIn("No managed devices are available for policy summary.", text)
        self.assertEqual(text.count("Back to Dashboard"), 1)

    def test_button_links_have_touch_safe_alignment_and_keyboard_focus(self):
        self.assertIn("display:inline-flex", self.app_css)
        self.assertIn("touch-action:manipulation", self.app_css)
        self.assertIn("button:focus-visible", self.layout)
        self.assertIn(".button-link.back-link::before", self.layout)
        self.assertIn("min-height:30px", self.layout)

    def test_tablet_navigation_uses_scroll_snap(self):
        self.assertIn(".app-tabs,.section-subnav{scroll-snap-type:x proximity", self.layout)
        self.assertIn(".app-tab,.section-subtab{scroll-snap-align:center}", self.layout)

    def test_reduced_motion_preference_is_respected(self):
        self.assertIn("@media(prefers-reduced-motion:reduce)", self.layout)
        self.assertIn(".ux-section{animation:none}", self.layout)

    def test_static_validator_module_reports_clean_tree(self):
        script = ROOT / "scripts/ux_validate.py"
        spec = importlib.util.spec_from_file_location("ux_validate", script)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        self.assertEqual([], module.validate())

    def test_static_validator_cli_passes(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/ux_validate.py")],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("ZEN UX validation: PASS", result.stdout)

    def test_no_stale_user_facing_brand_or_legacy_root_hash_remains(self):
        joined = "\n".join(self.templates.values())
        self.assertNotIn("MIKROTIK CONTROL ·", joined)
        self.assertNotIn("No MikroTik Control", joined)
        self.assertNotIn('section=recent#audit"', self.index)


if __name__ == "__main__":
    unittest.main()
