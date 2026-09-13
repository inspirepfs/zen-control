import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class CompactUxTests(unittest.TestCase):
    def setUp(self):
        self.index = (ROOT / "app/templates/index.html").read_text()
        self.css = (ROOT / "app/static/app.css").read_text() + "\n" + (ROOT / "app/static/layout.css").read_text()
        self.main = (ROOT / "app/main.py").read_text()

    def test_version_bumped(self):
        self.assertIn('version="0.55.3.1"', self.main)

    def test_all_main_tabs_have_submenu_configuration(self):
        for name in ("dashboard", "devices", "policies", "schedules", "activity", "incidents", "settings"):
            self.assertIn(f"{name}: [", self.index)

    def test_hash_supports_tab_and_subsection(self):
        self.assertIn("raw.split('/')", self.index)
        self.assertIn("zen-subtab:", self.index)
        self.assertIn("section-subtab", self.index)

    def test_mobile_collapses_long_open_details(self):
        self.assertIn("details.device-policy-details[open]", self.index)
        self.assertIn("max-width: 900px", self.index)

    def test_compact_css_keeps_horizontal_scrollable_subnav(self):
        self.assertIn(".section-subnav", self.css)
        self.assertIn("overflow-x:auto", self.css)
        self.assertIn(".ux-section[hidden]", self.css)


if __name__ == "__main__":
    unittest.main()
