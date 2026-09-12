import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class InformationArchitectureTests(unittest.TestCase):
    def setUp(self):
        self.index = (ROOT / "app/templates/index.html").read_text()
        self.css = (ROOT / "app/static/app.css").read_text() + "\n" + (ROOT / "app/static/layout.css").read_text()
        self.main = (ROOT / "app/main.py").read_text()

    def test_version(self):
        self.assertIn('version="0.54.5.2.1"', self.main)

    def test_durable_audit_is_main_tab_not_device_subsection(self):
        self.assertIn('data-tab="audit" href="/?view=audit&amp;section=recent#audit/recent">Audit</a>', self.index)
        self.assertIn('data-panel="audit"', self.index)
        device_start = self.index.index('data-panel="devices"')
        policy_start = self.index.index('data-panel="policies"')
        self.assertNotIn('Durable audit', self.index[device_start:policy_start])

    def test_discovery_owns_add_restricted_device(self):
        device_start = self.index.index('data-panel="devices"')
        policy_start = self.index.index('data-panel="policies"')
        devices = self.index[device_start:policy_start]
        discovery_pos = devices.index('Device discovery')
        add_pos = devices.index('Add managed device')
        restricted_pos = devices.index('Managed devices')
        self.assertLess(discovery_pos, add_pos)
        self.assertLess(add_pos, restricted_pos)
        self.assertIn('discovery-add-device', devices)
        self.assertIn('position:sticky', self.css)
        self.assertIn('max-height:min(64vh,560px)', self.css)

    def test_bulk_subtab_contains_only_bulk_and_copy_cards(self):
        self.assertIn("{ key: 'bulk', label: 'Bulk actions', match: ['Bulk actions', 'Copy Device Policy'] }", self.index)

    def test_policy_assignments_have_own_subtab(self):
        self.assertIn("{ key: 'assignments', label: 'Device assignment', match: [] }", self.index)
        self.assertIn('data-ux-groups="profiles assignments"', self.index)
        self.assertIn('data-ux-group="assignments"', self.index)
        self.assertIn('data-ux-group="profiles"', self.index)

    def test_activity_has_distinct_overview_devices_services_dns_tabs(self):
        for key, label in (
            ('overview', 'Overview'), ('devices', 'Devices'),
            ('services', 'Services'), ('dns', 'DNS')
        ):
            self.assertIn(f"{{ key: '{key}', label: '{label}'", self.index)
        self.assertIn("match: ['Policy service activity']", self.index)

    def test_ultra_compact_density_rules_present(self):
        self.assertIn('Ultra-compact density pass for desktop, tablet and mobile.', self.css)
        self.assertIn('.managed-device-card{border-radius:8px;padding:6px}', self.css)
        self.assertIn('.card{padding:9px}', self.css)
        self.assertIn('.section-subtab{min-height:27px', self.css)


if __name__ == "__main__":
    unittest.main()
