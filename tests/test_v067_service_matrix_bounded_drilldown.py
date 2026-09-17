import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ServiceMatrixBoundedDrilldownTests(unittest.TestCase):
    def test_concrete_service_drilldown_explicitly_preserves_matrix_window_and_filters(self):
        template = (ROOT / "app/templates/index.html").read_text()

        self.assertIn('href="/activity/service/{{s.key}}?hours=24', template)
        self.assertIn('{% if service_matrix_filters.capability %}&amp;capability=', template)
        self.assertIn('{% if service_matrix_filters.routeros_state %}&amp;routeros_state=', template)
        self.assertIn('{% if service_matrix_filters.managed %}&amp;managed=', template)
        self.assertIn('{% if service_matrix_filters.evidence_health %}&amp;evidence_health=', template)
        self.assertIn("s.kind != 'group'", template)


if __name__ == "__main__":
    unittest.main()
