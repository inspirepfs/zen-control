import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class BoundedDrilldownFilterContractTests(unittest.TestCase):
    def test_relative_service_device_links_keep_the_selected_hour_window(self):
        service = (ROOT / "app/templates/activity_service.html").read_text()
        device = (ROOT / "app/templates/activity_device.html").read_text()

        self.assertIn("{% else %}hours={{hours}}&amp;{% endif %}service={{service.key|urlencode}}", service)
        self.assertIn("{% else %}hours={{hours}}&amp;{% endif %}client_ip={{client_ip}}", device)

    def test_evidence_health_filter_uses_the_public_descriptive_vocabulary(self):
        main = (ROOT / "app/main.py").read_text()
        activity = (ROOT / "app/activity.py").read_text()
        matrix = (ROOT / "app/templates/index.html").read_text()

        self.assertIn('"retained": "fresh"', main)
        self.assertIn('"no-retained-evidence": "no-evidence"', main)
        self.assertIn('"evidence_health": "fresh" if last_activity else "no-evidence"', activity)
        self.assertIn("s.evidence_health == service_matrix_filters.evidence_health", matrix)


if __name__ == "__main__":
    unittest.main()
