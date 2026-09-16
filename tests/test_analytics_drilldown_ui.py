import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class AnalyticsDrilldownUiTests(unittest.TestCase):
    def test_historical_analytics_exposes_persistent_drilldown_states(self):
        page = (ROOT / "app/templates/activity_analytics.html").read_text()

        self.assertIn('id="analytics-drilldown"', page)
        self.assertIn('/api/activity/analytics-summary?', page)
        self.assertIn('/api/activity/analytics-drilldown?', page)
        self.assertIn("window.history.replaceState", page)
        self.assertIn("Loading analytics drill-down", page)
        self.assertIn("Could not load analytics drill-down", page)
        self.assertIn("No traffic-over-time data matches these filters.", page)
        self.assertIn("['Classified', quality.classified_bytes]", page)
        self.assertIn("['Low confidence', quality.low_confidence_bytes]", page)
        self.assertIn("['Unknown', quality.unknown_bytes]", page)


if __name__ == "__main__":
    unittest.main()
