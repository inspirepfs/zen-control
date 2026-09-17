import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class BoundedDrilldownUrlRestorationTests(unittest.TestCase):
    def setUp(self):
        self.analytics = (ROOT / "app/templates/activity_analytics.html").read_text()
        self.service = (ROOT / "app/templates/activity_service.html").read_text()
        self.device = (ROOT / "app/templates/activity_device.html").read_text()

    def test_analytics_device_drill_and_clear_action_keep_exact_window(self):
        self.assertIn("period=custom&amp;start={{window.start|urlencode}}&amp;end={{window.end|urlencode}}&amp;client_ip={{item.client_ip}}", self.analytics)
        self.assertIn('href="/activity/analytics?period=custom&amp;start={{window.start|urlencode}}&amp;end={{window.end|urlencode}}">Clear filters</a>', self.analytics)

    def test_service_and_device_clear_actions_keep_the_nondefault_hour_window(self):
        self.assertIn("{% else %}hours={{hours}}{% endif %}", self.service)
        self.assertIn("{% else %}hours={{hours}}{% endif %}", self.device)


if __name__ == "__main__":
    unittest.main()
