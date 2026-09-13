import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class NotificationDeliveryNavigationHotfixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = (ROOT / "app" / "main.py").read_text()
        cls.index = (ROOT / "app" / "templates" / "index.html").read_text()
        cls.readme = (ROOT / "README.md").read_text()

    def test_release_identity_is_v05542(self):
        self.assertIn('version="0.56.0"', self.main)
        self.assertIn("Current release: **v0.56.0**", self.readme)

    def test_backend_allows_delivery_subsection(self):
        self.assertIn(
            '"notifications": ("inbox", "preferences", "intelligence", "delivery", "history")',
            self.main,
        )

    def test_generated_notification_subnav_exposes_delivery(self):
        self.assertIn("{ key: 'delivery', label: 'Delivery'", self.index)
        intelligence = self.index.index("{ key: 'intelligence', label: 'Intelligence'")
        delivery = self.index.index("{ key: 'delivery', label: 'Delivery'")
        history = self.index.index("{ key: 'history', label: 'History'", intelligence)
        self.assertLess(intelligence, delivery)
        self.assertLess(delivery, history)

    def test_delivery_markup_and_routes_remain_present(self):
        self.assertIn('data-ux-group="delivery"', self.index)
        self.assertIn("External delivery", self.index)
        self.assertIn('@app.get("/api/notifications/delivery")', self.main)
        self.assertIn('@app.post("/local/notifications/delivery")', self.main)
        self.assertIn('@app.post("/local/notifications/delivery/test/{channel}")', self.main)


if __name__ == "__main__":
    unittest.main()
