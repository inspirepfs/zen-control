import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class AnalyticsClearFiltersUiContractTests(unittest.TestCase):
    def test_clear_filters_control_resets_drilldown_state_and_announces_restoration(self):
        page = (ROOT / "app/templates/activity_analytics.html").read_text()

        self.assertIn('data-clear-filters', page)
        self.assertIn('type="button"', page)
        self.assertIn('aria-label="Clear category, service, and client filters"', page)
        self.assertIn("clearFilters.addEventListener('click'", page)
        self.assertIn("{category: '', service: '', client_ip: ''}", page)
        self.assertIn("window.history.replaceState", page)
        self.assertIn("Filters cleared; showing all categories, services, and devices.", page)
        self.assertIn('aria-live="polite"', page)


if __name__ == "__main__":
    unittest.main()
