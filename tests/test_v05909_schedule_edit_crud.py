import tempfile
import unittest
from pathlib import Path

from app.policy_store import PolicyStore


ROOT = Path(__file__).resolve().parents[1]


class SchedulePlanUpdateStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PolicyStore(str(Path(self.tmp.name) / "policy.db"))
        self.plan_id = self.store.create_schedule_plan(
            "School morning",
            "all",
            "",
            "mode",
            "normal",
            "07:00",
            ["mon", "tue", "wed", "thu", "fri"],
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_update_preserves_identity_and_paused_state(self):
        self.store.set_schedule_plan_enabled(self.plan_id, False)
        revision_before = self.store.current_config_revision()["revision"]

        updated = self.store.update_schedule_plan(
            self.plan_id,
            "School morning revised",
            "all",
            "",
            "mode",
            "slow",
            "07:30",
            ["mon", "wed", "fri"],
        )

        self.assertEqual(updated["id"], self.plan_id)
        self.assertFalse(updated["enabled"])
        self.assertEqual(updated["label"], "School morning revised")
        self.assertEqual(updated["action_value"], "slow")
        self.assertEqual(updated["clock_time"], "07:30")
        self.assertEqual(updated["days"], ["mon", "wed", "fri"])
        self.assertGreater(self.store.current_config_revision()["revision"], revision_before)

    def test_update_reuses_create_validation_and_is_atomic_on_failure(self):
        before = self.store.get_schedule_plan(self.plan_id)
        with self.assertRaisesRegex(ValueError, "Time must be HH:MM"):
            self.store.update_schedule_plan(
                self.plan_id,
                "Broken edit",
                "all",
                "",
                "mode",
                "blocked",
                "25:99",
                ["sat"],
            )
        self.assertEqual(self.store.get_schedule_plan(self.plan_id), before)

    def test_update_can_change_action_dimension_using_existing_service_contract(self):
        updated = self.store.update_schedule_plan(
            self.plan_id,
            "YouTube bedtime",
            "all",
            "",
            "service",
            "youtube:block",
            "21:15",
            ["sun", "mon", "tue", "wed", "thu"],
        )
        self.assertEqual(updated["id"], self.plan_id)
        self.assertEqual(updated["action_type"], "service")
        self.assertEqual(updated["action_value"], "youtube:block")
        self.assertEqual(updated["action_service"], "youtube")
        self.assertEqual(updated["action_state"], "block")

    def test_missing_schedule_update_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "Schedule plan not found"):
            self.store.update_schedule_plan(
                999999,
                "Missing",
                "all",
                "",
                "mode",
                "normal",
                "08:00",
                ["mon"],
            )


class SchedulePlannerCrudContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = (ROOT / "app/main.py").read_text()
        cls.template = (ROOT / "app/templates/index.html").read_text()
        cls.css = (ROOT / "app/static/app.css").read_text()
        cls.help = (ROOT / "app/help_content.py").read_text()
        cls.readme = (ROOT / "README.md").read_text()
        cls.changelog = (ROOT / "CHANGELOG.md").read_text()

    def test_planner_exposes_prepopulated_in_place_edit_form(self):
        for token in (
            'action="/local/schedule-plans/update"',
            'name="plan_id" value="{{p.id}}"',
            'value="{{p.label}}"',
            'value="{{p.clock_time}}"',
            'Save schedule changes',
            'data-schedule-form',
            'data-schedule-target-type',
            'data-schedule-action-type',
        ):
            self.assertIn(token, self.template)
        self.assertIn("schedule-plan-edit", self.css)
        self.assertIn("schedule-plan-row", self.css)

    def test_all_targeted_schedule_mutations_wake_normal_reconciler_path(self):
        start = self.main.index('@app.post("/local/schedule-plans/add")')
        end = self.main.index('@app.post("/local/policy-groups/add")', start)
        block = self.main[start:end]
        self.assertIn('@app.post("/local/schedule-plans/update")', block)
        self.assertIn('"POLICY_SCHEDULE_UPDATED"', block)
        self.assertGreaterEqual(block.count("auto_reconciler.wake()"), 4)
        self.assertNotIn("router.set_", block)
        self.assertNotIn("router.add_", block)
        self.assertNotIn("router.remove_", block)

    def test_release_and_help_describe_crud_closure(self):
        self.assertIn("Current maintenance release: **v0.59.0.9**", self.readme)
        self.assertIn("## v0.59.0.9 — Schedule Edit & Planner CRUD Closure", self.changelog)
        self.assertIn("create, edit, pause, enable and delete", self.help)
        self.assertIn("Application/PWA runtime remains `0.59.0`", self.changelog)


if __name__ == "__main__":
    unittest.main()
