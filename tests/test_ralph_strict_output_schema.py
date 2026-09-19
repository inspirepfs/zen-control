import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "ralph.py"
spec = importlib.util.spec_from_file_location(
    "ralph_strict_output_schema",
    MODULE_PATH,
)
ralph = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(ralph)


class StrictOutputSchemaTests(unittest.TestCase):
    def assert_strict_schema(self, schema: object, path: str = "$") -> None:
        if isinstance(schema, dict):
            if schema.get("type") == "object":
                properties = schema.get("properties", {})
                self.assertIsInstance(properties, dict, path)
                self.assertEqual(
                    set(properties),
                    set(schema.get("required", [])),
                    (
                        f"{path}: every object property must be required "
                        "for strict structured output"
                    ),
                )
                self.assertIs(
                    schema.get("additionalProperties"),
                    False,
                    (
                        f"{path}: strict structured-output objects must "
                        "reject additional properties"
                    ),
                )

            for key, value in schema.items():
                self.assert_strict_schema(value, f"{path}.{key}")

        elif isinstance(schema, list):
            for index, value in enumerate(schema):
                self.assert_strict_schema(value, f"{path}[{index}]")

    def test_codex_output_schemas_are_strict(self):
        self.assert_strict_schema(ralph.PLAN_SCHEMA, "PLAN_SCHEMA")
        self.assert_strict_schema(ralph.RESULT_SCHEMA, "RESULT_SCHEMA")

    def test_planning_bounds_are_controller_owned(self):
        self.assertNotIn("planning", ralph.PLAN_SCHEMA["properties"])

    def test_plan_validation_still_binds_planning_bounds(self):
        plan = {
            "goal": "Bounded planning",
            "planning": {"min_steps": 2, "max_steps": 3},
            "steps": [
                {
                    "id": index,
                    "title": f"Step {index}",
                    "objective": f"Objective {index}",
                    "acceptance": [f"Acceptance {index}"],
                    "test_change_policy": "none",
                }
                for index in range(1, 3)
            ],
        }
        ralph.validate_plan(plan)
        self.assertEqual((2, 3), ralph.plan_step_bounds(plan))


if __name__ == "__main__":
    unittest.main()
