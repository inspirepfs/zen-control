import ast
import contextlib
import unittest
from pathlib import Path

from scripts import release_patch


ROOT = Path(__file__).resolve().parents[1]


def load_template_wrapper(fake_original):
    source = (ROOT / "app" / "main.py").read_text()
    tree = ast.parse(source)
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "_performance_template_response"
    )
    module = ast.Module(body=[function], type_ignores=[])
    ast.fix_missing_locations(module)

    @contextlib.contextmanager
    def perf_span(_name):
        yield

    namespace = {
        "_original_template_response": fake_original,
        "perf_span": perf_span,
    }
    exec(compile(module, "app/main.py", "exec"), namespace)
    return namespace["_performance_template_response"]


class TemplateResponseCompatibilityHotfixTests(unittest.TestCase):
    def test_legacy_name_context_call_is_translated_to_request_first(self):
        calls = []

        def original(*args, **kwargs):
            calls.append((args, kwargs))
            return "rendered"

        wrapper = load_template_wrapper(original)
        request = object()
        context = {"request": request, "value": 42}

        result = wrapper("index.html", context, status_code=201)

        self.assertEqual(result, "rendered")
        self.assertEqual(
            calls,
            [((request, "index.html", context), {"status_code": 201})],
        )

    def test_request_first_call_passes_through_unchanged(self):
        calls = []

        def original(*args, **kwargs):
            calls.append((args, kwargs))
            return "rendered"

        wrapper = load_template_wrapper(original)
        request = object()
        context = {"request": request}

        wrapper(request, "index.html", context, status_code=202)

        self.assertEqual(
            calls,
            [((request, "index.html", context), {"status_code": 202})],
        )

    def test_legacy_call_without_request_fails_closed(self):
        wrapper = load_template_wrapper(lambda *args, **kwargs: None)

        with self.assertRaisesRegex(TypeError, "template context must contain request"):
            wrapper("index.html", {"value": 42})

    def test_template_hotfix_rebuilds_application_without_version_bump(self):
        self.assertEqual(
            release_patch.affected_services(["app/main.py"]),
            ["mikrotik-control"],
        )
        main = (ROOT / "app" / "main.py").read_text()
        self.assertIn('version="0.59.0"', main)
        self.assertIn('PWA_RELEASE = "0.59.0"', (ROOT / "app" / "pwa.py").read_text())


if __name__ == "__main__":
    unittest.main()
