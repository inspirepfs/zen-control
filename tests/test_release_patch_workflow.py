import argparse
import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("zen_release_patch", ROOT / "scripts/release_patch.py")
release_patch = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(release_patch)


class ReleasePatchWorkflowTests(unittest.TestCase):
    def test_patch_output_rejects_non_exact_application_evidence(self):
        self.assertTrue(release_patch.patch_output_is_exact("checking file app/main.py\n"))
        for evidence in (
            "Hunk #1 succeeded at 10 (offset 2 lines).",
            "Hunk #1 succeeded with fuzz 1.",
            "Reversed (or previously applied) patch detected!",
            "1 out of 1 hunk FAILED",
        ):
            with self.subTest(evidence=evidence):
                self.assertFalse(release_patch.patch_output_is_exact(evidence))

    def test_patch_resolution_checks_parent_directory(self):
        with tempfile.TemporaryDirectory() as td:
            parent = Path(td)
            repo = parent / "repo"
            repo.mkdir()
            patch = parent / "example.patch"
            patch.write_text("example")
            old_root = release_patch.ROOT
            try:
                release_patch.ROOT = repo
                self.assertEqual(release_patch.resolve_patch("example.patch"), patch.resolve())
            finally:
                release_patch.ROOT = old_root

    def test_resume_and_patch_are_mutually_exclusive(self):
        args = self._args(resume=True, patch="../x.patch")
        with self.assertRaises(release_patch.WorkflowError):
            release_patch.validate_args(args)

    def test_tag_requires_watched_ci_unless_explicitly_overridden(self):
        args = self._args(tag="v1.0.0", skip_watch=True)
        with self.assertRaises(release_patch.WorkflowError):
            release_patch.validate_args(args)
        args.allow_tag_without_ci = True
        release_patch.validate_args(args)

    def test_tag_cannot_be_combined_with_skip_push(self):
        args = self._args(tag="v1.0.0", skip_push=True)
        with self.assertRaises(release_patch.WorkflowError):
            release_patch.validate_args(args)

    def test_default_rebuild_target_is_application_service(self):
        parser = release_patch.build_parser()
        args = parser.parse_args(["--patch", "release.patch"])
        self.assertEqual(args.rebuild_service, [])
        self.assertFalse(args.rebuild_all)
        services = args.rebuild_service or ["mikrotik-control"]
        self.assertEqual(services, ["mikrotik-control"])

    def test_cli_exposes_resume_health_ci_tag_and_safety_bits(self):
        help_text = release_patch.build_parser().format_help()
        for flag in (
            "--resume", "--expect-version", "--rebuild-service", "--rebuild-all",
            "--stage", "--workflow", "--tag", "--skip-watch", "--dry-run",
        ):
            with self.subTest(flag=flag):
                self.assertIn(flag, help_text)

    @staticmethod
    def _args(**overrides):
        values = dict(
            resume=False,
            patch="../release.patch",
            message=None,
            message_file=None,
            rebuild_all=False,
            rebuild_service=[],
            tag=None,
            skip_push=False,
            skip_watch=False,
            allow_tag_without_ci=False,
            health_timeout=60,
            run_discovery_timeout=120,
        )
        values.update(overrides)
        return argparse.Namespace(**values)


if __name__ == "__main__":
    unittest.main()
