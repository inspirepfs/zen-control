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

    def test_default_rebuild_plan_is_auto_detected(self):
        parser = release_patch.build_parser()
        args = parser.parse_args(["--patch", "release.patch"])
        self.assertEqual(args.rebuild_service, [])
        self.assertFalse(args.rebuild_all)
        self.assertFalse(args.no_auto_services)

    def test_cli_exposes_resume_health_ci_tag_and_safety_bits(self):
        help_text = release_patch.build_parser().format_help()
        for flag in (
            "--resume", "--expect-version", "--rebuild-service", "--rebuild-all",
            "--no-auto-services", "--runtime-health-url", "--topology-timeout",
            "--skip-runtime-health", "--skip-topology-health",
            "--stage", "--workflow", "--tag", "--skip-watch", "--dry-run",
        ):
            with self.subTest(flag=flag):
                self.assertIn(flag, help_text)

    def test_worktree_delta_includes_untracked_files(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            subprocess = __import__("subprocess")
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            (repo / "tracked.txt").write_text("base\n")
            subprocess.run(["git", "add", "tracked.txt"], cwd=repo, check=True)
            subprocess.run(
                ["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                 "commit", "-qm", "base"],
                cwd=repo,
                check=True,
            )
            (repo / "app").mkdir()
            (repo / "app" / "new_worker.py").write_text("VALUE = 1\n")
            old_root = release_patch.ROOT
            try:
                release_patch.ROOT = repo
                paths = release_patch.changed_paths_since("HEAD", include_worktree=True)
            finally:
                release_patch.ROOT = old_root
            self.assertIn("app/new_worker.py", paths)

    def test_path_rules_detect_only_affected_runtime_services(self):
        self.assertEqual(
            release_patch.affected_services(["app/main.py", "tests/test_x.py"]),
            ["mikrotik-control"],
        )
        self.assertEqual(
            release_patch.affected_services(["telemetry/ingest/ingest.py"]),
            ["traffic-ingest"],
        )
        self.assertEqual(
            release_patch.affected_services(["telemetry/goflow2/mapping.yaml"]),
            ["goflow2"],
        )
        self.assertEqual(
            release_patch.affected_services(["deploy/caddy/Caddyfile"]),
            ["zen-local-https"],
        )

    def test_postgres_init_change_requires_explicit_migration(self):
        with self.assertRaises(release_patch.WorkflowError):
            release_patch.affected_services(["telemetry/postgres/init.sql"])

    def test_compose_block_diff_targets_changed_service_only(self):
        before = """services:
  one:
    image: one:1
  two:
    image: two:1
volumes:
  data:
"""
        after = """services:
  one:
    image: one:2
  two:
    image: two:1
volumes:
  data:
"""
        self.assertEqual(release_patch.changed_compose_services(before, after), {"one"})

    def test_compose_top_level_change_conservatively_targets_all_services(self):
        before = """services:
  one:
    image: one:1
  two:
    image: two:1
volumes:
  data:
"""
        after = """services:
  one:
    image: one:1
  two:
    image: two:1
volumes:
  data:
    external: true
"""
        self.assertEqual(release_patch.changed_compose_services(before, after), {"one", "two"})

    def test_compose_ps_parser_accepts_array_and_json_lines(self):
        rows = release_patch.parse_compose_ps(
            '[{"Service":"app","State":"running"},{"Service":"db","State":"running"}]'
        )
        self.assertEqual(set(rows), {"app", "db"})
        rows = release_patch.parse_compose_ps(
            '{"Service":"app","State":"running"}\n{"Service":"db","State":"running"}\n'
        )
        self.assertEqual(set(rows), {"app", "db"})

    def test_topology_preserves_running_and_successful_one_shot_services(self):
        before = {
            "mikrotik-control": {"Service": "mikrotik-control", "State": "running"},
            "cloudflared": {"Service": "cloudflared", "State": "running"},
            "flow-pipe-init": {"Service": "flow-pipe-init", "State": "exited", "ExitCode": 0},
            "stopped-opt": {"Service": "stopped-opt", "State": "exited", "ExitCode": 1},
        }
        required = release_patch.topology_requirements(
            before,
            ["mikrotik-control"],
            rebuild_all=False,
            configured_services=["mikrotik-control", "cloudflared", "flow-pipe-init", "stopped-opt"],
        )
        self.assertEqual(
            required,
            {
                "mikrotik-control": "running",
                "cloudflared": "running",
                "flow-pipe-init": "completed",
            },
        )

    def test_topology_fails_for_lost_running_service_or_unhealthy_target(self):
        required = {"mikrotik-control": "running", "cloudflared": "running"}
        after = {
            "mikrotik-control": {
                "Service": "mikrotik-control", "State": "running", "Health": "unhealthy"
            }
        }
        failures = release_patch.topology_failures(after, required)
        self.assertIn("mikrotik-control=health:unhealthy", failures)
        self.assertIn("cloudflared=missing", failures)

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
            topology_timeout=90,
            run_discovery_timeout=120,
        )
        values.update(overrides)
        return argparse.Namespace(**values)


if __name__ == "__main__":
    unittest.main()
