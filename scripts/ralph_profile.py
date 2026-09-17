"""ZEN Control's internal RALPH-Lite project contract.

This module deliberately contains project choices only.  Controller lifecycle,
approval, repair, resource, and state-machine behavior remains in the RALPH
controller modules.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ZenProjectProfile:
    """Stable, internal defaults for the ZEN Control RALPH installation."""

    identity: str = "ZEN Control"
    completion_commit_prefix: str = "chore(zen):"
    runtime_dir_name: str = ".ralph"
    controller_cli_relative_path: str = "scripts/ralph.py"
    git_executable: str = "git"
    source_roots: tuple[str, ...] = ("app", "scripts")
    test_root: str = "tests"
    artifacts: tuple[tuple[str, str], ...] = (
        ("state", "state.json"), ("plan", "plan.md"), ("ideas", "ideas.md"),
        ("journal", "journal.md"), ("policy", "policy.md"), ("live", "live.log"),
        ("context", "context.json"), ("events", "events.jsonl"),
        ("recovery", "recovery"), ("reports", "reports"),
        ("usage_ledger", "usage-ledger.jsonl"), ("usage_stats_reset", "usage-stats-reset.json"),
        ("web_job", "web-job.json"), ("web_log", "web-run.log"),
    )
    excluded_dirs: frozenset[str] = frozenset({
        ".git", ".ralph", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
        ".venv", "venv", "node_modules", "data", "logs", "diagnostics", "backup", "backups",
    })
    protected_prefixes: tuple[str, ...] = ("secrets/", "certs/")
    protected_exact: frozenset[str] = frozenset({".npmrc", ".pypirc", ".netrc", ".envrc"})
    protected_dir_prefixes: tuple[str, ...] = (".codex/", ".direnv/")
    protected_suffixes: tuple[str, ...] = (".token", ".secret", ".secrets", ".credentials")
    tooling_paths: frozenset[str] = frozenset({
        ".gitignore", ".ralph/policy.md", "scripts/ralph.py", "scripts/ralph_efficiency.py",
        "scripts/ralph_model.py", "scripts/ralph_gate.py", "scripts/ralph_tui.py",
        "scripts/ralph_web.py", "tests/test_ralph_lite.py", "tests/test_ralph_efficiency.py",
        "tests/test_ralph_model.py", "tests/test_ralph_gate.py", "tests/test_ralph_lifecycle.py",
        "tests/test_ralph_retry_hardening.py", "tests/test_ralph_web.py", "tests/test_ralph_self_hosting.py",
        "docs/RALPH-LITE.md",
    })
    optional_final_validators: tuple[tuple[str, str], ...] = (
        ("environment", "scripts/env_validate.py"),
        ("supply-chain", "scripts/supply_chain_validate.py"),
        ("public-audit", "scripts/public_release_audit.py"),
    )
    policy_review_guidance: tuple[tuple[str, tuple[str, ...]], ...] = (
        ("actions", (
            "Compare the requested path/action with the approved step and its test-change policy.",
            "Use steer for bounded human direction when the objective is still correct; use --allow-new-test only for an exact test path absent at plan approval.",
            "Retire/re-plan if the approved objective genuinely needs broader existing-file authority.",
        )),
        ("success", (
            "The requested change is demonstrably inside the approved step or is explicitly bounded by a human steering record.",
            "Existing protected/tooling paths and pre-existing tests remain unchanged unless the approved plan already permits them.",
        )),
        ("forbidden", (
            "Do not use steering to bypass protected paths, RALPH tooling authority, secrets or existing-test protection.",
            "Do not broaden the whole step merely to clear one blocked path.",
        )),
    )
    incident_gate_guidance: tuple[tuple[str, tuple[str, ...]], ...] = (
        ("actions", (
            "Review the currently active ZEN incidents and identify the underlying condition.",
            "Correct the underlying operational condition where appropriate; do not clear evidence merely for release acceptance.",
            "Run a fresh Incident Monitor scan after the underlying condition has cleared.",
            "Capture fresh operational diagnostics and verify the Incident Monitor is healthy with zero active incidents.",
        )),
        ("success", (
            "Incident Monitor diagnostic state is healthy.",
            "Active durable incident count is 0.",
            "Fresh evidence is produced by the normal monitor/diagnostic path.",
        )),
        ("forbidden", (
            "Do not disable Incident Monitor to obtain PASS.",
            "Do not edit/delete the incident database to obtain PASS.",
            "Do not manufacture or manually rewrite release evidence.",
        )),
    )
    performance_gate_guidance: tuple[tuple[str, tuple[str, ...]], ...] = (
        ("actions", (
            "Exercise the real workload required by the existing performance contract.",
            "Capture a fresh operator-owned performance snapshot outside the repository.",
            "Validate it with python3 scripts/perf_acceptance.py ../zen-performance.json.",
        )),
        ("success", (
            "All configured request-class sample minima and latency budgets pass.",
            "Prepared-view effectiveness and mutation-lane evidence pass without threshold relaxation.",
        )),
        ("forbidden", (
            "Do not lower sample minima, latency budgets or acceptance thresholds.",
            "Do not inject synthetic PASS evidence.",
        )),
    )

    def repository_root(self, script_file: str | Path) -> Path:
        return Path(script_file).resolve().parents[1]

    def runtime_directory(self, root: Path) -> Path:
        return root / self.runtime_dir_name

    def artifact(self, root: Path, name: str) -> Path:
        return self.runtime_directory(root) / dict(self.artifacts)[name]

    def controller_cli(self, root: Path) -> Path:
        return root / self.controller_cli_relative_path

    def controller_display_command(self, root: Path) -> str:
        return f"python3 {self.relative_path(root, self.controller_cli(root))}"

    def git_worktree(self, root: Path) -> Path:
        return root

    def git_command(self, *args: str) -> list[str]:
        return [self.git_executable, *args]

    def relative_path(self, root: Path, path: Path) -> str:
        return str(path.relative_to(root))

    def project_metadata(self, root: Path) -> dict[str, str]:
        return {
            "identity": self.identity,
            "repository": root.name,
            "runtime_directory": self.relative_path(root, self.runtime_directory(root)),
        }

    def qualification_gates(self, root: Path, python_executable: str) -> list[tuple[str, list[str]]]:
        """Return host-project validation; lifecycle validation stays in the controller."""
        py_files = sorted(
            str(path.relative_to(root))
            for base in (root / relative_path for relative_path in self.source_roots) if base.exists()
            for path in base.glob("*.py")
        )
        return [
            ("python-compile", [python_executable, "-m", "py_compile", *py_files]),
            ("unit-tests", [python_executable, "-m", "unittest", "discover", "-s", self.test_root, "-v"]),
            ("ux-validator", [python_executable, "scripts/ux_validate.py"]),
        ]

    def final_validator_gates(self, root: Path, python_executable: str) -> list[tuple[str, list[str]]]:
        return [
            (name, [python_executable, relative_path])
            for name, relative_path in self.optional_final_validators
            if (root / relative_path).exists()
        ]

    @staticmethod
    def guidance(values: tuple[tuple[str, tuple[str, ...]], ...]) -> dict[str, list[str]]:
        return {key: list(items) for key, items in values}


ZEN_PROFILE = ZenProjectProfile()
