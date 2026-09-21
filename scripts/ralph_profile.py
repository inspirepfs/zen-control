"""Host-project profile contract for embedded RALPH-Lite.

The controller owns lifecycle, approval, recovery, qualification orchestration,
and evidence semantics.  A project profile supplies repository layout, durable
runtime locations, host validation commands, protection/tooling policy, and
host-specific prompt/gate wording.

``ZEN_PROFILE`` is the compatibility-preserving adapter for the current ZEN
Control embedding.  Controller modules consume the neutral ``PROJECT_PROFILE``
name so physical extraction can replace the adapter without editing core
lifecycle logic.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class ProjectProfile:
    """Host-supplied project contract consumed by the embedded controller."""

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
        ("retirements", "retirements"),
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
        "scripts/ralph_web.py", "scripts/ralph_profile.py", "tests/test_ralph_lite.py",
        "tests/test_ralph_efficiency.py", "tests/test_ralph_model.py", "tests/test_ralph_gate.py",
        "tests/test_ralph_lifecycle.py", "tests/test_ralph_retry_hardening.py",
        "tests/test_ralph_web.py", "tests/test_ralph_self_hosting.py",
        "tests/test_ralph_profile_boundary.py", "tests/test_ralph_web_gate_profile_boundary.py",
        "docs/RALPH-LITE.md",
    })
    optional_final_validators: tuple[tuple[str, str], ...] = (
        ("environment", "scripts/env_validate.py"),
        ("supply-chain", "scripts/supply_chain_validate.py"),
        ("public-audit", "scripts/public_release_audit.py"),
    )
    execution_prompt_guardrails: tuple[str, ...] = (
        "Do not interact with live RouterOS, secrets, credentials, or external production systems.",
    )
    nonrecoverable_validation_markers: tuple[str, ...] = (
        "policy violation", "secret", "credential", "routeros", "human decision",
    )
    production_action_keywords: tuple[str, ...] = (
        "routeros", "production", "live write", "live action",
    )
    incident_reason_keyword: str = "incident"
    performance_reason_keyword: str = "performance"
    incident_runtime_summary: str = (
        "Incident Monitor state is runtime-owned. No verified source/configuration defect "
        "was found; operator action/evidence is required before this approved step can advance."
    )
    web_login_subtitle: str = "Private home-lab operator console"
    web_title: str = "RALPH-Lite"
    web_console_subtitle: str = "Operator console · CLI/TUI remains authoritative"
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

    def runtime_relative_path(self, relative: str | Path | None = None) -> str:
        base = Path(self.runtime_dir_name).as_posix().strip("/")
        if not relative:
            return base
        suffix = Path(relative).as_posix().lstrip("/")
        return f"{base}/{suffix}" if suffix else base

    def is_runtime_path(self, path: str | Path) -> bool:
        value = Path(str(path)).as_posix()
        while value.startswith("./"):
            value = value[2:]
        base = self.runtime_relative_path()
        return value == base or value.startswith(base + "/")

    def artifact(self, root: Path, name: str) -> Path:
        return self.runtime_directory(root) / dict(self.artifacts)[name]

    def artifact_relative_path(self, name: str) -> str:
        return self.runtime_relative_path(dict(self.artifacts)[name])

    def runtime_config_path(self, root: Path, filename: str) -> Path:
        return self.runtime_directory(root) / filename

    def policy_storage_directory(self, root: Path) -> Path:
        """Return the host-owned directory for live policy documents."""
        return self.runtime_directory(root)

    def policy_storage_kwargs(self, root: Path) -> dict[str, Path]:
        """Return helper arguments while preserving the ZEN helper call shape.

        The original ZEN helpers infer their ``.ralph`` location from ``root``.
        Alternate hosts must pass their runtime directory explicitly; keeping
        that distinction here prevents controller and Web code from owning a
        runtime-path decision.
        """
        runtime_directory = self.policy_storage_directory(root)
        if self.runtime_dir_name == ".ralph" and runtime_directory == self.runtime_directory(root):
            return {}
        return {"runtime_directory": runtime_directory}

    def recovery_manifest(self, root: Path, checkpoint_id: str) -> Path:
        return self.artifact(root, "recovery") / checkpoint_id / "manifest.json"

    def policy_reference(self) -> str:
        return self.artifact_relative_path("policy")

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

    def prompt_guardrails(self) -> str:
        return " ".join(item.strip() for item in self.execution_prompt_guardrails if item.strip())

    def validation_block_is_nonrecoverable(self, text: str) -> bool:
        lower = str(text or "").lower()
        return any(marker.lower() in lower for marker in self.nonrecoverable_validation_markers)

    def gate_rules(self) -> tuple[tuple[str, tuple[str, ...]], ...]:
        return (
            ("validation_evidence", ("performance", "sample", "acceptance evidence", "snapshot", "validation")),
            ("runtime_evidence", ("incident", "runtime", "diagnostic", "worker", "active durable")),
            ("credentials_or_access", ("credential", "login", "permission", "access token", "authentication")),
            ("security_approval", ("security approval", "security sign-off", "authority approval")),
            ("production_action", tuple(self.production_action_keywords)),
            ("scope_conflict", ("scope conflict", "overlap", "claimed work", "out of scope")),
            ("external_dependency", ("external dependency", "third-party", "upstream", "service unavailable")),
        )

    @staticmethod
    def guidance(values: tuple[tuple[str, tuple[str, ...]], ...]) -> dict[str, list[str]]:
        return {key: list(items) for key, items in values}


# Current host adapter.  Persisted filenames/schemas remain unchanged; D4 only
# makes the boundary executable and testable, it does not migrate runtime data.
ZEN_PROFILE = ProjectProfile()
PROJECT_PROFILE = ZEN_PROFILE
