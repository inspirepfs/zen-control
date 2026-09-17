#!/usr/bin/env python3
"""RALPH-Lite: a tiny, deterministic Codex development-loop supervisor.

Human approves a 5-10 step plan. Codex may then implement one step per loop.
The controller, not Codex, owns approval state, qualification gates, failure
budgets, loop journaling, and the ideas bucket.
"""
from __future__ import annotations

import argparse
import ast
import datetime as dt
import hashlib
import json
import os
import re
import selectors
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path
from typing import Iterable

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))
import ralph_tui as tui

ROOT = Path(__file__).resolve().parents[1]
RALPH = ROOT / ".ralph"
STATE = RALPH / "state.json"
PLAN = RALPH / "plan.md"
IDEAS = RALPH / "ideas.md"
JOURNAL = RALPH / "journal.md"
POLICY = RALPH / "policy.md"
LIVE = RALPH / "live.log"
CONTEXT = RALPH / "context.json"
EVENTS = RALPH / "events.jsonl"
RECOVERY = RALPH / "recovery"
REPORTS = RALPH / "reports"
USAGE_LEDGER = RALPH / "usage-ledger.jsonl"

MAX_REPAIRS_PER_FAILURE = 3
DEFAULT_MAX_LOOPS = 40
# Codex exec currently has no native max-agent-turns/max-steps control. These
# budgets therefore act as a safe post-loop circuit breaker: finish the current
# qualified step, then pause before another model turn if efficiency regresses.
PROMPT_COMMAND_BUDGET = 6
EFFICIENCY_MAX_COMMANDS = 8
EFFICIENCY_MAX_CUMULATIVE_INPUT = 600_000
EFFICIENCY_MAX_NONCACHED_INPUT = 100_000
EFFICIENCY_MAX_REPORTED_FILES = 8
USAGE_RESERVE_PERCENT = 5.0
USAGE_APP_SERVER_TIMEOUT_SECONDS = 15
USAGE_POLL_SECONDS = 300
USAGE_LEDGER_MAX_ROWS = 20_000
_CODEX_PREFIX: list[str] | None = None
EXCLUDED_DIRS = {
    ".git", ".ralph", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".venv", "venv", "node_modules", "data", "logs", "diagnostics", "backup", "backups",
}
PROTECTED_PREFIXES = ("secrets/", "certs/")
PROTECTED_EXACT = {".npmrc", ".pypirc", ".netrc", ".envrc"}
PROTECTED_DIR_PREFIXES = (".codex/", ".direnv/")
PROTECTED_SUFFIXES = (".token", ".secret", ".secrets", ".credentials")
TOOLING_PATHS = {
    ".gitignore",
    ".ralph/policy.md",
    "scripts/ralph.py",
    "scripts/ralph_gate.py",
    "scripts/ralph_tui.py",
    "scripts/ralph_web.py",
    "tests/test_ralph_lite.py",
    "tests/test_ralph_gate.py",
    "tests/test_ralph_lifecycle.py",
    "tests/test_ralph_retry_hardening.py",
    "tests/test_ralph_web.py",
    "tests/test_ralph_self_hosting.py",
    "docs/RALPH-LITE.md",
}

PLAN_SCHEMA = {
    "type": "object",
    "properties": {
        "goal": {"type": "string"},
        "steps": {
            "type": "array", "minItems": 5, "maxItems": 10,
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "title": {"type": "string"},
                    "objective": {"type": "string"},
                    "acceptance": {"type": "array", "items": {"type": "string"}},
                    "test_change_policy": {"type": "string", "enum": ["none", "add-only", "modify"]},
                },
                "required": ["id", "title", "objective", "acceptance", "test_change_policy"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["goal", "steps"],
    "additionalProperties": False,
}

RESULT_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "ideas": {"type": "array", "items": {"type": "string"}},
        "blockers": {"type": "array", "items": {"type": "string"}},
        "needs_human": {"type": "boolean"},
        "blocker_class": {"type": "string", "enum": ["none", "validation-only", "continuation", "human-decision", "policy"]},
        "validation_notes": {"type": "array", "items": {"type": "string"}},
        "context": {
            "type": "object",
            "properties": {
                "relevant_files": {"type": "array", "maxItems": 8, "items": {"type": "string"}},
                "accepted_findings": {"type": "array", "maxItems": 8, "items": {"type": "string"}},
                "files_inspected": {"type": "array", "maxItems": 16, "items": {"type": "string"}},
            },
            "required": ["relevant_files", "accepted_findings", "files_inspected"],
            "additionalProperties": False,
        },
    },
    "required": ["summary", "ideas", "blockers", "needs_human", "blocker_class", "validation_notes", "context"],
    "additionalProperties": False,
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def canonical_plan(plan: dict) -> bytes:
    return json.dumps(plan, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def plan_hash(plan: dict) -> str:
    return hashlib.sha256(canonical_plan(plan)).hexdigest()


def validate_plan(plan: dict) -> None:
    steps = plan.get("steps") if isinstance(plan, dict) else None
    if not isinstance(plan.get("goal") if isinstance(plan, dict) else None, str) or not plan["goal"].strip():
        raise ValueError("plan goal must be a non-empty string")
    if not isinstance(steps, list) or not 5 <= len(steps) <= 10:
        raise ValueError("plan must contain 5-10 steps")
    for index, step in enumerate(steps, 1):
        if step.get("id") != index:
            raise ValueError("plan step ids must be sequential starting at 1")
        for key in ("title", "objective"):
            if not isinstance(step.get(key), str) or not step[key].strip():
                raise ValueError(f"step {index} {key} must be non-empty")
        acceptance = step.get("acceptance")
        if not isinstance(acceptance, list) or not acceptance or not all(isinstance(x, str) and x.strip() for x in acceptance):
            raise ValueError(f"step {index} acceptance must contain at least one item")
        if step.get("test_change_policy") not in {"none", "add-only", "modify"}:
            raise ValueError(f"step {index} has invalid test_change_policy")


def render_plan(plan: dict) -> str:
    digest = plan_hash(plan)
    lines = ["# RALPH-Lite Approved-Plan Candidate", "", f"**Goal:** {plan['goal']}", f"**Plan SHA-256:** `{digest}`", ""]
    for step in plan["steps"]:
        lines += [f"## {step['id']}. {step['title']}", "", step["objective"], "", "Acceptance:"]
        lines += [f"- {item}" for item in step["acceptance"]]
        lines += [f"- Test changes: `{step['test_change_policy']}`", ""]
    lines += ["## Human gate", "", f"Approve exactly this plan with: `python3 scripts/ralph.py approve {digest}`", ""]
    return "\n".join(lines)


def default_state() -> dict:
    return {
        "schema": "zen_ralph_lite_state_v1",
        "status": "IDLE",
        "plan_hash": None,
        "plan": None,
        "current_step": 1,
        "loop_count": 0,
        "failure_attempts": {},
        "active_failure": None,
        "last_failure": None,
        "last_result": None,
        "block_reason": None,
        "recovery_checkpoint": None,
        "plan_changed_files": [],
        "plan_owned_files": [],
        "human_steering": [],
        "steering_allowed_new_tests": [],
        "self_hosting_grant": None,
        "self_hosting_candidate": None,
        "self_hosting_grant_history": [],
        "step_results": [],
        "final_qualification": None,
        "commit_sha": None,
        "commit_reconciled": False,
        "commit_reconcile_note": None,
        "push_upstream": None,
        "push_reconciled": False,
        "completion_changes": None,
        "updated_at": utc_now(),
    }


def load_state() -> dict:
    if not STATE.exists():
        return default_state()
    return json.loads(STATE.read_text(encoding="utf-8"))


def save_state(state: dict) -> None:
    state["updated_at"] = utc_now()
    RALPH.mkdir(parents=True, exist_ok=True)
    tmp = STATE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, STATE)


def default_context() -> dict:
    return {
        "schema": "zen_ralph_lite_context_v1",
        "plan_hash": None,
        "last_step": None,
        "last_result": None,
        "summary": "",
        "changed_files": [],
        "relevant_files": [],
        "accepted_findings": [],
        "updated_at": utc_now(),
    }


def load_context() -> dict:
    if not CONTEXT.exists():
        return default_context()
    try:
        data = json.loads(CONTEXT.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default_context()
    return data if isinstance(data, dict) and data.get("schema") == "zen_ralph_lite_context_v1" else default_context()


def save_context(context: dict) -> None:
    context = dict(context)
    context["schema"] = "zen_ralph_lite_context_v1"
    context["updated_at"] = utc_now()
    CONTEXT.parent.mkdir(parents=True, exist_ok=True)
    tmp = CONTEXT.with_suffix(".tmp")
    tmp.write_text(json.dumps(context, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, CONTEXT)


def _context_path(value: str) -> str | None:
    value = str(value or "").strip()
    if not value:
        return None
    try:
        candidate = Path(value)
        if candidate.is_absolute():
            candidate = candidate.relative_to(ROOT)
    except ValueError:
        return None
    rel = candidate.as_posix().lstrip("./")
    if not rel or rel == ".ralph" or rel.startswith(".ralph/") or is_protected_path(rel):
        return None
    return rel


def context_handoff(state: dict) -> dict:
    context = load_context()
    if context.get("plan_hash") not in {None, state.get("plan_hash")}:
        return default_context()
    return {
        "last_step": context.get("last_step"),
        "last_result": context.get("last_result"),
        "summary": str(context.get("summary") or "")[:1200],
        "changed_files": list(context.get("changed_files") or [])[:12],
        "relevant_files": list(context.get("relevant_files") or [])[:8],
        "accepted_findings": list(context.get("accepted_findings") or [])[:8],
    }


def update_context_after_human_confirmation(state: dict, step: dict, gate_id: str, reason: str) -> None:
    """Record a human-owned accepted finding without pretending Codex proved it."""
    prior = context_handoff(state)
    summary = " ".join(str(reason or "").split())[:1200]
    finding = f"Human gate {gate_id} satisfied by operator: {summary}"[:500]
    findings: list[str] = []
    for raw in [finding, *(prior.get("accepted_findings") or [])]:
        text = " ".join(str(raw).split())[:500]
        if text and text not in findings:
            findings.append(text)
        if len(findings) >= 8:
            break
    save_context({
        "plan_hash": state.get("plan_hash"),
        "last_step": step.get("id"),
        "last_result": "HUMAN_CONFIRMED",
        "summary": summary,
        "changed_files": [],
        "relevant_files": list(prior.get("relevant_files") or [])[:8],
        "accepted_findings": findings,
    })


def update_context_after_pass(state: dict, step: dict, result: dict, changed: Iterable[str]) -> None:
    supplied = result.get("context") if isinstance(result.get("context"), dict) else {}
    prior = context_handoff(state)
    changed_files = [path for raw in changed if (path := _context_path(raw))]
    relevant: list[str] = []
    for raw in [*changed_files, *(supplied.get("relevant_files") or []), *(prior.get("relevant_files") or [])]:
        path = _context_path(raw)
        if path and path not in relevant:
            relevant.append(path)
        if len(relevant) >= 8:
            break
    findings: list[str] = []
    for raw in [*(supplied.get("accepted_findings") or []), *(prior.get("accepted_findings") or [])]:
        text = " ".join(str(raw).split())[:500]
        if text and text not in findings:
            findings.append(text)
        if len(findings) >= 8:
            break
    save_context({
        "plan_hash": state.get("plan_hash"),
        "last_step": step.get("id"),
        "last_result": "PASS",
        "summary": " ".join(str(result.get("summary") or "").split())[:1200],
        "changed_files": changed_files[:12],
        "relevant_files": relevant,
        "accepted_findings": findings,
    })


def bootstrap_context_from_journal(state: dict) -> bool:
    """Seed compact handoff state from the latest successful pre-v0.1.4 loop."""
    if int(state.get("current_step") or 1) <= 1 or not JOURNAL.exists():
        return False
    current = load_context()
    if current.get("last_step") is not None:
        return False
    text = JOURNAL.read_text(encoding="utf-8")
    blocks = re.findall(r"(?ms)^## Loop .*?(?=^## |\Z)", text)
    for block_text in reversed(blocks):
        if "- Result: PASS" not in block_text:
            continue
        def field(name: str) -> str:
            match = re.search(rf"(?m)^- {re.escape(name)}: (.*)$", block_text)
            return match.group(1).strip() if match else ""
        try:
            step_no = int(field("Plan step"))
        except ValueError:
            continue
        raw_files = field("Files changed")
        changed_files = [] if raw_files in {"", "-"} else [p.strip() for p in raw_files.split(",") if _context_path(p.strip())]
        summary = field("Summary")
        save_context({
            "plan_hash": state.get("plan_hash"),
            "last_step": step_no,
            "last_result": "PASS",
            "summary": summary[:1200],
            "changed_files": changed_files[:12],
            "relevant_files": changed_files[:8],
            "accepted_findings": [summary[:500]] if summary and summary != "-" else [],
        })
        return True
    return False



def _git(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(["git", *args], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if check and proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed ({proc.returncode}): {proc.stdout[-3000:]}")
    return proc


def git_head() -> str:
    return _git(["rev-parse", "HEAD"]).stdout.strip()


def git_branch() -> str:
    return _git(["branch", "--show-current"]).stdout.strip()


def git_upstream() -> str | None:
    proc = _git(["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"], check=False)
    value = proc.stdout.strip()
    return value if proc.returncode == 0 and value else None


def _status_sets() -> tuple[list[str], list[str]]:
    proc = _git(["status", "--porcelain=v1", "-z", "--untracked-files=all"])
    dirty: list[str] = []
    untracked: list[str] = []
    for entry in proc.stdout.split("\0"):
        if not entry:
            continue
        code = entry[:2]
        payload = entry[3:] if len(entry) >= 4 else ""
        if " -> " in payload:
            payload = payload.split(" -> ", 1)[1]
        payload = payload.strip()
        if not payload:
            continue
        if payload not in dirty:
            dirty.append(payload)
        if code == "??" and payload not in untracked:
            untracked.append(payload)
    return sorted(dirty), sorted(untracked)


def create_recovery_checkpoint(state: dict) -> dict:
    """Create a local Git-backed recovery point before an approved plan can run."""
    plan_digest = str(state.get("plan_hash") or "")
    if not plan_digest:
        raise RuntimeError("cannot checkpoint a plan without a plan hash")
    stamp = dt.datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
    checkpoint_id = f"RP-{stamp}-{plan_digest[:8]}"
    directory = RECOVERY / checkpoint_id
    directory.mkdir(parents=True, exist_ok=False)
    head = git_head()
    branch = git_branch()
    upstream = git_upstream()
    dirty, untracked = _status_sets()
    staged = [line.strip() for line in _git(["diff", "--cached", "--name-only"]).stdout.splitlines() if line.strip()]

    # `git stash create` records tracked staged/unstaged work without changing the
    # worktree.  Keep the object reachable through a private local ref.  Untracked
    # paths are listed separately; protected/private files are never copied.
    stash = _git(["stash", "create", f"RALPH recovery {checkpoint_id}"], check=False).stdout.strip()
    recovery_oid = stash or head
    ref = f"refs/ralph/recovery/{checkpoint_id}"
    _git(["update-ref", ref, recovery_oid])

    (directory / "status.txt").write_text(_git(["status", "--short"]).stdout, encoding="utf-8")
    (directory / "working.patch").write_text(_git(["diff", "--binary", "HEAD"]).stdout, encoding="utf-8")
    (directory / "staged.patch").write_text(_git(["diff", "--cached", "--binary"]).stdout, encoding="utf-8")
    manifest = {
        "schema": "zen_ralph_recovery_v1",
        "id": checkpoint_id,
        "created_at": utc_now(),
        "plan_hash": plan_digest,
        "head": head,
        "branch": branch,
        "upstream": upstream,
        "ref": ref,
        "recovery_oid": recovery_oid,
        "baseline_dirty_paths": dirty,
        "baseline_untracked_paths": untracked,
        "baseline_staged_paths": staged,
        "protected_untracked_not_copied": [path for path in untracked if is_protected_path(path)],
    }
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tui.write_event(EVENTS, "CHECKPOINT", f"created {checkpoint_id}", checkpoint=manifest)
    live_write(f"{checkpoint_id} · HEAD {head[:12]} · dirty={len(dirty)} · ref={ref}", "CHECKPOINT")
    return manifest


def load_recovery_checkpoint(checkpoint_id: str | None) -> dict:
    if not checkpoint_id:
        return {}
    path = RECOVERY / checkpoint_id / "manifest.json"
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def plan_baseline_path_kind(state: dict, path: str) -> str:
    """Classify a path against the approval-time recovery checkpoint."""
    checkpoint = load_recovery_checkpoint(state.get("recovery_checkpoint"))
    if not checkpoint:
        return "unknown"
    path = str(path or "").strip().replace("\\", "/")
    if path in set(checkpoint.get("baseline_untracked_paths") or []):
        return "preexisting-untracked"
    head = str(checkpoint.get("head") or "").strip()
    if head:
        proc = _git(["cat-file", "-e", f"{head}:{path}"], check=False)
        if proc.returncode == 0:
            return "tracked"
    if path in set(checkpoint.get("baseline_dirty_paths") or []):
        return "preexisting-dirty"
    return "absent"


def plan_owned_path(state: dict, path: str) -> bool:
    return str(path) in set(state.get("plan_owned_files") or [])


def remember_plan_files(state: dict, paths: Iterable[str]) -> None:
    current = list(state.get("plan_changed_files") or [])
    owned = list(state.get("plan_owned_files") or [])
    for path in paths:
        if not path:
            continue
        if path not in current:
            current.append(path)
        if plan_baseline_path_kind(state, path) == "absent" and path not in owned:
            owned.append(path)
    state["plan_changed_files"] = sorted(current)
    state["plan_owned_files"] = sorted(owned)


def steering_for_step(state: dict, step_no: int) -> list[dict]:
    values = state.get("human_steering") if isinstance(state.get("human_steering"), list) else []
    return [dict(item) for item in values if isinstance(item, dict) and int(item.get("step") or 0) == int(step_no)]


def steering_allowed_new_tests(state: dict, step_no: int) -> set[str]:
    allowed: set[str] = set()
    for item in state.get("steering_allowed_new_tests") or []:
        if not isinstance(item, dict) or int(item.get("step") or 0) != int(step_no):
            continue
        path = str(item.get("path") or "").strip()
        if path:
            allowed.add(path)
    return allowed


def _numstat(paths: Iterable[str], *, base_ref: str = "HEAD") -> dict[str, tuple[int, int]]:
    selected = [str(path) for path in paths if path]
    if not selected:
        return {}
    proc = _git(["diff", "--numstat", base_ref, "--", *selected], check=False)
    result: dict[str, tuple[int, int]] = {}
    if proc.returncode == 0:
        for line in proc.stdout.splitlines():
            parts = line.split("\t", 2)
            if len(parts) != 3:
                continue
            try:
                added = int(parts[0]) if parts[0].isdigit() else 0
                removed = int(parts[1]) if parts[1].isdigit() else 0
            except ValueError:
                continue
            result[parts[2]] = (added, removed)
    for path in selected:
        full = ROOT / path
        if path not in result and full.exists() and full.is_file():
            status = _git(["status", "--porcelain=v1", "--", path], check=False).stdout
            if status.startswith("??"):
                try:
                    result[path] = (len(full.read_text(encoding="utf-8", errors="ignore").splitlines()), 0)
                except OSError:
                    result[path] = (0, 0)
    return result


def _changed_new_lines(path: str, *, base_ref: str = "HEAD") -> set[int]:
    proc = _git(["diff", "--unified=0", base_ref, "--", path], check=False)
    lines: set[int] = set()
    for raw in proc.stdout.splitlines():
        match = re.match(r"@@ -(?:\d+)(?:,\d+)? \+(\d+)(?:,(\d+))? @@", raw)
        if not match:
            continue
        start = int(match.group(1))
        count = int(match.group(2) or 1)
        lines.update(range(start, start + max(0, count)))
    full = ROOT / path
    if not lines and full.exists() and _git(["status", "--porcelain=v1", "--", path], check=False).stdout.startswith("??"):
        try:
            lines.update(range(1, len(full.read_text(encoding="utf-8", errors="ignore").splitlines()) + 1))
        except OSError:
            pass
    return lines


def _python_changed_symbols(path: str, *, base_ref: str = "HEAD") -> list[str]:
    if not path.endswith(".py"):
        return []
    full = ROOT / path
    if not full.exists():
        return []
    changed = _changed_new_lines(path, base_ref=base_ref)
    if not changed:
        return []
    try:
        tree = ast.parse(full.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, SyntaxError):
        return []
    symbols: list[tuple[int, str]] = []
    class_stack: list[str] = []

    class Visitor(ast.NodeVisitor):
        def visit_ClassDef(self, node):
            end = int(getattr(node, "end_lineno", node.lineno))
            if any(int(node.lineno) <= line <= end for line in changed):
                symbols.append((int(node.lineno), f"class {'.'.join([*class_stack, node.name])}"))
            class_stack.append(node.name)
            self.generic_visit(node)
            class_stack.pop()

        def _function(self, node):
            end = int(getattr(node, "end_lineno", node.lineno))
            if any(int(node.lineno) <= line <= end for line in changed):
                name = ".".join([*class_stack, node.name])
                symbols.append((int(node.lineno), f"{name}()"))
            self.generic_visit(node)

        visit_FunctionDef = _function
        visit_AsyncFunctionDef = _function

    Visitor().visit(tree)
    result: list[str] = []
    for _, name in sorted(symbols):
        if name not in result:
            result.append(name)
        if len(result) >= 5:
            break
    return result


def _diff_symbols(path: str, *, base_ref: str = "HEAD") -> list[str]:
    symbols = _python_changed_symbols(path, base_ref=base_ref)
    if symbols:
        return symbols
    proc = _git(["diff", "--function-context", "--unified=0", base_ref, "--", path], check=False)
    fallback: list[str] = []
    for line in proc.stdout.splitlines():
        if not line.startswith("@@"):
            continue
        tail = line.split("@@", 2)[-1].strip()
        tail = re.sub(r"\s+", " ", tail)[:100]
        if tail and tail not in fallback:
            fallback.append(tail)
        if len(fallback) >= 3:
            break
    return fallback


def change_entries(paths: Iterable[str], *, base_ref: str = "HEAD") -> list[dict]:
    paths = sorted(set(str(path) for path in paths if path))
    stats = _numstat(paths, base_ref=base_ref)
    entries: list[dict] = []
    for path in paths:
        full = ROOT / path
        status = _git(["status", "--porcelain=v1", "--", path], check=False).stdout[:2]
        if status == "??":
            action = "CREATE"
        elif "D" in status or not full.exists():
            action = "DELETE"
        elif "R" in status:
            action = "MOVE"
        else:
            action = "EDIT"
        added, removed = stats.get(path, (0, 0))
        entries.append({
            "action": action,
            "path": path,
            "added": added,
            "removed": removed,
            "symbols": _diff_symbols(path, base_ref=base_ref),
        })
    return entries



def bounded_diff(paths: Iterable[str], *, base_ref: str = "HEAD", max_chars: int = 12000) -> str:
    selected = [str(path) for path in paths if path]
    if not selected:
        return ""
    proc = _git(["diff", "--unified=1", base_ref, "--", *selected], check=False)
    text = proc.stdout
    for path in selected:
        full = ROOT / path
        if full.exists() and _git(["status", "--porcelain=v1", "--", path], check=False).stdout.startswith("??"):
            try:
                content = full.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            text += f"\ndiff --git a/{path} b/{path}\n--- /dev/null\n+++ b/{path}\n@@ new file @@\n"
            text += "\n".join("+" + line for line in content.splitlines()[:80]) + "\n"
    return text[:max_chars]

def final_qualification_gates() -> list[tuple[str, list[str]]]:
    gates = list(qualification_gates())
    optional = [
        ("environment", ROOT / "scripts" / "env_validate.py"),
        ("supply-chain", ROOT / "scripts" / "supply_chain_validate.py"),
        ("public-audit", ROOT / "scripts" / "public_release_audit.py"),
    ]
    for name, path in optional:
        if path.exists():
            gates.append((name, [sys.executable, str(path.relative_to(ROOT))]))
    gates.append(("diff-check", ["git", "diff", "--check"]))
    return gates


def run_final_qualification() -> tuple[bool, list[str], dict[str, float], str]:
    results: list[str] = []
    durations: dict[str, float] = {}
    output = ""
    print(tui.box("FINAL QUALIFICATION", ["Re-running authoritative gates before commit readiness"], tone="cyan"))
    for name, command in final_qualification_gates():
        live_write(f"running {name}", "GATE")
        started = time.monotonic()
        proc = run_process(command)
        durations[name] = time.monotonic() - started
        outcome = "PASS" if proc.returncode == 0 else "FAIL"
        results.append(f"{name}={outcome}")
        live_write(f"{name}={outcome} duration={durations[name]:.1f}s", "PASS" if proc.returncode == 0 else "FAIL")
        if proc.returncode != 0:
            output = proc.stdout[-12000:]
            return False, results, durations, output
    return True, results, durations, output


def _step_results_from_state(state: dict) -> list[dict]:
    values = state.get("step_results") if isinstance(state.get("step_results"), list) else []
    return [dict(value) for value in values if isinstance(value, dict)]


def record_step_result(state: dict, step: dict, result: str, *, summary: str = "", files: Iterable[str] = (), gates: Iterable[str] = (), stats: dict | None = None) -> None:
    values = _step_results_from_state(state)
    values.append({
        "step": int(step.get("id") or 0),
        "title": str(step.get("title") or ""),
        "result": result,
        "summary": " ".join(str(summary or "").split())[:1000],
        "files": list(files),
        "gates": list(gates),
        "stats": dict(stats or {}),
        "recorded_at": utc_now(),
    })
    state["step_results"] = values[-100:]


def summarize_step_outcomes(state: dict) -> dict:
    """Return one terminal outcome per plan step plus useful operator counts."""
    latest: dict[int, dict] = {}
    for item in _step_results_from_state(state):
        step_no = int(item.get("step") or 0)
        if step_no:
            latest[step_no] = item
    values = list(latest.values())
    passed = [item for item in values if item.get("result") == "PASS"]
    human = [item for item in values if item.get("result") == "HUMAN_CONFIRMED"]
    recovered = [
        item for item in passed
        if int((item.get("stats") or {}).get("repair") or 0) > 0
    ]
    accepted = passed + human
    return {
        "latest": latest,
        "accepted": len(accepted),
        "pass": len(passed),
        "human_confirmed": len(human),
        "recovered": len(recovered),
        "failed": max(0, len((state.get("plan") or {}).get("steps") or []) - len(accepted)),
    }


def plan_progress_rows(state: dict) -> list[str]:
    outcomes = summarize_step_outcomes(state)["latest"]
    current = int(state.get("current_step") or 0)
    rows: list[str] = []
    for step in list(((state.get("plan") or {}).get("steps") or [])):
        step_no = int(step.get("id") or 0)
        outcome = str((outcomes.get(step_no) or {}).get("result") or "")
        if outcome in {"PASS", "HUMAN_CONFIRMED"}:
            marker = "✓"
        elif step_no == current:
            marker = "▶"
        else:
            marker = "○"
        rows.append(f"{marker} {step_no}. {str(step.get('title') or '')}")
    return rows


def build_completion_report(state: dict, final_gates: list[str]) -> dict:
    plan = state.get("plan") if isinstance(state.get("plan"), dict) else {}
    steps = list(plan.get("steps") or [])
    files = list(state.get("plan_changed_files") or [])
    saved_changes = state.get("completion_changes") if isinstance(state.get("completion_changes"), dict) else {}
    entries = list(saved_changes.get("entries") or []) if saved_changes else change_entries(files)
    added = int(saved_changes.get("added") or 0) if saved_changes else sum(int(item.get("added") or 0) for item in entries)
    removed = int(saved_changes.get("removed") or 0) if saved_changes else sum(int(item.get("removed") or 0) for item in entries)
    step_results = _step_results_from_state(state)
    outcomes = summarize_step_outcomes(state)
    passed_steps = int(outcomes["accepted"])
    token_totals = {"input_tokens": 0, "cached_input_tokens": 0, "output_tokens": 0, "reasoning_output_tokens": 0, "commands_executed": 0}
    for item in step_results:
        stats = item.get("stats") if isinstance(item.get("stats"), dict) else {}
        for key in token_totals:
            token_totals[key] += int(stats.get(key) or 0)

    report = {
        "schema": "zen_ralph_completion_v1",
        "generated_at": utc_now(),
        "plan_hash": state.get("plan_hash"),
        "goal": plan.get("goal"),
        "status": state.get("status"),
        "counts": {
            "steps_total": len(steps),
            "steps_accepted": int(outcomes["accepted"]),
            "steps_passed": int(outcomes["pass"]),
            "steps_human_confirmed": int(outcomes["human_confirmed"]),
            "steps_recovered": int(outcomes["recovered"]),
            "steps_failed": int(outcomes["failed"]),
            "loops": int(state.get("loop_count") or 0),
            "human_gates": len(state.get("human_gate_resolutions") or []),
            "human_steers": len(state.get("human_steering") or []),
        },
        "qualification": {"state": str((state.get("final_qualification") or {}).get("state") or "UNKNOWN"), "gates": final_gates},
        "changes": {"files": len(entries), "added": added, "removed": removed, "entries": entries},
        "step_results": step_results,
        "recovery_checkpoint": state.get("recovery_checkpoint"),
        "recovery_ref": (load_recovery_checkpoint(state.get("recovery_checkpoint")) or {}).get("ref"),
        "authority": {
            "ralph_tooling_changed": any(is_tooling_path(path) for path in files),
            "protected_paths_changed": any(is_protected_path(path) for path in files),
            "plan_owned_files": sorted(state.get("plan_owned_files") or []),
            "human_steering": list(state.get("human_steering") or []),
        },
        "usage": token_totals,
        "suggested_commit": state.get("commit_message") or _default_commit_message(state),
        "commit": state.get("commit_sha"),
        "push": state.get("push_upstream"),
        "reconciliation": {
            "commit_adopted": bool(state.get("commit_reconciled")),
            "push_adopted": bool(state.get("push_reconciled")),
            "commit_note": state.get("commit_reconcile_note"),
        },
    }
    REPORTS.mkdir(parents=True, exist_ok=True)
    stem = str(state.get("plan_hash") or "unknown")[:16]
    json_path = REPORTS / f"{stem}-summary.json"
    md_path = REPORTS / f"{stem}-summary.md"
    report["json_path"] = str(json_path.relative_to(ROOT))
    report["markdown_path"] = str(md_path.relative_to(ROOT))
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        "# RALPH-Lite Completion Report", "",
        f"**Plan:** `{state.get('plan_hash')}`", f"**Goal:** {plan.get('goal') or '-'}", f"**Status:** {state.get('status')}", "",
        "## Execution", "",
        f"- Steps accepted: {outcomes['accepted']}/{len(steps)}",
        f"- Direct PASS: {outcomes['pass']}",
        f"- Human-confirmed: {outcomes['human_confirmed']}",
        f"- Recovered/repaired PASS: {outcomes['recovered']}",
        f"- Failed/unaccepted: {outcomes['failed']}",
        f"- Implementation loops: {int(state.get('loop_count') or 0)}",
        f"- Human gates resolved: {len(state.get('human_gate_resolutions') or [])}",
        f"- Human steering decisions: {len(state.get('human_steering') or [])}",
        f"- Recovery checkpoint: `{state.get('recovery_checkpoint') or '-'}`", "",
        "## Final qualification", "",
        *[f"- {gate}" for gate in final_gates], "",
        "## Changes", "",
        f"- Files: {len(entries)}", f"- Lines: +{added}/-{removed}",
    ]
    for item in entries:
        symbols = ", ".join(item.get("symbols") or [])
        detail = f" ({symbols})" if symbols else ""
        lines.append(f"- {item['action']} `{item['path']}` +{item['added']}/-{item['removed']}{detail}")
    lines += ["", "## Step results", ""]
    for item in step_results:
        lines.append(f"- Step {item.get('step')}: **{item.get('result')}** — {item.get('title')} — {item.get('summary') or '-'}")
    lines += [
        "", "## Authority", "",
        f"- RALPH tooling changed by plan: {'YES' if report['authority']['ralph_tooling_changed'] else 'NO'}",
        f"- Protected paths changed by plan: {'YES' if report['authority']['protected_paths_changed'] else 'NO'}",
        f"- Plan-owned files: {', '.join(report['authority']['plan_owned_files']) if report['authority']['plan_owned_files'] else '-'}",
        f"- Human steering decisions: {len(report['authority']['human_steering'])}",
        "", "## Usage / efficiency", "",
        f"- Input tokens: {token_totals['input_tokens']}",
        f"- Cached input tokens: {token_totals['cached_input_tokens']}",
        f"- Output tokens: {token_totals['output_tokens']}",
        f"- Reasoning tokens: {token_totals['reasoning_output_tokens']}",
        f"- Commands executed: {token_totals['commands_executed']}",
        "", "## Finalization", "",
        f"- Suggested commit: `{report['suggested_commit']}`",
        f"- Commit: `{state.get('commit_sha') or '-'}`",
        f"- Push upstream: `{state.get('push_upstream') or '-'}`",
        f"- Commit reconciled: {'yes' if state.get('commit_reconciled') else 'no'}",
        f"- Push reconciled: {'yes' if state.get('push_reconciled') else 'no'}",
        f"- Review: `python3 scripts/ralph.py finalize {state.get('plan_hash')}`",
        f"- Commit: `python3 scripts/ralph.py finalize {state.get('plan_hash')} --commit`",
        f"- Push: `python3 scripts/ralph.py finalize {state.get('plan_hash')} --push`",
        "",
    ]
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return report


def finalization_review(state: dict) -> dict:
    checkpoint = load_recovery_checkpoint(state.get("recovery_checkpoint"))
    baseline = set(checkpoint.get("baseline_dirty_paths") or []) if checkpoint else set()
    planned = set(state.get("plan_changed_files") or [])
    current = {path for path in git_changed_paths() if not path.startswith(".ralph/")}
    overlap = sorted((baseline & planned) - {path for path in planned if path.startswith(".ralph/")})
    unexpected = sorted(current - baseline - planned)
    protected = sorted(path for path in planned if is_protected_path(path) or is_tooling_path(path))
    return {
        "baseline": sorted(baseline),
        "planned": sorted(planned),
        "current": sorted(current),
        "overlap": overlap,
        "unexpected": unexpected,
        "protected": protected,
        "checkpoint": checkpoint,
    }


def _commit_paths(commit_sha: str) -> list[str]:
    proc = _git(["diff-tree", "--no-commit-id", "--name-only", "-r", commit_sha], check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"cannot inspect commit {commit_sha}: {proc.stdout[-2000:]}")
    return sorted({line.strip() for line in proc.stdout.splitlines() if line.strip()})


def _verify_reconciled_commit(state: dict, commit_sha: str) -> dict:
    if state.get("status") != "READY_TO_COMMIT":
        raise RuntimeError(f"reconcile-commit requires READY_TO_COMMIT, found {state.get('status')}")
    if str((state.get("final_qualification") or {}).get("state") or "") != "PASS":
        raise RuntimeError("final qualification is not PASS; commit reconciliation refused")
    resolved = _git(["rev-parse", "--verify", f"{commit_sha}^{{commit}}"], check=False)
    if resolved.returncode != 0:
        raise RuntimeError(f"commit {commit_sha} does not exist")
    sha = resolved.stdout.strip()
    reachable = _git(["merge-base", "--is-ancestor", sha, "HEAD"], check=False)
    if reachable.returncode != 0:
        raise RuntimeError("commit is not reachable from current HEAD")
    planned = set(state.get("plan_changed_files") or [])
    if not planned:
        raise RuntimeError("plan has no recorded changed files")
    protected = sorted(path for path in planned if is_protected_path(path) or is_tooling_path(path))
    if protected:
        raise RuntimeError(f"plan records protected/RALPH tooling paths; reconciliation refused: {protected}")
    checkpoint = load_recovery_checkpoint(state.get("recovery_checkpoint"))
    if not checkpoint:
        raise RuntimeError("recovery checkpoint is missing; reconciliation refused")
    baseline = set(checkpoint.get("baseline_dirty_paths") or []) | set(checkpoint.get("baseline_untracked_paths") or [])
    commit_paths = set(_commit_paths(sha))
    missing = sorted(planned - commit_paths)
    if missing:
        raise RuntimeError(f"manual commit does not contain every recorded plan path: {missing}")
    unexpected = sorted(commit_paths - planned - baseline)
    if unexpected:
        raise RuntimeError(f"manual commit contains unexpected paths outside plan/baseline: {unexpected}")
    return {
        "sha": sha,
        "commit_paths": sorted(commit_paths),
        "baseline_extras": sorted(commit_paths - planned),
    }


def _finalization_guard(state: dict) -> tuple[list[str], list[str]]:
    checkpoint = load_recovery_checkpoint(state.get("recovery_checkpoint"))
    if not checkpoint:
        raise RuntimeError("recovery checkpoint is missing; finalization refused")
    baseline = set(checkpoint.get("baseline_dirty_paths") or [])
    baseline_staged = sorted(checkpoint.get("baseline_staged_paths") or [])
    if baseline_staged:
        raise RuntimeError(f"pre-existing staged changes were present at approval; automated commit refused: {baseline_staged}")
    planned = set(state.get("plan_changed_files") or [])
    if not planned:
        raise RuntimeError("no RALPH plan changes are recorded; commit refused")
    overlap = sorted(baseline & planned)
    if overlap:
        print(tui.commit_overlap_card(
            plan_hash=str(state.get("plan_hash") or ""),
            checkpoint=str(state.get("recovery_checkpoint") or "-"),
            baseline_head=str(checkpoint.get("head") or ""),
            branch=str(checkpoint.get("branch") or "-"),
            upstream=str(checkpoint.get("upstream") or "-"),
            overlaps=overlap,
            plan_files=len(planned),
        ))
        raise RuntimeError(f"plan changed files that were already dirty at approval; safe automated commit refused: {overlap}")
    current = {path for path in git_changed_paths() if not path.startswith(".ralph/")}
    baseline = {path for path in baseline if not path.startswith(".ralph/")}
    unexpected = sorted(current - baseline - planned)
    if unexpected:
        raise RuntimeError(f"unexpected working-tree delta outside baseline/plan; automated commit refused: {unexpected}")
    protected = sorted(path for path in planned if is_protected_path(path) or is_tooling_path(path))
    if protected:
        raise RuntimeError(f"automated commit refuses protected/RALPH tooling paths: {protected}")
    missing = sorted(path for path in planned if path not in current)
    if missing:
        raise RuntimeError(f"recorded plan paths are no longer present in the working-tree delta: {missing}")
    proc = _git(["diff", "--check", "--", *sorted(planned)], check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"git diff --check failed: {proc.stdout[-3000:]}")
    audit = ROOT / "scripts" / "public_release_audit.py"
    if audit.exists():
        proc = run_process([sys.executable, str(audit.relative_to(ROOT))])
        if proc.returncode != 0:
            raise RuntimeError(f"public release audit failed; commit refused: {proc.stdout[-4000:]}")
    return sorted(planned), sorted(baseline)


def _default_commit_message(state: dict) -> str:
    goal = " ".join(str(((state.get("plan") or {}).get("goal") or "RALPH plan completion")).split())
    goal = re.sub(r"[^A-Za-z0-9 ._/-]+", "", goal).strip()
    if len(goal) > 64:
        goal = goal[:61].rstrip() + "..."
    return f"chore(zen): {goal[0].lower() + goal[1:] if goal else 'ralph plan completion'}"


def cmd_checkpoints(_: argparse.Namespace) -> int:
    init_files()
    manifests = sorted(RECOVERY.glob("*/manifest.json"), reverse=True)
    if not manifests:
        print("No RALPH recovery checkpoints.")
        return 0
    for path in manifests[:30]:
        data = json.loads(path.read_text(encoding="utf-8"))
        print(f"{data.get('id')} head={str(data.get('head') or '')[:12]} branch={data.get('branch') or '-'} dirty={len(data.get('baseline_dirty_paths') or [])} ref={data.get('ref')}")
    return 0


def cmd_checkpoint_info(args: argparse.Namespace) -> int:
    init_files()
    data = load_recovery_checkpoint(args.checkpoint_id)
    if not data:
        raise RuntimeError(f"unknown checkpoint {args.checkpoint_id}")
    print(json.dumps(data, indent=2, sort_keys=True))
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    init_files()
    state = load_state()
    if args.plan_hash != state.get("plan_hash"):
        raise RuntimeError("report hash does not match the current plan")
    gates = list((state.get("final_qualification") or {}).get("gates") or [])
    report = build_completion_report(state, gates)
    print(report["markdown_path"])
    return 0


def cmd_finalize(args: argparse.Namespace) -> int:
    init_files()
    state = load_state()
    if args.plan_hash != state.get("plan_hash"):
        raise RuntimeError("finalize hash does not match the current plan")
    action = "push" if args.push else "commit" if args.commit else "review"
    if action == "review":
        if state.get("status") not in {"READY_TO_COMMIT", "COMMITTED", "PUSHED"}:
            raise RuntimeError(f"finalize review requires READY_TO_COMMIT/COMMITTED/PUSHED, found {state.get('status')}")
        report = build_completion_report(state, list((state.get("final_qualification") or {}).get("gates") or []))
        print(tui.completion_card(report))
        review = finalization_review(state)
        if review.get("overlap"):
            checkpoint = review.get("checkpoint") or {}
            print(tui.commit_overlap_card(
                plan_hash=str(state.get("plan_hash") or ""),
                checkpoint=str(state.get("recovery_checkpoint") or "-"),
                baseline_head=str(checkpoint.get("head") or ""),
                branch=str(checkpoint.get("branch") or "-"),
                upstream=str(checkpoint.get("upstream") or "-"),
                overlaps=list(review.get("overlap") or []),
                plan_files=len(review.get("planned") or []),
            ))
        print(f"Report: {report['markdown_path']}")
        return 0

    if action == "commit":
        if state.get("status") != "READY_TO_COMMIT":
            raise RuntimeError(f"finalize --commit requires READY_TO_COMMIT, found {state.get('status')}")
        planned, _baseline = _finalization_guard(state)
        _git(["add", "--", *planned])
        message = args.message or _default_commit_message(state)
        proc = _git(["commit", "-m", message, "-m", f"RALPH-Plan: {state.get('plan_hash')}"] , check=False)
        if proc.returncode != 0:
            _git(["reset"], check=False)
            raise RuntimeError(f"git commit failed ({proc.returncode}): {proc.stdout[-4000:]}")
        sha = git_head()
        state["status"] = "COMMITTED"
        state["commit_sha"] = sha
        state["commit_message"] = message
        save_state(state)
        build_completion_report(state, list((state.get("final_qualification") or {}).get("gates") or []))
        live_write(f"commit {sha[:12]} created · {message}", "COMPLETE")
        print(f"COMMITTED plan={state['plan_hash']} sha={sha}")
        return 0

    if state.get("status") != "COMMITTED":
        raise RuntimeError(f"finalize --push requires COMMITTED, found {state.get('status')}")
    upstream = git_upstream()
    if not upstream or "/" not in upstream:
        raise RuntimeError("current branch has no configured upstream; push refused")
    remote, remote_branch = upstream.split("/", 1)
    current_branch = git_branch()
    if not current_branch:
        raise RuntimeError("detached HEAD; push refused")
    fetch = _git(["fetch", "--quiet", "--prune", remote], check=False)
    if fetch.returncode != 0:
        raise RuntimeError(f"could not refresh configured upstream; push refused: {fetch.stdout[-3000:]}")
    counts = _git(["rev-list", "--left-right", "--count", f"HEAD...{upstream}"]).stdout.strip().split()
    if len(counts) != 2:
        raise RuntimeError("could not determine upstream divergence")
    ahead, behind = map(int, counts)
    if behind:
        raise RuntimeError(f"configured upstream is ahead by {behind}; push refused")
    if ahead < 1:
        raise RuntimeError("nothing to push to configured upstream")
    proc = _git(["push"], check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"git push failed ({proc.returncode}): {proc.stdout[-4000:]}")
    state["status"] = "PUSHED"
    state["push_upstream"] = upstream
    state["pushed_at"] = utc_now()
    save_state(state)
    build_completion_report(state, list((state.get("final_qualification") or {}).get("gates") or []))
    live_write(f"pushed commit {str(state.get('commit_sha') or '')[:12]} to configured upstream {upstream}", "COMPLETE")
    print(f"PUSHED plan={state['plan_hash']} upstream={upstream}")
    return 0

def cmd_reconcile_commit(args: argparse.Namespace) -> int:
    """Adopt an already-created qualified commit after strict controller verification."""
    init_files()
    state = load_state()
    if args.plan_hash != state.get("plan_hash"):
        raise RuntimeError("reconcile-commit hash does not match the current plan")
    verified = _verify_reconciled_commit(state, args.commit)
    note = " ".join(str(args.reason or "").split())
    if not note:
        raise RuntimeError("reconcile-commit requires a non-empty --reason")
    state["status"] = "COMMITTED"
    state["commit_sha"] = verified["sha"]
    state["commit_reconciled"] = True
    state["commit_reconcile_note"] = note[:1200]
    state["commit_reconciled_at"] = utc_now()
    save_state(state)
    build_completion_report(state, list((state.get("final_qualification") or {}).get("gates") or []))
    append_journal(
        int(state.get("loop_count") or 0), len((state.get("plan") or {}).get("steps") or []),
        "reconcile-commit", "COMMITTED", summary=note, files=verified["commit_paths"],
        next_action="verify/push configured upstream",
    )
    live_write(f"reconciled existing commit {verified['sha'][:12]} into completed plan", "COMPLETE")
    print(tui.reconcile_card(
        title="COMMIT RECONCILED", plan_hash=str(state.get("plan_hash") or ""),
        commit=verified["sha"], upstream=git_upstream() or "-",
        detail=f"Verified {len(verified['commit_paths'])} commit paths; baseline extras={len(verified['baseline_extras'])}",
    ))
    return 0


def cmd_reconcile_push(args: argparse.Namespace) -> int:
    """Mark a reconciled/created commit PUSHED only after proving it exists upstream."""
    init_files()
    state = load_state()
    if args.plan_hash != state.get("plan_hash"):
        raise RuntimeError("reconcile-push hash does not match the current plan")
    if state.get("status") not in {"COMMITTED", "PUSHED"}:
        raise RuntimeError(f"reconcile-push requires COMMITTED/PUSHED, found {state.get('status')}")
    sha = str(state.get("commit_sha") or "").strip()
    if not sha:
        raise RuntimeError("no recorded commit SHA")
    upstream = git_upstream()
    if not upstream or "/" not in upstream:
        raise RuntimeError("current branch has no configured upstream")
    remote, _branch = upstream.split("/", 1)
    fetch = _git(["fetch", "--quiet", "--prune", remote], check=False)
    if fetch.returncode != 0:
        raise RuntimeError(f"could not refresh configured upstream: {fetch.stdout[-3000:]}")
    pushed = _git(["merge-base", "--is-ancestor", sha, upstream], check=False)
    if pushed.returncode != 0:
        raise RuntimeError(f"recorded commit {sha[:12]} is not present on configured upstream {upstream}")
    state["status"] = "PUSHED"
    state["push_upstream"] = upstream
    state["push_reconciled"] = True
    state["pushed_at"] = utc_now()
    save_state(state)
    build_completion_report(state, list((state.get("final_qualification") or {}).get("gates") or []))
    live_write(f"reconciled upstream {upstream} containing commit {sha[:12]}", "COMPLETE")
    print(tui.reconcile_card(
        title="PUSH RECONCILED", plan_hash=str(state.get("plan_hash") or ""),
        commit=sha, upstream=upstream, detail="Configured upstream contains the recorded commit",
    ))
    return 0


def init_files() -> None:
    RALPH.mkdir(parents=True, exist_ok=True)
    RECOVERY.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)
    EVENTS.touch(exist_ok=True)
    USAGE_LEDGER.touch(exist_ok=True)
    if not STATE.exists():
        save_state(default_state())
    if not PLAN.exists():
        PLAN.write_text("# RALPH-Lite Plan\n\nNo plan proposed yet.\n", encoding="utf-8")
    if not IDEAS.exists():
        IDEAS.write_text("# RALPH-Lite Ideas Bucket\n\n", encoding="utf-8")
    if not JOURNAL.exists():
        JOURNAL.write_text("# RALPH-Lite Loop Journal\n\n", encoding="utf-8")
    if not LIVE.exists():
        LIVE.write_text("# RALPH-Lite Live Trace\n", encoding="utf-8")
    if not CONTEXT.exists():
        save_context(default_context())
    if not POLICY.exists():
        raise RuntimeError("missing tracked authority file .ralph/policy.md")
    bootstrap_context_from_journal(load_state())


def append_journal(loop_no: int, step_no: int, phase: str, result: str, *, summary: str = "", files: Iterable[str] = (), gates: Iterable[str] = (), fingerprint: str | None = None, repair: int = 0, ideas: Iterable[str] = (), next_action: str = "", change_class: str = "control-event", stats: dict | None = None) -> None:
    ideas = list(ideas)
    stats = dict(stats or {})
    gate_times = stats.get("gate_durations") or {}
    input_tokens = int(stats.get("input_tokens") or 0)
    cached_tokens = int(stats.get("cached_input_tokens") or 0)
    noncached = max(0, input_tokens - cached_tokens)
    cache_ratio = (cached_tokens / input_tokens * 100.0) if input_tokens else 0.0
    efficiency = efficiency_findings(stats) if stats else []
    lines = [
        f"## Loop {loop_no:04d} — {utc_now()}", "",
        f"- Plan step: {step_no}", f"- Phase: {phase}", f"- Result: {result}", f"- Change class: {change_class}", f"- Repair attempt: {repair}",
        f"- Failure fingerprint: `{fingerprint or '-'}`", f"- Files changed: {', '.join(files) if files else '-'}",
        f"- Gates: {'; '.join(gates) if gates else '-'}", f"- Summary: {summary or '-'}",
        f"- Ideas captured: {len(ideas)}", f"- Next action: {next_action or '-'}",
    ]
    if stats:
        lines += [
            f"- Duration: {float(stats.get('duration_seconds') or 0):.1f}s",
            f"- Codex duration: {float(stats.get('codex_seconds') or 0):.1f}s",
            f"- Commands executed: {int(stats.get('commands_executed') or 0)}",
            f"- Files inspected (reported): {int(stats.get('files_inspected') or 0)}",
            f"- Codex cumulative tokens: input={input_tokens} cached={cached_tokens} non-cached={noncached} cache-write={int(stats.get('cache_write_input_tokens') or 0)} output={int(stats.get('output_tokens') or 0)} reasoning={int(stats.get('reasoning_output_tokens') or 0)} cache={cache_ratio:.1f}%",
            f"- Efficiency budget: {'WARN' if efficiency else 'PASS'}",
            f"- Efficiency findings: {'; '.join(efficiency) if efficiency else '-'}",
            f"- Gate durations: {'; '.join(f'{name}={seconds:.1f}s' for name, seconds in gate_times.items()) if gate_times else '-'}",
            f"- First pass: {'yes' if result == 'PASS' and repair == 0 else 'no'}",
        ]
    lines.append("")
    with JOURNAL.open("a", encoding="utf-8") as handle:
        handle.write("\n".join(lines))


def live_write(message: str, category: str = "RALPH") -> None:
    """Write a plain durable trace plus a colour-aware operator event."""
    RALPH.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().astimezone().strftime("%H:%M:%S")
    clean = " ".join(str(message).split())
    plain = f"[{stamp}] {category:<8} {clean}"
    print(tui.event_line(category, clean, stamp=stamp), flush=True)
    with LIVE.open("a", encoding="utf-8") as handle:
        handle.write(plain + "\n")
    tui.write_event(EVENTS, category, clean)


def _clip(text: str, limit: int = 500) -> str:
    compact = " ".join(str(text).split())
    return compact if len(compact) <= limit else compact[: limit - 3] + "..."


def codex_event_messages(event: dict) -> list[tuple[str, str]]:
    """Translate Codex JSONL events into concise, stable operator messages."""
    event_type = str(event.get("type") or "")
    item = event.get("item") if isinstance(event.get("item"), dict) else {}
    item_type = str(item.get("type") or "")
    messages: list[tuple[str, str]] = []

    if event_type == "thread.started":
        messages.append(("CODEX", f"thread started {event.get('thread_id', '-') }"))
    elif event_type == "turn.started":
        messages.append(("CODEX", "turn started"))
    elif event_type == "item.started" and item_type == "command_execution":
        command = str(item.get("command") or "")
        first = command.strip().split(maxsplit=1)[0] if command.strip() else ""
        read_tools = {"cat", "sed", "grep", "rg", "head", "tail", "less", "find", "ls", "stat", "git"}
        category = "READ" if first in read_tools and not any(token in command for token in (" >", ">>", " apply", " commit", " add ", " rm ", " mv ")) else "RUN"
        messages.append((category, _clip(command)))
    elif event_type == "item.completed":
        if item_type == "reasoning":
            messages.append(("THINK", _clip(item.get("text", ""), 800)))
        elif item_type == "command_execution":
            status = str(item.get("status") or "completed").upper()
            code = item.get("exit_code")
            command = str(item.get("command") or "")
            failed = status == "FAILED" or (code is not None and int(code) != 0)
            validation = any(token in command for token in ("unittest", "pytest", "py_compile", "validate.py", "audit.py"))
            if failed:
                messages.append(("FAIL", f"exit={code} · {_clip(command)}"))
                if item.get("aggregated_output"):
                    messages.append(("OUTPUT", _clip(str(item["aggregated_output"])[-1200:], 800)))
            elif validation:
                messages.append(("PASS", f"exit={code if code is not None else 0} · {_clip(command)}"))
        elif item_type == "file_change":
            changes = item.get("changes") if isinstance(item.get("changes"), list) else []
            if not changes:
                messages.append(("EDIT", "file change completed"))
            for change in changes:
                if not isinstance(change, dict):
                    continue
                kind = str(change.get("kind") or "update").lower()
                category = {"add": "CREATE", "create": "CREATE", "delete": "DELETE", "remove": "DELETE", "rename": "MOVE", "move": "MOVE"}.get(kind, "EDIT")
                messages.append((category, str(change.get("path") or "?")))
        elif item_type == "error":
            messages.append(("WARN", _clip(item.get("message", "Codex item error"), 800)))
    elif event_type == "turn.completed":
        usage = event.get("usage") if isinstance(event.get("usage"), dict) else {}
        messages.append((
            "USAGE",
            "cumulative_input={input} cached={cached} cache_write={cache_write} output={output} reasoning={reasoning}".format(
                input=usage.get("input_tokens", 0),
                cached=usage.get("cached_input_tokens", 0),
                cache_write=usage.get("cache_write_input_tokens", 0),
                output=usage.get("output_tokens", 0),
                reasoning=usage.get("reasoning_output_tokens", 0),
            ),
        ))
    elif event_type == "turn.failed":
        error = event.get("error") if isinstance(event.get("error"), dict) else {}
        messages.append(("ERROR", _clip(error.get("message", "Codex turn failed"), 800)))
    elif event_type == "error":
        messages.append(("ERROR", _clip(event.get("message", "Codex stream error"), 800)))
    return messages


def append_ideas(loop_no: int, ideas: Iterable[str]) -> None:
    ideas = [x.strip() for x in ideas if x and x.strip()]
    if not ideas:
        return
    with IDEAS.open("a", encoding="utf-8") as handle:
        for idea in ideas:
            handle.write(f"- [{utc_now()}] loop {loop_no}: {idea}\n")


def file_hash(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def repo_snapshot() -> dict[str, str]:
    snapshot: dict[str, str] = {}
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT)
        if any(part in EXCLUDED_DIRS for part in rel.parts):
            continue
        try:
            snapshot[rel.as_posix()] = file_hash(path)
        except OSError:
            continue
    return snapshot


def changed_paths(before: dict[str, str], after: dict[str, str]) -> list[str]:
    return sorted(path for path in set(before) | set(after) if before.get(path) != after.get(path))


def authority_snapshot() -> dict[Path, bytes | None]:
    runtime_paths = {STATE, PLAN, IDEAS, JOURNAL, POLICY, CONTEXT}
    tooling_paths = {ROOT / rel for rel in TOOLING_PATHS if not rel.startswith(".ralph/")}
    paths = runtime_paths | tooling_paths
    return {path: path.read_bytes() if path.exists() else None for path in paths}


def _normalize_repo_path(value: str) -> str:
    path = str(value or "").strip().replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path


def authority_changed_paths(snapshot: dict[Path, bytes | None]) -> list[str]:
    changed: list[str] = []
    for path, content in snapshot.items():
        current = path.read_bytes() if path.exists() else None
        if current == content:
            continue
        try:
            changed.append(path.relative_to(ROOT).as_posix())
        except ValueError:
            changed.append(str(path))
    return sorted(changed)


def self_hosting_grant_allows(state: dict, step_no: int, changed: Iterable[str]) -> tuple[bool, str]:
    paths = sorted({_normalize_repo_path(str(path)) for path in changed if str(path).strip()})
    if not paths:
        return False, "no authority paths changed"
    grant = state.get("self_hosting_grant") if isinstance(state.get("self_hosting_grant"), dict) else {}
    if not grant:
        return False, "no active self-hosting grant"
    if str(grant.get("plan_hash") or "") != str(state.get("plan_hash") or ""):
        return False, "self-hosting grant plan hash does not match active plan"
    if int(grant.get("step") or 0) != int(step_no):
        return False, "self-hosting grant is not for the current step"
    allowed = {str(path) for path in grant.get("paths") or []}
    runtime = [path for path in paths if path == ".ralph" or path.startswith(".ralph/")]
    if runtime:
        return False, f"RALPH runtime authority is never self-hosting writable: {runtime}"
    protected = [path for path in paths if is_protected_path(path)]
    if protected:
        return False, f"protected paths are never self-hosting writable: {protected}"
    non_tooling = [path for path in paths if not is_tooling_path(path)]
    if non_tooling:
        return False, f"self-hosting grant applies only to RALPH tooling paths: {non_tooling}"
    extra = sorted(set(paths) - allowed)
    if extra:
        return False, f"authority changes exceed exact self-hosting grant: {extra}"
    return True, f"exact self-hosting grant permits {paths}"


def protected_snapshot() -> dict[Path, bytes]:
    paths: list[Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        rel = path.relative_to(ROOT).as_posix()
        if is_protected_path(rel):
            paths.append(path)
    return {path: path.read_bytes() for path in paths}


def restore_protected(snapshot: dict[Path, bytes], changed: Iterable[str] = ()) -> None:
    original = set(snapshot)
    for rel in changed:
        path = ROOT / rel
        if path not in original and is_protected_path(rel):
            path.unlink(missing_ok=True)
    for path, content in snapshot.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)


def restore_authority(snapshot: dict[Path, bytes | None]) -> None:
    for path, content in snapshot.items():
        if content is None:
            path.unlink(missing_ok=True)
        else:
            path.write_bytes(content)


def authority_changed(snapshot: dict[Path, bytes | None]) -> bool:
    for path, content in snapshot.items():
        current = path.read_bytes() if path.exists() else None
        if current != content:
            return True
    return False


def is_protected_path(path: str) -> bool:
    name = Path(path).name
    return (
        path == ".env"
        or path.startswith(".env.")
        or path in PROTECTED_EXACT
        or path.startswith(PROTECTED_PREFIXES)
        or path.startswith(PROTECTED_DIR_PREFIXES)
        or name.endswith(PROTECTED_SUFFIXES)
    )


def is_tooling_path(path: str) -> bool:
    return path in TOOLING_PATHS


def classify_changes(paths: Iterable[str]) -> str:
    paths = list(paths)
    if not paths:
        return "no-code-change"
    tooling = any(is_tooling_path(path) for path in paths)
    product = any(not is_tooling_path(path) for path in paths)
    if tooling and product:
        return "mixed-tooling-product"
    if tooling:
        return "ralph-tooling"
    return "product-development"


def test_policy_violation(
    before: dict[str, str],
    after: dict[str, str],
    policy: str,
    *,
    state: dict | None = None,
    step_no: int | None = None,
) -> list[str]:
    """Enforce test authority against the approval-time baseline, not retry-loop state.

    A test created by the approved plan remains editable during later repair/retry
    loops under add-only policy.  Tests that existed when the plan was approved
    remain protected.  Explicit human steering may authorize one exact new test
    path without granting authority over existing tests.
    """
    changed = [p for p in changed_paths(before, after) if p == "tests" or p.startswith("tests/")]
    if policy == "modify":
        return []
    allowed = steering_allowed_new_tests(state or {}, int(step_no or 0)) if state else set()
    if policy == "none":
        return [p for p in changed if p not in allowed]
    violations: list[str] = []
    for path in changed:
        if path in allowed:
            continue
        if state is not None:
            if plan_baseline_path_kind(state, path) == "absent":
                continue
            violations.append(path)
        elif path in before:
            violations.append(path)
    return violations


def normalize_failure(text: str) -> str:
    useful = []
    for line in text.splitlines():
        stripped = line.strip()
        if re.search(r"^(FAIL|ERROR):|AssertionError|Traceback|FAILED|ERRORS?\b", stripped):
            useful.append(stripped)
    if not useful:
        useful = [line.strip() for line in text.splitlines() if line.strip()][-20:]
    normalized = "\n".join(useful)
    normalized = re.sub(r"0x[0-9a-fA-F]+", "0xADDR", normalized)
    normalized = re.sub(r"/tmp/[^\s:]+", "/tmp/TMP", normalized)
    normalized = re.sub(r"\b\d+\.\d+s\b", "TIME", normalized)
    return normalized[:8000]


def failure_fingerprint(gate: str, output: str, returncode: int) -> str:
    payload = f"{gate}\n{returncode}\n{normalize_failure(output)}".encode()
    return hashlib.sha256(payload).hexdigest()[:20]


def run_process(args: list[str], *, cwd: Path = ROOT, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, input=input_text, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def empty_codex_metrics() -> dict:
    return {
        "commands_executed": 0,
        "input_tokens": 0,
        "cached_input_tokens": 0,
        "cache_write_input_tokens": 0,
        "output_tokens": 0,
        "reasoning_output_tokens": 0,
    }


def update_codex_metrics(metrics: dict, event: dict) -> None:
    event_type = str(event.get("type") or "")
    item = event.get("item") if isinstance(event.get("item"), dict) else {}
    if event_type == "item.completed" and str(item.get("type") or "") == "command_execution":
        metrics["commands_executed"] = int(metrics.get("commands_executed") or 0) + 1
    if event_type == "turn.completed":
        usage = event.get("usage") if isinstance(event.get("usage"), dict) else {}
        for key in (
            "input_tokens", "cached_input_tokens", "cache_write_input_tokens",
            "output_tokens", "reasoning_output_tokens",
        ):
            metrics[key] = int(usage.get(key) or 0)


def stream_codex_process(args: list[str]) -> tuple[int, str, dict]:
    """Run Codex while rendering its JSONL event stream for the operator."""
    proc = subprocess.Popen(
        args, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1,
    )
    captured: list[str] = []
    metrics = empty_codex_metrics()
    assert proc.stdout is not None
    for raw in proc.stdout:
        captured.append(raw)
        stripped = raw.strip()
        if not stripped:
            continue
        try:
            event = json.loads(stripped)
        except json.JSONDecodeError:
            live_write(_clip(stripped, 800), "CODEX")
            continue
        if isinstance(event, dict):
            update_codex_metrics(metrics, event)
            for category, message in codex_event_messages(event):
                if message:
                    live_write(message, category)
    return proc.wait(), "".join(captured), metrics


def is_bwrap_bootstrap_failure(output: str) -> bool:
    """Return True only for the known Codex Linux bubblewrap bootstrap failure."""
    text = output.lower()
    return "bwrap:" in text and any(
        marker in text
        for marker in (
            "failed rtm_newaddr",
            "setting up uid map: permission denied",
            "write failed /proc/self/uid_map",
        )
    )


def codex_environment_error_output(output: str) -> str:
    """Extract only process/turn errors eligible for sandbox classification."""
    errors: list[str] = []
    for raw in output.splitlines():
        stripped = raw.strip()
        if not stripped:
            continue
        try:
            event = json.loads(stripped)
        except json.JSONDecodeError:
            if is_bwrap_bootstrap_failure(stripped):
                errors.append(stripped)
            continue
        if not isinstance(event, dict):
            continue
        event_type = str(event.get("type") or "")
        if event_type == "turn.failed":
            error = event.get("error") if isinstance(event.get("error"), dict) else {}
            message = str(error.get("message") or "").strip()
            if message:
                errors.append(message)
        elif event_type == "error":
            message = str(event.get("message") or "").strip()
            if message:
                errors.append(message)
    return "\n".join(errors)


class EnvironmentBlocked(RuntimeError):
    """Environment prerequisite failed; metrics are retained if a turn had already started."""

    def __init__(self, message: str, metrics: dict | None = None):
        super().__init__(message)
        self.metrics = dict(metrics or {})


def sandbox_prefix_from_preflights(default_returncode: int, default_output: str) -> list[str]:
    """Accept only the supported default sandbox backend for workspace-write."""
    if default_returncode == 0 and not is_bwrap_bootstrap_failure(default_output):
        return ["codex"]
    detail = default_output[-1200:] or f"exit={default_returncode}"
    raise EnvironmentBlocked(
        "Codex default Linux sandbox preflight failed; fix the host sandbox prerequisites before running RALPH: "
        + detail
    )


def codex_command_prefix() -> list[str]:
    """Return the process-local Codex prefix after a zero-model sandbox preflight."""
    global _CODEX_PREFIX
    if _CODEX_PREFIX is not None:
        return list(_CODEX_PREFIX)
    if shutil.which("codex") is None:
        raise EnvironmentBlocked("codex CLI is not installed or not on PATH")

    default = run_process(["codex", "sandbox", "--", "/bin/true"])
    _CODEX_PREFIX = sandbox_prefix_from_preflights(default.returncode, default.stdout)
    live_write("sandbox preflight=PASS backend=default", "SANDBOX")
    return list(_CODEX_PREFIX)


def run_codex(prompt: str, schema: dict, sandbox: str, *, context: str = "Codex") -> dict:
    prefix = codex_command_prefix()
    with tempfile.TemporaryDirectory(prefix="ralph-lite-") as temp_dir:
        schema_path = Path(temp_dir) / "schema.json"
        output_path = Path(temp_dir) / "result.json"
        schema_path.write_text(json.dumps(schema), encoding="utf-8")
        command = [
            *prefix, "exec", "--ephemeral", "--json", "--sandbox", sandbox,
            "--output-schema", str(schema_path), "-o", str(output_path), prompt,
        ]
        live_write(f"{context} · sandbox={sandbox} backend=default", "CODEX")
        started = time.monotonic()
        returncode, output, metrics = stream_codex_process(command)
        metrics["codex_seconds"] = time.monotonic() - started

        environment_error = codex_environment_error_output(output)
        if is_bwrap_bootstrap_failure(environment_error):
            raise EnvironmentBlocked(
                "Codex default sandbox failed inside the model turn; automatic legacy fallback is disabled: "
                + normalize_failure(environment_error)[-1200:],
                metrics=metrics,
            )
        if returncode != 0:
            raise RuntimeError(f"codex exec failed ({returncode}):\n{output[-6000:]}")
        try:
            result = json.loads(output_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"codex returned invalid structured output: {exc}") from exc
        if isinstance(result, dict) and result.get("summary"):
            live_write(_clip(result["summary"], 800), "SUMMARY")
        if isinstance(result, dict):
            result["_ralph_metrics"] = metrics
        return result


def qualification_gates() -> list[tuple[str, list[str]]]:
    py_files = sorted(str(p.relative_to(ROOT)) for base in (ROOT / "app", ROOT / "scripts") if base.exists() for p in base.glob("*.py"))
    return [
        ("python-compile", [sys.executable, "-m", "py_compile", *py_files]),
        ("unit-tests", [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"]),
        ("ux-validator", [sys.executable, "scripts/ux_validate.py"]),
    ]


def run_gates() -> tuple[bool, list[str], str | None, str, dict[str, float]]:
    gate_log: list[str] = []
    durations: dict[str, float] = {}
    for name, command in qualification_gates():
        live_write(f"running {name}", "GATE")
        started = time.monotonic()
        proc = run_process(command)
        durations[name] = time.monotonic() - started
        outcome = "PASS" if proc.returncode == 0 else "FAIL"
        gate_log.append(f"{name}={outcome}")
        live_write(f"{name}={outcome} duration={durations[name]:.1f}s", "GATE")
        if proc.returncode != 0:
            fp = failure_fingerprint(name, proc.stdout, proc.returncode)
            live_write(f"{name} failure fingerprint={fp}", "FAIL")
            return False, gate_log, fp, proc.stdout[-12000:], durations
    return True, gate_log, None, "", durations


def loop_stats(loop_started: float, result: dict | None = None, *, gate_durations: dict[str, float] | None = None, repair: int = 0) -> dict:
    result = result if isinstance(result, dict) else {}
    metrics = dict(result.get("_ralph_metrics") or {})
    reported = result.get("context") if isinstance(result.get("context"), dict) else {}
    metrics.update({
        "duration_seconds": time.monotonic() - loop_started,
        "gate_durations": dict(gate_durations or {}),
        "files_inspected": len(list(reported.get("files_inspected") or [])),
        "repair": repair,
    })
    return metrics


def efficiency_findings(stats: dict | None) -> list[str]:
    """Return stable post-loop efficiency findings without interrupting a live edit."""
    stats = dict(stats or {})
    commands = int(stats.get("commands_executed") or 0)
    files = int(stats.get("files_inspected") or 0)
    cumulative = int(stats.get("input_tokens") or 0)
    cached = int(stats.get("cached_input_tokens") or 0)
    noncached = max(0, cumulative - cached)
    findings: list[str] = []
    if commands > EFFICIENCY_MAX_COMMANDS:
        findings.append(f"commands {commands}>{EFFICIENCY_MAX_COMMANDS}")
    if files > EFFICIENCY_MAX_REPORTED_FILES:
        findings.append(f"reported-files {files}>{EFFICIENCY_MAX_REPORTED_FILES}")
    if cumulative > EFFICIENCY_MAX_CUMULATIVE_INPUT:
        findings.append(f"cumulative-input {cumulative}>{EFFICIENCY_MAX_CUMULATIVE_INPUT}")
    if noncached > EFFICIENCY_MAX_NONCACHED_INPUT:
        findings.append(f"non-cached-input {noncached}>{EFFICIENCY_MAX_NONCACHED_INPUT}")
    return findings


def _step_explicitly_delegates_human_gate(step: dict | None) -> bool:
    """Return true only when the approved step explicitly delegates a human gate.

    This is intentionally conservative.  A model-authored summary may never create
    new human authority by itself; the approved plan must already say that missing
    runtime/operator evidence stops at BLOCKED_HUMAN.
    """
    if not isinstance(step, dict):
        return False
    text = " ".join([
        str(step.get("objective") or ""),
        *(str(value) for value in (step.get("acceptance") or [])),
    ]).lower()
    return (
        "blocked_human" in text
        and any(marker in text for marker in ("operator", "runtime", "evidence", "human-owned", "human owned"))
    )


def _declared_human_block(result: dict) -> str:
    summary = str(result.get("summary") or "").strip()
    match = re.match(r"^BLOCKED_HUMAN\s*:\s*(.*)$", summary, flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    detail = match.group(1).strip()
    return detail or "Approved step requires human-owned evidence before it can advance"


def codex_requires_human_before_gates(result: dict, step: dict | None = None) -> tuple[bool, str]:
    """Only approved human/policy blockers may pre-empt controller qualification.

    Local/focused validation is advisory: the deterministic controller owns the
    authoritative qualification gates and must be allowed to run them.  However,
    if the approved step explicitly delegates missing operator/runtime evidence to
    BLOCKED_HUMAN, a model result that explicitly declares BLOCKED_HUMAN must not
    be laundered into PASS merely because generic compile/unit/UX gates succeed.
    """
    blocker_class = str(result.get("blocker_class") or "none")
    blockers = [str(item).strip() for item in (result.get("blockers") or []) if str(item).strip()]

    declared = _declared_human_block(result)
    if declared and _step_explicitly_delegates_human_gate(step):
        return True, declared

    if blocker_class in {"validation-only", "continuation"}:
        return False, ""
    if blocker_class in {"human-decision", "policy"} or result.get("needs_human"):
        return True, "; ".join(blockers or [declared or "Codex requested human review"])
    if blockers:
        return True, "; ".join(blockers)
    return False, ""


def codex_requests_continuation(result: dict, step: dict | None = None) -> tuple[bool, str]:
    """Recognise ordinary bounded continuation without manufacturing a human gate.

    A model turn may exhaust its per-turn command/inspection budget while staying
    entirely inside the approved step. That is controller scheduling, not new
    human authority. The explicit continuation class is preferred; a narrow text
    fallback covers the false-human-gate wording observed in live use.
    """
    blocker_class = str(result.get("blocker_class") or "none")
    blockers = [str(item).strip() for item in (result.get("blockers") or []) if str(item).strip()]
    summary = str(result.get("summary") or "").strip()
    text = " ".join([summary, *blockers]).lower()

    if _declared_human_block(result) and _step_explicitly_delegates_human_gate(step):
        return False, ""

    if blocker_class == "continuation":
        reason = "; ".join(blockers) or summary or "approved step requires another bounded implementation turn"
        return True, reason

    continuation_markers = (
        "another shell execution",
        "further shell execution",
        "additional shell execution",
        "another model turn",
        "additional model turn",
        "another implementation turn",
        "additional implementation turn",
        "new loop/retry",
        "another loop/retry",
        "command budget",
    )
    authority_markers = (
        "policy violation",
        "protected path",
        "protected-path",
        "secret",
        "credential",
        "operator evidence",
        "runtime evidence",
        "human judgement",
        "human judgment",
        "operator decision",
        "choose between",
    )
    if any(marker in text for marker in continuation_markers) and not any(
        marker in text for marker in authority_markers
    ):
        reason = "; ".join(blockers) or summary or "approved step requires another bounded implementation turn"
        return True, reason
    return False, ""


def reset_failure_epoch_after_human_steer(state: dict) -> dict | None:
    """Start a fresh bounded repair epoch only after genuine retry exhaustion."""
    active = str(state.get("active_failure") or "").strip()
    reason = str(state.get("block_reason") or "").lower()
    if not active or active.lower() not in reason:
        return None
    if "repair attempt" not in reason and "persisted through" not in reason and "exceeded" not in reason:
        return None
    attempts = state.setdefault("failure_attempts", {})
    previous = int(attempts.get(active, 0))
    attempts[active] = 0
    return {"fingerprint": active, "previous_attempts": previous, "new_attempts": 0}


def repair_failure_evidence(state: dict, repair_fp: str | None) -> str:
    """Return bounded authoritative failure evidence for the next repair turn."""
    if not repair_fp:
        return ""
    failure = state.get("last_failure") if isinstance(state.get("last_failure"), dict) else {}
    if str(failure.get("fingerprint") or "") != str(repair_fp):
        return ""
    gates = [str(item) for item in (failure.get("gates") or []) if str(item).strip()]
    output = normalize_failure(str(failure.get("output") or ""))
    parts = [
        "Authoritative controller failure evidence for this repair:",
        f"- fingerprint: {repair_fp}",
    ]
    if gates:
        parts.append("- gates: " + "; ".join(gates))
    if output:
        parts.append("- normalized failure:\n" + output[-3000:])
    parts.append(
        "Repair the failing evidence above first. Do not churn already-green "
        "subsystems merely because they are related to the approved step."
    )
    return "\n".join(parts)


def is_recoverable_validation_block(reason: str) -> bool:
    """Conservative migration check for pre-v0.1.6 validation-only blocks."""
    text = str(reason or "").lower()
    required = ("test", "validation", "command budget", "python")
    return any(marker in text for marker in required) and not any(
        marker in text for marker in ("policy violation", "secret", "credential", "routeros", "human decision")
    )


def git_changed_paths() -> list[str]:
    """Return current tracked/untracked worktree paths without reading file contents."""
    proc = _git(["status", "--porcelain=v1", "-z", "--untracked-files=all"], check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"git status failed ({proc.returncode}): {proc.stdout[-2000:]}")
    entries = proc.stdout.split("\0")
    paths: list[str] = []
    for entry in entries:
        if not entry:
            continue
        payload = entry[3:] if len(entry) >= 4 else ""
        if " -> " in payload:
            payload = payload.split(" -> ", 1)[1]
        payload = payload.strip()
        if payload and payload not in paths:
            paths.append(payload)
    return sorted(paths)


def validate_recovery_paths(paths: Iterable[str], step: dict) -> None:
    paths = list(paths)
    tooling = [path for path in paths if is_tooling_path(path)]
    protected = [path for path in paths if is_protected_path(path)]
    if tooling:
        raise RuntimeError(f"blocked-change recovery refuses RALPH tooling changes: {tooling}")
    if protected:
        raise RuntimeError(f"blocked-change recovery refuses protected paths: {protected}")
    policy = step.get("test_change_policy")
    test_paths = [p for p in paths if p == "tests" or p.startswith("tests/")]
    if policy == "none" and test_paths:
        raise RuntimeError(f"blocked-change recovery violates test policy none: {test_paths}")
    if policy == "add-only":
        state = load_state()
        for path in test_paths:
            if plan_baseline_path_kind(state, path) != "absent":
                raise RuntimeError(f"blocked-change recovery modifies existing test under add-only policy: {path}")


def plan_prompt(goal: str) -> str:
    return f"""You are planning work for ZEN Control under RALPH-Lite. Inspect the repository read-only.
Goal: {goal}
Return exactly 5-10 ordered, concrete implementation steps. Keep steps small enough to implement and qualify independently.
For each step choose test_change_policy: none, add-only, or modify. Prefer add-only; use modify only when modifying existing tests is genuinely required.
Use targeted symbol/range reads instead of broad repository ingestion. Avoid reading docs, README, CHANGELOG, or Git history unless directly needed for the goal.
Do not execute or edit anything. Respect .ralph/policy.md. Put discovered nice-to-have work into later plan steps only if it directly serves the goal; otherwise it belongs in the ideas bucket during execution.
"""


def step_prompt(state: dict, step: dict, repair_fp: str | None, repair_no: int) -> str:
    repair_text = ""
    if repair_fp:
        repair_text = (
            f"\nThis is repair attempt {repair_no} for failure fingerprint {repair_fp}. "
            "Fix the failure without weakening qualification.\n"
            + repair_failure_evidence(state, repair_fp)
        )
    prior = context_handoff(state)
    return f"""Execute exactly ONE approved RALPH-Lite plan step in ZEN Control.
Approved plan hash: {state['plan_hash']}
Step {step['id']}: {step['title']}
Objective: {step['objective']}
Acceptance: {json.dumps(step['acceptance'])}
Test-change policy: {step['test_change_policy']}
{repair_text}

Human steering for this approved step (bounded, auditable; does not waive protected-path/security rules):
{json.dumps(steering_for_step(state, int(step['id'])), separators=(',', ':'))}

Compact handoff from the previous successful loop:
{json.dumps(prior, separators=(',', ':'))}

CONTEXT-EFFICIENCY RULES:
- Start from the handoff's relevant_files and accepted_findings; do not rediscover accepted facts unless this step directly invalidates them.
- HARD BUDGET: use at most {PROMPT_COMMAND_BUDGET} shell command executions for this implementation turn. If safe completion genuinely needs another normal implementation/shell turn while remaining inside this approved step, return blocker_class="continuation", needs_human=false, explain the next bounded action in blockers, and stop this turn. The controller will schedule another loop without creating a human gate.
- Batch related reads into one discovery command. Prefer rg -n plus narrow sed/range reads or targeted symbols; do not repeatedly read whole large files.
- Aim for one discovery bundle, one implementation/edit bundle, and no more than two focused validation commands. The external controller runs the full authoritative gates.
- Python command contract: use `python3` (or the repository's explicit interpreter), never bare `python`.
- Failure of a focused/local validation command after implementation is NOT a human blocker. Set blocker_class="validation-only", needs_human=false, record the detail in validation_notes, and return so the controller can run authoritative gates.
- Normally inspect no more than 6-8 relevant files before implementation. If more are genuinely required, stop and request human review rather than expanding silently.
- Do not broadly scan docs/, README.md, CHANGELOG.md, or Git history unless directly necessary for this step.
- Stop discovery once there is enough evidence to implement safely.
- Return context.relevant_files (max 8), context.accepted_findings (max 8), and context.files_inspected (max 16) for the next loop.

Read .ralph/policy.md and obey it. Do not edit any file under .ralph. Do not interact with live RouterOS, secrets, credentials, or external production systems. Stay inside the repository. Do not disable, skip, delete, or weaken qualification to obtain a pass. Make only changes necessary for this step. You may run focused local tests while working, but the external controller will run authoritative gates afterwards.
If you discover useful out-of-scope work, return it in ideas and continue the approved step rather than implementing it.
Use blocker_class="continuation", needs_human=false only for ordinary additional work inside the already-approved step when the current bounded turn is exhausted. Use blocker_class="human-decision" only when genuine human judgement is required and blocker_class="policy" only when safe completion would break policy. In those cases return needs_human=true with blockers. If the APPROVED acceptance explicitly says missing operator/runtime evidence must stop at BLOCKED_HUMAN, treat absent required evidence as blocker_class="human-decision", needs_human=true, and put the exact evidence/action in blockers; never classify that condition as validation-only or continuation. Otherwise use blocker_class="none" (or "validation-only" as described above).
If safe completion requires breaking policy or human judgement, make no speculative workaround: return needs_human=true with blockers.
"""



def configured_codex_model() -> str | None:
    """Read only the configured model name; never retain other Codex config."""
    path = Path.home() / ".codex" / "config.toml"
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return None
    model = data.get("model") if isinstance(data, dict) else None
    return str(model).strip() if isinstance(model, str) and model.strip() else None


def _app_server_send(handle, payload: dict) -> None:
    handle.write(json.dumps(payload, separators=(",", ":")) + "\n")
    handle.flush()


def _app_server_read_response(proc: subprocess.Popen, request_id: int, timeout: float) -> dict:
    """Read line-delimited app-server JSON-RPC until the matching response arrives."""
    assert proc.stdout is not None
    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            remaining = max(0.0, deadline - time.monotonic())
            events = selector.select(remaining)
            if not events:
                break
            line = proc.stdout.readline()
            if not line:
                break
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            if message.get("id") != request_id:
                continue
            if message.get("error"):
                raise RuntimeError(f"Codex app-server request failed: {message['error']}")
            result = message.get("result")
            if not isinstance(result, dict):
                raise RuntimeError("Codex app-server returned an invalid result")
            return result
    finally:
        selector.close()
    stderr = ""
    if proc.poll() is not None and proc.stderr is not None:
        try:
            stderr = proc.stderr.read()[-1200:]
        except OSError:
            pass
    raise RuntimeError(f"timed out waiting for Codex app-server rate limits{': ' + stderr if stderr else ''}")


def query_codex_rate_limits(*, timeout: float = USAGE_APP_SERVER_TIMEOUT_SECONDS) -> dict:
    """Read live ChatGPT/Codex account limits through the supported app-server surface.

    This performs no model turn and deliberately discards account identifiers from the
    returned state. The app-server contract is account/rateLimits/read.
    """
    codex = shutil.which("codex")
    if not codex:
        raise RuntimeError("codex not found")
    proc = subprocess.Popen(
        [codex, "app-server", "--stdio"],
        cwd=ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    try:
        assert proc.stdin is not None
        _app_server_send(proc.stdin, {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "clientInfo": {"name": "ralph-lite", "title": "RALPH-Lite", "version": "0.3.2"},
                "capabilities": {"experimentalApi": True},
            },
        })
        _app_server_read_response(proc, 1, timeout)
        _app_server_send(proc.stdin, {"jsonrpc": "2.0", "method": "initialized", "params": {}})
        _app_server_send(proc.stdin, {
            "jsonrpc": "2.0", "id": 2, "method": "account/rateLimits/read",
            "params": {"supportsLunaReserve": False, "excludeResetCreditDetails": True},
        })
        raw = _app_server_read_response(proc, 2, timeout)
        return normalise_codex_usage(raw, configured_codex_model())
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            try:
                proc.kill()
            except OSError:
                pass


def _usage_window_name(minutes: int | None, fallback: str) -> str:
    if minutes is None:
        return fallback
    if 285 <= minutes <= 315:
        return "5h"
    if 9_576 <= minutes <= 10_584:
        return "weekly"
    if 1_368 <= minutes <= 1_512:
        return "daily"
    return f"{minutes}m"


def normalise_codex_usage(raw: dict, model: str | None = None) -> dict:
    """Reduce the app-server response to non-sensitive quota state used by RALPH."""
    by_id = raw.get("rateLimitsByLimitId") if isinstance(raw.get("rateLimitsByLimitId"), dict) else {}
    fallback = raw.get("rateLimits") if isinstance(raw.get("rateLimits"), dict) else None
    if not by_id and fallback:
        by_id = {str(fallback.get("limitId") or "codex"): fallback}
    windows: list[dict] = []
    plan_type = None
    for limit_id, snapshot in by_id.items():
        if not isinstance(snapshot, dict):
            continue
        if plan_type is None and snapshot.get("planType") is not None:
            plan_type = str(snapshot.get("planType"))
        relevant = str(limit_id).lower() == "codex"
        if model:
            relevant = relevant or snapshot.get("limitName") == model or snapshot.get("normalModelSlug") == model
        if not relevant:
            continue
        for slot in ("primary", "secondary"):
            window = snapshot.get(slot)
            if not isinstance(window, dict) or window.get("usedPercent") is None:
                continue
            try:
                used = float(window["usedPercent"])
            except (TypeError, ValueError):
                continue
            minutes = window.get("windowDurationMins")
            try:
                minutes = int(minutes) if minutes is not None else None
            except (TypeError, ValueError):
                minutes = None
            reset = window.get("resetsAt")
            try:
                reset = int(reset) if reset is not None else None
            except (TypeError, ValueError):
                reset = None
            windows.append({
                "limit_id": str(limit_id),
                "name": _usage_window_name(minutes, slot),
                "slot": slot,
                "used_percent": max(0.0, min(100.0, used)),
                "remaining_percent": max(0.0, min(100.0, 100.0 - used)),
                "window_minutes": minutes,
                "resets_at": reset,
            })
    reset_summary = raw.get("rateLimitResetCredits") if isinstance(raw.get("rateLimitResetCredits"), dict) else {}
    available_resets = reset_summary.get("availableCount")
    try:
        available_resets = int(available_resets) if available_resets is not None else None
    except (TypeError, ValueError):
        available_resets = None
    return {
        "captured_at": utc_now(),
        "model": model,
        "plan_type": plan_type,
        "ordinary_usage_allowed": raw.get("ordinaryUsageAllowed") if isinstance(raw.get("ordinaryUsageAllowed"), bool) else None,
        "windows": windows,
        "available_reset_credits": available_resets,
    }


def codex_usage_guard(snapshot: dict, reserve_percent: float = USAGE_RESERVE_PERCENT) -> tuple[str, list[str]]:
    """Return SAFE, PAUSE, or UNKNOWN using backend authority plus visible windows."""
    ordinary = snapshot.get("ordinary_usage_allowed")
    windows = snapshot.get("windows") if isinstance(snapshot.get("windows"), list) else []
    if ordinary is False:
        return "PAUSE", ["backend ordinary usage is not allowed"]
    if ordinary is None:
        return "UNKNOWN", ["backend ordinaryUsageAllowed is unavailable"]
    if not windows:
        return "UNKNOWN", ["no relevant Codex rate-limit windows were returned"]
    low = [w for w in windows if float(w.get("remaining_percent", 100.0)) <= reserve_percent]
    if low:
        return "PAUSE", [f"{w.get('name', 'usage')} remaining {float(w.get('remaining_percent', 0.0)):.1f}% <= {reserve_percent:.1f}% reserve" for w in low]
    return "SAFE", []


def usage_poll_delay(snapshot: dict, default_seconds: int = USAGE_POLL_SECONDS) -> int:
    now = int(dt.datetime.now(dt.timezone.utc).timestamp())
    resets = [int(w["resets_at"]) for w in snapshot.get("windows", []) if isinstance(w, dict) and isinstance(w.get("resets_at"), int) and int(w["resets_at"]) > now]
    if not resets:
        return max(15, default_seconds)
    return max(15, min(default_seconds, min(resets) - now + 5))


def _format_reset(epoch: int | None) -> str:
    if not isinstance(epoch, int):
        return "unknown"
    return dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")


def usage_snapshot_line(snapshot: dict) -> str:
    windows = snapshot.get("windows") if isinstance(snapshot.get("windows"), list) else []
    if not windows:
        return "limits=unavailable"
    return " ".join(f"{w['name']}={w['remaining_percent']:.1f}%left reset={_format_reset(w.get('resets_at'))}" for w in windows)


def record_usage_pause(state: dict, snapshot: dict, findings: list[str]) -> None:
    state["status"] = "PAUSED_USAGE_LIMIT"
    state["block_reason"] = "; ".join(findings) or "Codex usage reserve reached"
    state["codex_usage"] = snapshot
    state["usage_pause"] = {
        "recorded_at": utc_now(),
        "reserve_percent": USAGE_RESERVE_PERCENT,
        "reason": state["block_reason"],
        "snapshot": snapshot,
    }
    save_state(state)
    with JOURNAL.open("a", encoding="utf-8") as handle:
        handle.write(
            f"## Usage pause — {utc_now()}\n\n"
            f"- Plan: `{state.get('plan_hash') or '-'}`\n"
            f"- Step: {state.get('current_step')}\n"
            f"- Reserve: {USAGE_RESERVE_PERCENT:.1f}% remaining\n"
            f"- Reason: {state['block_reason']}\n"
            f"- Snapshot: {usage_snapshot_line(snapshot)}\n"
            "- State: recorded; no new Codex model turn will start until limits recover\n\n"
        )


def ensure_codex_usage_capacity(state: dict, *, wait: bool = True, poll_seconds: int = USAGE_POLL_SECONDS) -> bool:
    """Guard every model turn; optionally wait and automatically resume after reset."""
    was_paused = state.get("status") == "PAUSED_USAGE_LIMIT"
    while True:
        try:
            snapshot = query_codex_rate_limits()
            guard, findings = codex_usage_guard(snapshot)
        except Exception as exc:
            snapshot = {"captured_at": utc_now(), "model": configured_codex_model(), "plan_type": None, "ordinary_usage_allowed": None, "windows": [], "available_reset_credits": None}
            guard, findings = "UNKNOWN", [f"rate-limit read failed: {exc}"]
        state["codex_usage"] = snapshot
        if guard == "SAFE":
            state["usage_pause"] = None
            state["block_reason"] = None
            if state.get("status") == "PAUSED_USAGE_LIMIT":
                state["status"] = "APPROVED"
                live_write(f"Codex limits recovered; resuming approved plan · {usage_snapshot_line(snapshot)}", "USAGE")
                with JOURNAL.open("a", encoding="utf-8") as handle:
                    handle.write(f"## Usage resumed — {utc_now()}\n\n- Snapshot: {usage_snapshot_line(snapshot)}\n- Next action: continue approved plan\n\n")
            save_state(state)
            return True
        if not was_paused or state.get("status") != "PAUSED_USAGE_LIMIT":
            record_usage_pause(state, snapshot, findings)
            was_paused = True
        detail = "; ".join(findings)
        live_write(f"Codex usage guard={guard}: {detail} · {usage_snapshot_line(snapshot)}", "USAGE")
        if not wait:
            print(f"PAUSED_USAGE plan={state.get('plan_hash') or '-'} step={state.get('current_step')} reason={detail}")
            return False
        delay = usage_poll_delay(snapshot, poll_seconds)
        live_write(f"waiting {delay}s before zero-model rate-limit recheck; Ctrl-C is safe because state is recorded", "WAIT")
        try:
            time.sleep(delay)
        except KeyboardInterrupt:
            print("PAUSED_USAGE state recorded; rerun `python3 scripts/ralph.py run` to continue waiting/resume")
            return False


def _usage_metric_row(metrics: dict | None) -> dict[str, int]:
    metrics = dict(metrics or {})
    return {
        "input_tokens": int(metrics.get("input_tokens") or 0),
        "cached_input_tokens": int(metrics.get("cached_input_tokens") or 0),
        "cache_write_input_tokens": int(metrics.get("cache_write_input_tokens") or 0),
        "output_tokens": int(metrics.get("output_tokens") or 0),
        "reasoning_output_tokens": int(metrics.get("reasoning_output_tokens") or 0),
    }


def append_usage_ledger(
    metrics: dict | None,
    *,
    plan_hash_value: str | None,
    goal: str = "",
    scope: str,
    loop: int | None = None,
    step: int | None = None,
    phase: str = "",
) -> None:
    """Persist one completed Codex turn for reset-aware and per-plan accounting.

    The ledger records only token counters and bounded plan metadata. It does not
    contain prompts, model output, credentials, account identifiers, or source.
    """
    usage = _usage_metric_row(metrics)
    if not any(usage.values()):
        return
    RALPH.mkdir(parents=True, exist_ok=True)
    row = {
        "schema": "zen_ralph_usage_turn_v1",
        "recorded_at": utc_now(),
        "epoch": int(dt.datetime.now(dt.timezone.utc).timestamp()),
        "plan_hash": str(plan_hash_value or "") or None,
        "goal": " ".join(str(goal or "").split())[:240],
        "scope": str(scope or "unknown")[:40],
        "loop": int(loop) if loop is not None else None,
        "step": int(step) if step is not None else None,
        "phase": str(phase or "")[:40],
        **usage,
    }
    with USAGE_LEDGER.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")
    try:
        if USAGE_LEDGER.stat().st_size > 8 * 1024 * 1024:
            rows = USAGE_LEDGER.read_text(encoding="utf-8", errors="replace").splitlines()[-USAGE_LEDGER_MAX_ROWS:]
            tmp = USAGE_LEDGER.with_suffix(".tmp")
            tmp.write_text("\n".join(rows) + ("\n" if rows else ""), encoding="utf-8")
            os.replace(tmp, USAGE_LEDGER)
    except OSError:
        pass


def usage_ledger_rows(limit: int = USAGE_LEDGER_MAX_ROWS) -> list[dict]:
    if not USAGE_LEDGER.exists():
        return []
    rows: list[dict] = []
    for raw in USAGE_LEDGER.read_text(encoding="utf-8", errors="replace").splitlines()[-max(1, int(limit)):]:
        try:
            item = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict) and item.get("schema") == "zen_ralph_usage_turn_v1":
            rows.append(item)
    return rows


def _sum_usage_rows(rows: Iterable[dict]) -> dict[str, int]:
    keys = (
        "input_tokens", "cached_input_tokens", "cache_write_input_tokens",
        "output_tokens", "reasoning_output_tokens",
    )
    total = {key: 0 for key in keys}
    count = 0
    for row in rows:
        count += 1
        for key in keys:
            total[key] += int(row.get(key) or 0)
    total["turns"] = count
    total["noncached_input_tokens"] = max(0, total["input_tokens"] - total["cached_input_tokens"])
    return total


def _fallback_current_plan_usage(state: dict) -> dict[str, int]:
    rows: list[dict] = []
    for item in _step_results_from_state(state):
        stats = item.get("stats") if isinstance(item.get("stats"), dict) else {}
        if stats:
            rows.append(stats)
    return _sum_usage_rows(rows)


def usage_ledger_report(state: dict, snapshot: dict | None = None) -> dict:
    """Return reset-aligned token tickers and bounded per-plan consumption."""
    rows = usage_ledger_rows()
    current_hash = str(state.get("plan_hash") or "")
    current_rows = [row for row in rows if str(row.get("plan_hash") or "") == current_hash] if current_hash else []
    current = _sum_usage_rows(current_rows)
    source = "ledger"
    if current_hash and not current_rows:
        current = _fallback_current_plan_usage(state)
        source = "step-results-fallback" if current.get("turns") else "ledger"

    grouped: dict[str, dict] = {}
    for row in rows:
        key = str(row.get("plan_hash") or "unassigned")
        group = grouped.setdefault(key, {"rows": [], "goal": str(row.get("goal") or ""), "last_epoch": 0})
        group["rows"].append(row)
        if row.get("goal"):
            group["goal"] = str(row.get("goal") or "")
        group["last_epoch"] = max(int(group.get("last_epoch") or 0), int(row.get("epoch") or 0))
    plans: list[dict] = []
    for key, group in grouped.items():
        totals = _sum_usage_rows(group["rows"])
        plans.append({
            "plan_hash": None if key == "unassigned" else key,
            "goal": group.get("goal") or "",
            "last_epoch": int(group.get("last_epoch") or 0),
            **totals,
        })
    plans.sort(key=lambda item: int(item.get("last_epoch") or 0), reverse=True)

    windows: list[dict] = []
    now = int(dt.datetime.now(dt.timezone.utc).timestamp())
    for window in (snapshot or {}).get("windows", []) if isinstance((snapshot or {}).get("windows"), list) else []:
        if not isinstance(window, dict):
            continue
        reset = window.get("resets_at")
        minutes = window.get("window_minutes")
        try:
            reset_i = int(reset) if reset is not None else None
            minutes_i = int(minutes) if minutes is not None else None
        except (TypeError, ValueError):
            reset_i, minutes_i = None, None
        start = reset_i - (minutes_i * 60) if reset_i and minutes_i else None
        period_rows = [row for row in rows if start is not None and int(row.get("epoch") or 0) >= start and int(row.get("epoch") or 0) <= now]
        windows.append({**window, "window_started_at": start, "observed_tokens": _sum_usage_rows(period_rows)})

    return {
        "current_plan": current,
        "current_plan_source": source,
        "plans": plans[:20],
        "windows": windows,
        "ledger_rows": len(rows),
        "last_event_at": max((int(row.get("epoch") or 0) for row in rows), default=None),
    }


def _usage_numbers(line: str) -> dict[str, int] | None:
    def number(pattern: str) -> int:
        found = re.search(pattern, line)
        return int(found.group(1)) if found else 0

    input_tokens = number(r"(?:cumulative_)?input=(\d+)")
    if not input_tokens:
        return None
    cached = number(r"cached=(\d+)")
    return {
        "input": input_tokens,
        "cached": cached,
        "noncached": max(0, input_tokens - cached),
        "cache_write": number(r"cache_write=(\d+)"),
        "output": number(r"output=(\d+)"),
        "reasoning": number(r"reasoning=(\d+)"),
    }


def live_usage_scopes() -> dict:
    """Recover implementation-loop and proposal usage without cross-contamination.

    Older traces did not carry an explicit usage scope.  A RALPH ``loop=`` marker
    owns subsequent usage until a PLAN PROPOSAL marker appears.  Proposal turns
    are retained separately and can therefore never overwrite the last real
    implementation loop.
    """
    result = {"implementation": {}, "planning": []}
    if not LIVE.exists():
        return result
    current_loop: int | None = None
    scope = "unscoped"
    for line in LIVE.read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.search(r"\bRALPH\s+loop=(\d+)", line)
        if match:
            current_loop = int(match.group(1))
            scope = "implementation"
            continue
        if " CODEX " in line and "PLAN PROPOSAL" in line:
            current_loop = None
            scope = "planning"
            continue
        if " USAGE " not in line:
            continue
        usage = _usage_numbers(line)
        if usage is None:
            continue
        if scope == "implementation" and current_loop is not None:
            result["implementation"][current_loop] = usage
        elif scope == "planning":
            result["planning"].append(usage)
    return result


def live_usage_by_loop() -> dict[int, dict[str, int]]:
    """Compatibility helper returning implementation-loop usage only."""
    return live_usage_scopes()["implementation"]


def usage_report_data(state: dict, snapshot: dict | None = None) -> dict:
    scoped = live_usage_scopes()
    turns = scoped["implementation"]
    planning_turns = scoped["planning"]
    fields = ("input", "cached", "noncached", "cache_write", "output", "reasoning")
    implementation_total = {field: sum(item.get(field, 0) for item in turns.values()) for field in fields}
    planning_total = {field: sum(item.get(field, 0) for item in planning_turns) for field in fields}
    total = {field: implementation_total[field] + planning_total[field] for field in fields}
    context = load_context()
    raw_context_bytes = len(CONTEXT.read_bytes()) if CONTEXT.exists() else 0
    result = {
        "plan_hash": state.get("plan_hash"),
        "status": state.get("status"),
        "loop_count": state.get("loop_count", 0),
        "observed_codex_turns": len(turns) + len(planning_turns),
        "implementation_codex_turns": len(turns),
        "planning_codex_turns": len(planning_turns),
        "turns": turns,
        "planning_turns": planning_turns,
        "totals": total,
        "implementation_totals": implementation_total,
        "planning_totals": planning_total,
        "cache_ratio_percent": (total["cached"] / total["input"] * 100.0) if total["input"] else 0.0,
        "handoff_context": {
            "bytes": raw_context_bytes,
            "relevant_files": len(context.get("relevant_files") or []),
            "accepted_findings": len(context.get("accepted_findings") or []),
            "last_step": context.get("last_step"),
        },
        "reserve_percent": USAGE_RESERVE_PERCENT,
        "codex_limits": snapshot,
        "ledger": usage_ledger_report(state, snapshot),
    }
    if snapshot:
        guard, findings = codex_usage_guard(snapshot)
        result["guard"] = guard
        result["guard_findings"] = findings
    else:
        result["guard"] = "UNKNOWN"
        result["guard_findings"] = ["live Codex rate limits unavailable"]
    return result


def cmd_usage(args: argparse.Namespace) -> int:
    init_files()
    state = load_state()
    snapshot = None
    error = None
    try:
        snapshot = query_codex_rate_limits()
        if not getattr(args, "no_save", False):
            state["codex_usage"] = snapshot
            save_state(state)
    except Exception as exc:
        error = str(exc)
        cached = state.get("codex_usage")
        snapshot = cached if isinstance(cached, dict) else None
    report = usage_report_data(state, snapshot)
    if args.json:
        if error:
            report["live_limit_error"] = error
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if snapshot else 2
    totals = report["totals"]
    print("RALPH-Lite Context / Usage Report")
    print(
        f"plan={report['plan_hash'] or '-'} status={report['status']} loops={report['loop_count']} "
        f"observed_codex_turns={report['observed_codex_turns']} "
        f"implementation_turns={report['implementation_codex_turns']} planning_turns={report['planning_codex_turns']}"
    )
    print(
        "tokens cumulative: "
        f"input={totals['input']:,} cached={totals['cached']:,} non-cached={totals['noncached']:,} "
        f"output={totals['output']:,} reasoning={totals['reasoning']:,} cache={report['cache_ratio_percent']:.1f}%"
    )
    handoff = report["handoff_context"]
    print(f"handoff context: bytes={handoff['bytes']:,} relevant_files={handoff['relevant_files']} accepted_findings={handoff['accepted_findings']} last_step={handoff['last_step']}")
    if snapshot:
        print(f"codex limits: model={snapshot.get('model') or '-'} plan={snapshot.get('plan_type') or '-'} ordinary_usage_allowed={snapshot.get('ordinary_usage_allowed')}")
        for window in snapshot.get("windows", []):
            headroom = float(window["remaining_percent"]) - USAGE_RESERVE_PERCENT
            print(f"  {window['name']}: {window['remaining_percent']:.1f}% left (reserve {USAGE_RESERVE_PERCENT:.1f}%, headroom {headroom:.1f}pp), resets {_format_reset(window.get('resets_at'))}")
        print(f"guard={report['guard']} findings={'; '.join(report['guard_findings']) if report['guard_findings'] else '-'}")
    else:
        print(f"codex limits: UNAVAILABLE ({error or 'no cached snapshot'})")
    if args.details:
        for loop_no, item in sorted(report["turns"].items()):
            ratio = (item["cached"] / item["input"] * 100.0) if item["input"] else 0.0
            print(f"  loop {loop_no:04d}: input={item['input']:,} non-cached={item['noncached']:,} output={item['output']:,} reasoning={item['reasoning']:,} cache={ratio:.1f}%")
        for index, item in enumerate(report["planning_turns"], start=1):
            ratio = (item["cached"] / item["input"] * 100.0) if item["input"] else 0.0
            print(f"  proposal {index:04d}: input={item['input']:,} non-cached={item['noncached']:,} output={item['output']:,} reasoning={item['reasoning']:,} cache={ratio:.1f}%")
    return 0 if snapshot else 2

def gate_id_for_state(state: dict) -> str:
    """Return the stable operator-facing ID for the currently latched human gate."""
    return f"HG-{int(state.get('loop_count') or 0):04d}-{int(state.get('current_step') or 0):02d}"


def human_gate_resolution_allowed(state: dict) -> tuple[bool, str]:
    """Conservatively decide whether a human-owned gate may advance without Codex retry.

    This is intentionally narrower than BLOCKED_HUMAN itself. Policy/authority failures,
    repair exhaustion, and ordinary agent decisions must be retried or otherwise handled;
    only an approved step that explicitly delegates a runtime/operator evidence condition
    to BLOCKED_HUMAN can be human-confirmed.
    """
    if state.get("status") != "BLOCKED_HUMAN":
        return False, "controller is not BLOCKED_HUMAN"
    if state.get("active_failure"):
        return False, "active implementation failure cannot be human-confirmed"
    plan = state.get("plan") if isinstance(state.get("plan"), dict) else {}
    steps = plan.get("steps") if isinstance(plan.get("steps"), list) else []
    current = int(state.get("current_step") or 0)
    if not (1 <= current <= len(steps)) or not isinstance(steps[current - 1], dict):
        return False, "current approved step is unavailable"
    step = steps[current - 1]
    approval_text = " ".join([
        str(step.get("objective") or ""),
        *(str(item) for item in (step.get("acceptance") or [])),
    ]).lower()
    if "blocked_human" not in approval_text:
        return False, "approved step does not explicitly delegate a BLOCKED_HUMAN condition"
    if not any(marker in approval_text for marker in ("runtime", "operator", "human-owned", "human owned")):
        return False, "approved step does not delegate runtime/operator-owned acceptance"

    block_text = " ".join(str(state.get("block_reason") or "").split()).lower()
    forbidden = (
        "policy violation", "protected path", "controller/tooling authority",
        "approved plan file changed", "repair attempts", "secret", "credential",
    )
    if any(marker in block_text for marker in forbidden):
        return False, "current blocker is policy/authority owned and cannot be human-confirmed"
    return True, "approved runtime/operator gate may be human-confirmed"


def append_human_gate_resolution(state: dict, step: dict, gate_id: str, reason: str, original_block: str) -> None:
    """Append an explicit non-Codex audit record for a resolved human gate."""
    with JOURNAL.open("a", encoding="utf-8") as handle:
        handle.write(
            f"## Human gate {gate_id} resolved — {utc_now()}\n\n"
            f"- Plan: `{state.get('plan_hash')}`\n"
            f"- Plan step: {step.get('id')}\n"
            f"- Result: HUMAN_CONFIRMED\n"
            f"- Original blocker: {original_block or '-'}\n"
            f"- Human evidence/reason: {reason}\n"
            f"- Codex loop incremented: no\n"
            f"- Next action: step {int(step.get('id') or 0) + 1} of approved plan\n\n"
        )


def block(state: dict, reason: str) -> None:
    state["status"] = "BLOCKED_HUMAN"
    state["block_reason"] = reason
    save_state(state)


def block_environment(state: dict, reason: str) -> None:
    state["status"] = "BLOCKED_ENVIRONMENT"
    state["block_reason"] = reason
    save_state(state)


def cmd_init(_: argparse.Namespace) -> int:
    init_files()
    print(f"RALPH-Lite initialized at {RALPH}")
    print("codex=" + (shutil.which("codex") or "NOT FOUND"))
    return 0


def cmd_propose(args: argparse.Namespace) -> int:
    init_files()
    state = load_state()
    if state.get("status") not in {"IDLE", "PLAN_COMPLETE", "PUSHED"}:
        raise RuntimeError(f"cannot propose while status={state.get('status')}; finish or resolve the current plan first")
    plan = run_codex(plan_prompt(args.goal), PLAN_SCHEMA, "read-only", context="PLAN PROPOSAL")
    validate_plan(plan)
    digest = plan_hash(plan)
    append_usage_ledger(
        plan.get("_ralph_metrics") if isinstance(plan, dict) else {},
        plan_hash_value=digest, goal=args.goal, scope="planning", phase="proposal",
    )
    previous_state = dict(state)
    previous_state.pop("proposal_previous_state", None)
    state.update({"status": "AWAITING_APPROVAL", "plan_hash": digest, "plan": plan, "current_step": 1, "failure_attempts": {}, "active_failure": None, "last_failure": None, "last_result": None, "block_reason": None, "proposal_previous_state": previous_state, "recovery_checkpoint": None, "plan_changed_files": [], "plan_owned_files": [], "human_steering": [], "steering_allowed_new_tests": [], "self_hosting_grant": None, "self_hosting_candidate": None, "step_results": [], "final_qualification": None, "commit_sha": None, "commit_reconciled": False, "commit_reconcile_note": None, "push_upstream": None, "push_reconciled": False, "completion_changes": None})
    PLAN.write_text(render_plan(plan), encoding="utf-8")
    save_state(state)
    print(render_plan(plan))
    return 0


def cmd_approve(args: argparse.Namespace) -> int:
    init_files()
    state = load_state()
    if state.get("status") != "AWAITING_APPROVAL" or not state.get("plan"):
        raise RuntimeError("no plan is awaiting approval")
    validate_plan(state["plan"])
    expected = plan_hash(state["plan"])
    if args.plan_hash != expected or state.get("plan_hash") != expected:
        raise RuntimeError("approval hash does not match the proposed plan")
    if PLAN.read_text(encoding="utf-8") != render_plan(state["plan"]):
        raise RuntimeError("plan.md changed after proposal; proposal must be regenerated before approval")
    checkpoint = create_recovery_checkpoint(state)
    state["status"] = "APPROVED"
    state["recovery_checkpoint"] = checkpoint["id"]
    state["plan_changed_files"] = []
    state["plan_owned_files"] = []
    state["human_steering"] = []
    state["steering_allowed_new_tests"] = []
    state["self_hosting_grant"] = None
    state["step_results"] = []
    state.pop("proposal_previous_state", None)
    save_state(state)
    print(tui.box(
        "PLAN APPROVED · RECOVERY CHECKPOINT CREATED",
        [
            f"Plan {expected}",
            f"Steps {len(state['plan']['steps'])}",
            f"Recovery {checkpoint['id']}",
            f"Git ref {checkpoint['ref']}",
            "Execution may now start safely.",
        ],
        tone="green",
    ))
    return 0


def cmd_reject(args: argparse.Namespace) -> int:
    """Reject a pending proposal without granting it execution authority."""
    init_files()
    state = load_state()
    if state.get("status") != "AWAITING_APPROVAL" or not state.get("plan"):
        raise RuntimeError("no plan is awaiting approval")
    expected = plan_hash(state["plan"])
    if args.plan_hash != expected or state.get("plan_hash") != expected:
        raise RuntimeError("rejection hash does not match the proposed plan")

    current_usage = state.get("codex_usage")
    previous = state.get("proposal_previous_state")
    if isinstance(previous, dict) and previous.get("status") in {"IDLE", "PLAN_COMPLETE", "PUSHED"}:
        restored = dict(previous)
        if isinstance(current_usage, dict):
            restored["codex_usage"] = current_usage
        state = restored
        if state.get("plan"):
            PLAN.write_text(render_plan(state["plan"]), encoding="utf-8")
        else:
            PLAN.unlink(missing_ok=True)
        restored_to = state.get("status")
    else:
        # Legacy v0.1.7 proposals did not retain the previous state object.
        # Preserve monotonic loop/accounting history but return to a neutral IDLE
        # state rather than inventing a PLAN_COMPLETE plan that is no longer held.
        loop_count = int(state.get("loop_count") or 0)
        last_efficiency = state.get("last_efficiency")
        fresh = default_state()
        fresh["loop_count"] = loop_count
        if isinstance(last_efficiency, dict):
            fresh["last_efficiency"] = last_efficiency
        if isinstance(current_usage, dict):
            fresh["codex_usage"] = current_usage
        state = fresh
        PLAN.unlink(missing_ok=True)
        restored_to = "IDLE"

    save_state(state)
    with JOURNAL.open("a", encoding="utf-8") as handle:
        handle.write(
            f"## Proposal rejected — {utc_now()}\n\n"
            f"- Proposal: `{expected}`\n"
            f"- Reason: {args.reason}\n"
            f"- Restored controller state: {restored_to}\n"
            "- Execution authority granted: no\n\n"
        )
    print(f"Rejected proposal {expected}; controller state={restored_to}.")
    return 0



def cmd_retire_plan(args: argparse.Namespace) -> int:
    """Human-only retirement of an obsolete approved plan."""
    init_files()
    state = load_state()

    allowed = {
        "APPROVED",
        "BLOCKED_HUMAN",
        "BLOCKED_ENVIRONMENT",
        "PAUSED_USAGE",
        "PAUSED_USAGE_LIMIT",
        "READY_TO_COMMIT",
        "COMMITTED",
    }
    status = str(state.get("status") or "")
    if status not in allowed:
        raise RuntimeError(
            f"retire-plan requires an active approved/blocked plan, found {status}"
        )

    expected = state.get("plan_hash")
    if not expected or args.plan_hash != expected:
        raise RuntimeError("retire-plan hash does not match the active plan")

    reason = " ".join(str(args.reason or "").split())
    if not reason:
        raise RuntimeError("retire-plan requires a non-empty reason")

    old_step = int(state.get("current_step") or 1)
    old_loops = int(state.get("loop_count") or 0)
    steps = list(((state.get("plan") or {}).get("steps") or []))

    retirement = {
        "plan_hash": expected,
        "status_before": status,
        "step": old_step,
        "step_count": len(steps),
        "loop_count": old_loops,
        "reason": reason[:1200],
        "retired_at": utc_now(),
    }

    history = (
        state.get("retired_plans")
        if isinstance(state.get("retired_plans"), list)
        else []
    )
    state["retired_plans"] = [*history[-19:], retirement]

    append_journal(
        old_loops,
        old_step,
        "human-retire",
        "RETIRED",
        summary=reason,
        next_action="propose a new plan",
    )

    live_write(
        f"plan={expected} retired at step={old_step}/{len(steps)} "
        f"without Codex execution; returning controller to IDLE",
        "RETIRED",
    )

    state.update({
        "status": "IDLE",
        "plan_hash": None,
        "plan": None,
        "current_step": 1,
        "failure_attempts": {},
        "active_failure": None,
        "last_failure": None,
        "last_result": "RETIRED",
        "block_reason": None,
        "self_hosting_grant": None,
    })
    state.pop("proposal_previous_state", None)

    PLAN.unlink(missing_ok=True)
    save_state(state)

    print(
        f"RETIRED plan={expected} "
        f"step={old_step}/{len(steps)} loops={old_loops}; state=IDLE"
    )
    return 0

def cmd_steer(args: argparse.Namespace) -> int:
    """Record bounded human direction for the current blocked step and retry it."""
    init_files()
    state = load_state()
    if state.get("status") != "BLOCKED_HUMAN":
        raise RuntimeError("steer is only valid from BLOCKED_HUMAN")
    if args.plan_hash != state.get("plan_hash"):
        raise RuntimeError("steer hash does not match the approved plan")
    expected_gate = gate_id_for_state(state)
    if args.gate != expected_gate:
        raise RuntimeError(f"steer gate does not match current gate {expected_gate}")
    direction = " ".join(str(args.direction or "").split())
    if not direction:
        raise RuntimeError("steer requires non-empty human direction")

    step_no = int(state.get("current_step") or 0)
    plan = state.get("plan") if isinstance(state.get("plan"), dict) else {}
    steps = plan.get("steps") if isinstance(plan.get("steps"), list) else []
    if not (1 <= step_no <= len(steps)):
        raise RuntimeError("steer cannot resolve current approved step")
    step = steps[step_no - 1]

    original_block = " ".join(str(state.get("block_reason") or "").split())
    blocked_test_paths = set(re.findall(r"['\"](tests/[^'\"]+)['\"]", original_block))
    if args.allow_new_test and "policy violation" not in original_block.lower():
        raise RuntimeError("--allow-new-test is valid only for the current policy-review gate")

    allowed_new_tests: list[str] = []
    for raw in list(args.allow_new_test or []):
        path = _normalize_repo_path(str(raw or ""))
        if not path.startswith("tests/") or path == "tests/":
            raise RuntimeError(f"--allow-new-test requires a concrete tests/ path: {path or raw}")
        if path not in blocked_test_paths:
            raise RuntimeError(f"--allow-new-test path is not part of the current policy gate: {path}")
        if is_protected_path(path) or is_tooling_path(path):
            raise RuntimeError(f"steer cannot grant authority over protected/RALPH tooling path: {path}")
        origin = plan_baseline_path_kind(state, path)
        if origin != "absent":
            raise RuntimeError(f"steer cannot grant new-test authority to a pre-existing path ({origin}): {path}")
        if path not in allowed_new_tests:
            allowed_new_tests.append(path)

    record = {
        "gate_id": expected_gate,
        "plan_hash": state.get("plan_hash"),
        "step": step_no,
        "step_title": str(step.get("title") or ""),
        "direction": direction[:1200],
        "allowed_new_tests": allowed_new_tests,
        "original_block": original_block[:1200],
        "recorded_at": utc_now(),
    }
    failure_epoch_reset = reset_failure_epoch_after_human_steer(state)
    if failure_epoch_reset:
        record["failure_epoch_reset"] = failure_epoch_reset
    history = state.get("human_steering") if isinstance(state.get("human_steering"), list) else []
    state["human_steering"] = [*history[-49:], record]
    grants = state.get("steering_allowed_new_tests") if isinstance(state.get("steering_allowed_new_tests"), list) else []
    for path in allowed_new_tests:
        grant = {"step": step_no, "path": path, "gate_id": expected_gate, "recorded_at": record["recorded_at"]}
        if not any(isinstance(item, dict) and int(item.get("step") or 0) == step_no and item.get("path") == path for item in grants):
            grants.append(grant)
    state["steering_allowed_new_tests"] = grants[-100:]
    state["status"] = "APPROVED"
    state["block_reason"] = None
    save_state(state)

    prior = context_handoff(state)
    findings = list(prior.get("accepted_findings") or [])
    finding = f"Human steer {expected_gate}: {direction}"[:500]
    if finding not in findings:
        findings.insert(0, finding)
    save_context({
        "plan_hash": state.get("plan_hash"),
        "last_step": step_no,
        "last_result": "HUMAN_STEERED",
        "summary": direction[:1200],
        "changed_files": list(prior.get("changed_files") or [])[:12],
        "relevant_files": list(prior.get("relevant_files") or [])[:8],
        "accepted_findings": findings[:8],
    })
    append_journal(
        int(state.get("loop_count") or 0),
        step_no,
        "human-steer",
        "STEERED",
        summary=direction,
        files=allowed_new_tests,
        next_action="retry same approved step with bounded human direction",
    )
    live_write(
        f"gate={expected_gate} step={step_no} human direction recorded"
        + (f" · new-test authority={','.join(allowed_new_tests)}" if allowed_new_tests else ""),
        "GATE-HUMAN",
    )
    print(tui.steer_card(
        gate_id=expected_gate,
        step_no=step_no,
        step_count=len(steps),
        title=str(step.get("title") or f"Step {step_no}"),
        direction=direction,
        allowed_new_tests=allowed_new_tests,
    ))
    return 0


def cmd_authorize_self_hosting(args: argparse.Namespace) -> int:
    """Grant exact, one-step RALPH tooling authority after an explicit policy stop."""
    init_files()
    state = load_state()
    if state.get("status") != "BLOCKED_HUMAN":
        raise RuntimeError("authorize-self-hosting is only valid from BLOCKED_HUMAN")
    if args.plan_hash != state.get("plan_hash"):
        raise RuntimeError("authorize-self-hosting hash does not match the approved plan")
    expected_gate = gate_id_for_state(state)
    if args.gate != expected_gate:
        raise RuntimeError(f"authorize-self-hosting gate does not match current gate {expected_gate}")
    original_block = " ".join(str(state.get("block_reason") or "").split())
    if original_block != "Codex attempted to change RALPH controller/tooling authority":
        raise RuntimeError("authorize-self-hosting is valid only for the current RALPH tooling authority block")
    reason = " ".join(str(args.reason or "").split())
    if not reason:
        raise RuntimeError("authorize-self-hosting requires a non-empty operator reason")

    step_no = int(state.get("current_step") or 0)
    steps = list(((state.get("plan") or {}).get("steps") or []))
    if not (1 <= step_no <= len(steps)):
        raise RuntimeError("authorize-self-hosting cannot resolve current approved step")

    requested: list[str] = []
    for raw in list(args.path or []):
        path = _normalize_repo_path(str(raw or ""))
        if not path or path == ".ralph" or path.startswith(".ralph/"):
            raise RuntimeError(f"self-hosting grant cannot include RALPH runtime state: {path or raw}")
        if is_protected_path(path):
            raise RuntimeError(f"self-hosting grant cannot include protected path: {path}")
        if not is_tooling_path(path):
            raise RuntimeError(f"self-hosting grant requires an exact registered RALPH tooling path: {path}")
        if path not in requested:
            requested.append(path)
    if not requested:
        raise RuntimeError("authorize-self-hosting requires at least one exact --path")

    candidate = state.get("self_hosting_candidate") if isinstance(state.get("self_hosting_candidate"), dict) else {}
    candidate_paths = sorted({_normalize_repo_path(str(path)) for path in candidate.get("paths") or [] if str(path).strip()})
    if (
        str(candidate.get("plan_hash") or "") != str(state.get("plan_hash") or "")
        or int(candidate.get("step") or 0) != step_no
        or str(candidate.get("gate_id") or "") != expected_gate
        or not candidate_paths
    ):
        raise RuntimeError("self-hosting candidate is missing or stale for the current plan/step/gate")
    if sorted(requested) != candidate_paths:
        raise RuntimeError(
            "self-hosting paths must exactly match the controller-derived candidate: "
            f"{candidate_paths}"
        )

    grant = {
        "plan_hash": state.get("plan_hash"),
        "step": step_no,
        "gate_id": expected_gate,
        "paths": sorted(requested),
        "reason": reason[:1200],
        "granted_at": utc_now(),
    }
    history = state.get("self_hosting_grant_history") if isinstance(state.get("self_hosting_grant_history"), list) else []
    state["self_hosting_grant_history"] = [*history[-19:], grant]
    state["self_hosting_grant"] = grant
    state["self_hosting_candidate"] = None

    steering = state.get("human_steering") if isinstance(state.get("human_steering"), list) else []
    steering_record = {
        "gate_id": expected_gate,
        "plan_hash": state.get("plan_hash"),
        "step": step_no,
        "step_title": str(steps[step_no - 1].get("title") or ""),
        "direction": f"Operator granted supervised self-hosting authority only for: {', '.join(sorted(requested))}. {reason}"[:1200],
        "self_hosting_paths": sorted(requested),
        "original_block": original_block,
        "recorded_at": grant["granted_at"],
    }
    state["human_steering"] = [*steering[-49:], steering_record]
    state["status"] = "APPROVED"
    state["block_reason"] = None
    save_state(state)
    append_journal(
        int(state.get("loop_count") or 0), step_no, "self-hosting-authority", "AUTHORIZED",
        summary=reason, files=sorted(requested),
        next_action="retry same approved step with exact supervised tooling authority",
    )
    live_write(
        f"gate={expected_gate} step={step_no} supervised self-hosting authority granted · {','.join(sorted(requested))}",
        "GATE-HUMAN",
    )
    print(
        f"SELF_HOSTING_AUTHORIZED plan={state['plan_hash']} step={step_no} "
        f"gate={expected_gate} paths={','.join(sorted(requested))}"
    )
    return 0


def cmd_resume(args: argparse.Namespace) -> int:
    """Retry the same blocked step after human input; this does not accept the step."""
    init_files()
    state = load_state()
    if state.get("status") not in {"BLOCKED_HUMAN", "BLOCKED_ENVIRONMENT"}:
        raise RuntimeError("resume is only valid from BLOCKED_HUMAN/BLOCKED_ENVIRONMENT")
    if args.plan_hash != state.get("plan_hash"):
        raise RuntimeError("resume hash does not match the approved plan")
    state["status"] = "APPROVED"
    state["block_reason"] = None
    save_state(state)
    append_journal(state["loop_count"], state["current_step"], "human-resume", "RESUMED", summary=args.reason, next_action="retry same approved step")
    print("Human resume accepted; the blocked approved step will be retried.")
    return 0


def cmd_resolve_gate(args: argparse.Namespace) -> int:
    """Accept a human-owned gate and advance without fabricating an autonomous PASS."""
    init_files()
    state = load_state()
    if state.get("status") != "BLOCKED_HUMAN":
        raise RuntimeError("resolve-gate is only valid from BLOCKED_HUMAN")
    if args.plan_hash != state.get("plan_hash"):
        raise RuntimeError("resolve-gate hash does not match the approved plan")
    expected_gate = gate_id_for_state(state)
    if args.gate != expected_gate:
        raise RuntimeError(f"resolve-gate ID does not match current gate {expected_gate}")
    reason = " ".join(str(args.reason or "").split())
    if not reason:
        raise RuntimeError("resolve-gate requires non-empty human evidence/reason")
    allowed, why = human_gate_resolution_allowed(state)
    if not allowed:
        raise RuntimeError(f"current human gate cannot be resolved by operator confirmation: {why}")

    plan = state.get("plan") if isinstance(state.get("plan"), dict) else {}
    steps = plan.get("steps") if isinstance(plan.get("steps"), list) else []
    step = steps[int(state["current_step"]) - 1]
    original_block = " ".join(str(state.get("block_reason") or "").split())
    resolution = {
        "gate_id": expected_gate,
        "plan_hash": state.get("plan_hash"),
        "loop": int(state.get("loop_count") or 0),
        "step": int(state.get("current_step") or 0),
        "step_title": str(step.get("title") or ""),
        "result": "HUMAN_CONFIRMED",
        "reason": reason[:1200],
        "original_block": original_block[:1200],
        "resolved_at": utc_now(),
    }
    history = state.get("human_gate_resolutions") if isinstance(state.get("human_gate_resolutions"), list) else []
    state["human_gate_resolutions"] = [*history[-49:], resolution]
    update_context_after_human_confirmation(state, step, expected_gate, reason)
    append_human_gate_resolution(state, step, expected_gate, reason, original_block)
    record_step_result(state, step, "HUMAN_CONFIRMED", summary=reason)

    state["last_result"] = "HUMAN_CONFIRMED"
    state["block_reason"] = None
    state["current_step"] = int(state["current_step"]) + 1
    state["status"] = "APPROVED"
    save_state(state)
    live_write(
        f"gate={expected_gate} resolved HUMAN_CONFIRMED; advanced to step={state['current_step']} without Codex retry",
        "GATE",
    )
    print(
        f"Human gate {expected_gate} resolved; step {step.get('id')}=HUMAN_CONFIRMED; "
        f"next step={state['current_step']}/{len(steps)}; status=APPROVED."
    )
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    """Run the RALPH-Lite operator web console."""
    try:
        import ralph_web
    except ImportError as exc:
        raise RuntimeError("RALPH web console module is unavailable") from exc
    return int(ralph_web.serve(
        args.host, args.port, allow_lan=bool(args.allow_lan),
        username=args.username, password_file=args.password_file,
        session_hours=args.session_hours, usage_refresh_seconds=args.usage_refresh_seconds,
    ))


def cmd_status(_: argparse.Namespace) -> int:
    init_files()
    state = load_state()
    total = len((state.get("plan") or {}).get("steps") or [])
    efficiency = state.get("last_efficiency") if isinstance(state.get("last_efficiency"), dict) else {}
    usage = state.get("codex_usage") if isinstance(state.get("codex_usage"), dict) else {}
    guard, _ = codex_usage_guard(usage) if usage else ("-", [])
    windows = usage.get("windows") if isinstance(usage.get("windows"), list) else []
    remaining = min((float(w.get("remaining_percent", 100.0)) for w in windows), default=None)
    quota = f"{guard}:{remaining:.1f}%min" if remaining is not None else guard
    gate = gate_id_for_state(state) if state.get("status") == "BLOCKED_HUMAN" else "-"
    print(f"status={state.get('status')} plan={state.get('plan_hash') or '-'} step={state.get('current_step')}/{total or '-'} loops={state.get('loop_count')} gate={gate} block={state.get('block_reason') or '-'} efficiency={efficiency.get('status') or '-'} quota={quota}")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    tui.configure(getattr(args, "color", "auto"))
    init_files()
    state = load_state()
    if state.get("status") not in {"APPROVED", "RUNNING", "PAUSED_USAGE_LIMIT"}:
        raise RuntimeError(f"run requires APPROVED/RUNNING/PAUSED_USAGE_LIMIT status, found {state.get('status')}")
    if PLAN.read_text(encoding="utf-8") != render_plan(state["plan"]):
        block(state, "approved plan file changed")
        raise RuntimeError("approved plan file changed; blocked for human review")
    if not state.get("recovery_checkpoint"):
        checkpoint = create_recovery_checkpoint(state)
        state["recovery_checkpoint"] = checkpoint["id"]
        save_state(state)

    loops_this_run = 0
    while state["current_step"] <= len(state["plan"]["steps"]):
        if not ensure_codex_usage_capacity(state, wait=args.wait_for_limits, poll_seconds=args.usage_poll_seconds):
            return 0
        state = load_state()
        if loops_this_run >= args.max_loops:
            state["status"] = "APPROVED"
            save_state(state)
            live_write(f"loop budget reached ({args.max_loops}); paused cleanly with plan still approved", "PAUSE")
            print(f"PAUSED plan={state['plan_hash']} step={state['current_step']} loops={state['loop_count']}")
            return 0
        loops_this_run += 1
        loop_started = time.monotonic()
        state["status"] = "RUNNING"
        state["loop_count"] += 1
        loop_no = state["loop_count"]
        step = state["plan"]["steps"][state["current_step"] - 1]
        active_fp = state.get("active_failure")
        repair_no = int(state.get("failure_attempts", {}).get(active_fp, 0)) + 1 if active_fp else 0
        if active_fp and repair_no > MAX_REPAIRS_PER_FAILURE:
            block(state, f"failure {active_fp} exceeded {MAX_REPAIRS_PER_FAILURE} repair attempts")
            return 2
        save_state(state)
        phase = "repair" if active_fp else "implement"
        usage = state.get("codex_usage") if isinstance(state.get("codex_usage"), dict) else {}
        windows = usage.get("windows") if isinstance(usage.get("windows"), list) else []
        remaining = min((float(w.get("remaining_percent", 100.0)) for w in windows), default=None)
        quota = f"{remaining:.1f}% remaining" if remaining is not None else ""
        efficiency_state = state.get("last_efficiency") if isinstance(state.get("last_efficiency"), dict) else {}
        print(tui.step_banner(
            loop_no=loop_no, step_no=int(step["id"]), step_count=len(state["plan"]["steps"]),
            title=str(step["title"]), phase=phase, plan_hash=str(state["plan_hash"]),
            repair=repair_no, quota=quota, status=str(state.get("status") or "RUNNING"),
            efficiency=str(efficiency_state.get("status") or "PASS"),
            recovery=str(state.get("recovery_checkpoint") or "-"),
            changed_files=len(state.get("plan_changed_files") or []),
            test_policy=str(step.get("test_change_policy") or "none"),
            progress=plan_progress_rows(state),
            acceptance=list(step.get("acceptance") or []),
        ))
        live_write(
            f"loop={loop_no:04d} step={step['id']}/{len(state['plan']['steps'])} phase={phase} repair={repair_no} title={step['title']}",
            "RALPH",
        )

        loop_git_base = _git(["stash", "create", f"RALPH loop {loop_no:04d} pre-turn"], check=False).stdout.strip() or git_head()
        before_repo = repo_snapshot()
        authority = authority_snapshot()
        protected_before = protected_snapshot()
        try:
            result = run_codex(step_prompt(state, step, active_fp, repair_no), RESULT_SCHEMA, "workspace-write", context=f"LOOP {loop_no:04d} STEP {step['id']} {'REPAIR' if active_fp else 'IMPLEMENT'}")
            append_usage_ledger(
                result.get("_ralph_metrics") if isinstance(result, dict) else {},
                plan_hash_value=str(state.get("plan_hash") or ""),
                goal=str((state.get("plan") or {}).get("goal") or ""),
                scope="implementation", loop=loop_no, step=int(step["id"]), phase=phase,
            )
        except EnvironmentBlocked as exc:
            reason = str(exc)
            live_write(reason, "ENV")
            append_usage_ledger(
                exc.metrics, plan_hash_value=str(state.get("plan_hash") or ""),
                goal=str((state.get("plan") or {}).get("goal") or ""),
                scope="implementation", loop=loop_no, step=int(step["id"]), phase=phase,
            )
            env_result = {"_ralph_metrics": exc.metrics, "context": {}}
            append_journal(loop_no, step["id"], phase, "BLOCKED_ENVIRONMENT", summary=reason, repair=repair_no, next_action="fix environment then resume approved plan", stats=loop_stats(loop_started, env_result, repair=repair_no))
            block_environment(state, reason)
            return 2
        except Exception as exc:
            append_journal(loop_no, step["id"], phase, "BLOCKED", summary=str(exc), repair=repair_no, next_action="human review", stats=loop_stats(loop_started, repair=repair_no))
            block(state, str(exc))
            return 2

        after_repo = repo_snapshot()
        files = changed_paths(before_repo, after_repo)
        change_class = classify_changes(files)
        tooling_changed = [path for path in files if is_tooling_path(path)]

        changed_authority = authority_changed_paths(authority)
        if changed_authority:
            granted, grant_reason = self_hosting_grant_allows(state, int(step["id"]), changed_authority)
            if not granted:
                restore_authority(authority)
                state = load_state()
                candidate_paths = sorted(
                    path for path in changed_authority
                    if path != ".ralph"
                    and not path.startswith(".ralph/")
                    and not is_protected_path(path)
                    and is_tooling_path(path)
                )
                candidate = None
                if candidate_paths:
                    candidate = {
                        "plan_hash": state.get("plan_hash"),
                        "step": int(step["id"]),
                        "gate_id": gate_id_for_state(state),
                        "paths": candidate_paths,
                        "detected_at": utc_now(),
                    }
                state["self_hosting_candidate"] = candidate
                detail = f"authority paths {changed_authority}"
                reason = f"Codex changed {detail}; original contents restored; {grant_reason}"
                live_write(reason, "POLICY")
                append_journal(loop_no, step["id"], "policy", "BLOCKED", summary=reason, files=files, repair=repair_no, next_action="human review", change_class=change_class, stats=loop_stats(loop_started, result, repair=repair_no))
                block(state, "Codex attempted to change RALPH controller/tooling authority")
                return 2
            live_write(
                f"step={step['id']} supervised self-hosting authority accepted · {','.join(changed_authority)}",
                "AUTHORITY",
            )

        protected = [p for p in files if is_protected_path(p)]
        test_violations = test_policy_violation(
            before_repo, after_repo, step["test_change_policy"], state=state, step_no=int(step["id"])
        )
        if protected or test_violations:
            if protected:
                restore_protected(protected_before, protected)
            reason = "policy violation: " + "; ".join(filter(None, [f"protected paths {protected}" if protected else "", f"test paths {test_violations}" if test_violations else ""]))
            origins = {path: plan_baseline_path_kind(state, path) for path in test_violations}
            print(tui.policy_gate_card(
                gate_id=gate_id_for_state(state),
                step_no=int(step["id"]),
                step_count=len(state["plan"]["steps"]),
                title=str(step.get("title") or ""),
                test_policy=str(step.get("test_change_policy") or ""),
                paths=test_violations,
                origins=origins,
                acceptance=list(step.get("acceptance") or []),
                protected=protected,
            ))
            append_journal(loop_no, step["id"], "policy", "BLOCKED", summary=reason, files=files, repair=repair_no, ideas=result.get("ideas", []), next_action="review gate; steer/resume/replan as appropriate", change_class=change_class, stats=loop_stats(loop_started, result, repair=repair_no))
            append_ideas(loop_no, result.get("ideas", []))
            block(state, reason)
            return 2

        remember_plan_files(state, files)
        save_state(state)
        entries = change_entries(files, base_ref=loop_git_base)
        if entries:
            print(tui.change_card(entries))
            preview = tui.diff_preview(bounded_diff(files, base_ref=loop_git_base))
            if preview:
                print(preview)
            summary_card = tui.behavior_summary(str(result.get("summary") or ""))
            if summary_card:
                print(summary_card)
            for item in entries:
                live_write(
                    f"{item['path']} +{item['added']}/-{item['removed']}"
                    + (f" · {', '.join(item['symbols'])}" if item.get("symbols") else ""),
                    item["action"],
                )

        append_ideas(loop_no, result.get("ideas", []))
        continuation, continuation_reason = codex_requests_continuation(result, step)
        if continuation:
            stats = loop_stats(loop_started, result, repair=repair_no)
            state["last_result"] = "CONTINUE"
            state["block_reason"] = None
            append_journal(
                loop_no, step["id"], phase, "CONTINUE",
                summary=continuation_reason, files=files, repair=repair_no,
                ideas=result.get("ideas", []),
                next_action="continue same approved step in next bounded loop",
                change_class=change_class, stats=stats,
            )
            save_state(state)
            live_write(
                f"loop={loop_no:04d} step={step['id']} ordinary continuation requested; "
                "another bounded loop remains inside approved authority",
                "CONTINUE",
            )
            continue

        requires_human, reason = codex_requires_human_before_gates(result, step)
        if requires_human:
            append_journal(loop_no, step["id"], phase, "BLOCKED", summary=reason, files=files, repair=repair_no, ideas=result.get("ideas", []), next_action="human review", change_class=change_class, stats=loop_stats(loop_started, result, repair=repair_no))
            block(state, reason)
            return 2
        if result.get("blocker_class") == "validation-only":
            notes = "; ".join(result.get("validation_notes") or result.get("blockers") or ["focused validation unavailable"])
            live_write(f"focused validation advisory: {notes}; controller gates remain authoritative", "VALIDATE")

        passed, gates, fp, gate_output, gate_durations = run_gates()
        stats = loop_stats(loop_started, result, gate_durations=gate_durations, repair=repair_no)
        if passed:
            efficiency = efficiency_findings(stats)
            next_action = "pause for efficiency review" if efficiency else "next approved step"
            live_write(f"loop={loop_no:04d} step={step['id']} PASS · class={change_class}", "PASS")
            append_journal(loop_no, step["id"], phase, "PASS", summary=result.get("summary", ""), files=files, gates=gates, repair=repair_no, ideas=result.get("ideas", []), next_action=next_action, change_class=change_class, stats=stats)
            state["last_result"] = "PASS"
            state["last_failure"] = None
            state["active_failure"] = None
            state["last_efficiency"] = {"status": "WARN" if efficiency else "PASS", "findings": efficiency}
            update_context_after_pass(state, step, result, files)
            record_step_result(state, step, "PASS", summary=result.get("summary", ""), files=files, gates=gates, stats=stats)
            entry_stats = change_entries(files, base_ref=loop_git_base)
            print(tui.result_card(
                result="PASS",
                step_no=int(step["id"]),
                step_count=len(state["plan"]["steps"]),
                files=len(entry_stats),
                added=sum(int(item.get("added") or 0) for item in entry_stats),
                removed=sum(int(item.get("removed") or 0) for item in entry_stats),
                tests=gates,
                tokens=stats,
            ))
            state["self_hosting_grant"] = None
            state["self_hosting_candidate"] = None
            state["current_step"] += 1
            state["status"] = "APPROVED"
            save_state(state)
            if efficiency:
                detail = "; ".join(efficiency)
                live_write(f"qualified step completed but efficiency budget exceeded: {detail}; pausing before next model turn", "EFFICIENCY")
                print(f"PAUSED_EFFICIENCY plan={state['plan_hash']} step={state['current_step']} loops={state['loop_count']} findings={detail}")
                return 0
            continue

        live_write(f"loop={loop_no:04d} step={step['id']} FAIL fingerprint={fp}", "FAIL")
        if active_fp:
            attempts = state.setdefault("failure_attempts", {})
            attempts[active_fp] = int(attempts.get(active_fp, 0)) + 1
        state["last_result"] = "FAIL"
        state["last_failure"] = {"fingerprint": fp, "output": gate_output[-6000:], "gates": gates}
        state["active_failure"] = fp
        append_journal(loop_no, step["id"], phase, "FAIL", summary=result.get("summary", ""), files=files, gates=gates, fingerprint=fp, repair=repair_no, ideas=result.get("ideas", []), next_action="repair same approved step", change_class=change_class, stats=stats)
        save_state(state)

        same_attempts = int(state.get("failure_attempts", {}).get(fp, 0))
        if active_fp == fp and same_attempts >= MAX_REPAIRS_PER_FAILURE:
            block(state, f"failure {fp} persisted through {MAX_REPAIRS_PER_FAILURE} repair attempts")
            return 2

    passed, final_gates, final_durations, final_output = run_final_qualification()
    state["final_qualification"] = {
        "state": "PASS" if passed else "FAIL",
        "gates": final_gates,
        "durations": final_durations,
        "output": final_output[-6000:],
        "completed_at": utc_now(),
    }
    state["block_reason"] = None
    try:
        state["codex_usage"] = query_codex_rate_limits()
    except Exception:
        pass

    if not passed:
        state["status"] = "BLOCKED_HUMAN"
        state["block_reason"] = "final qualification failed after all approved steps completed"
        save_state(state)
        append_journal(
            state["loop_count"], len(state["plan"]["steps"]), "final-qualification", "FAIL",
            summary=state["block_reason"], gates=final_gates, next_action="human review final qualification output",
        )
        live_write(state["block_reason"], "FAIL")
        print(final_output[-6000:])
        return 2

    final_entries = change_entries(state.get("plan_changed_files") or [])
    state["completion_changes"] = {
        "entries": final_entries,
        "files": len(final_entries),
        "added": sum(int(item.get("added") or 0) for item in final_entries),
        "removed": sum(int(item.get("removed") or 0) for item in final_entries),
    }
    state["status"] = "READY_TO_COMMIT"
    save_state(state)
    report = build_completion_report(state, final_gates)
    with JOURNAL.open("a", encoding="utf-8") as handle:
        handle.write(
            f"## Plan complete — {utc_now()}\n\n"
            f"- Plan: `{state['plan_hash']}`\n"
            f"- Loops: {state['loop_count']}\n"
            f"- Steps: {len(state['plan']['steps'])}\n"
            "- Final qualification: PASS\n"
            "- Status: READY_TO_COMMIT\n"
            f"- Completion report: `{report['markdown_path']}`\n"
            f"- Recovery checkpoint: `{state.get('recovery_checkpoint')}`\n"
            f"- Next action: python3 scripts/ralph.py finalize {state['plan_hash']}\n\n"
        )
    live_write(
        f"plan complete · final qualification PASS · report={report['markdown_path']} · READY_TO_COMMIT",
        "READY",
    )
    print(tui.completion_card(report))
    print(f"Next: python3 scripts/ralph.py finalize {state['plan_hash']}")
    return 0


def cmd_recover_validation_block(args: argparse.Namespace) -> int:
    """Human-triggered controller qualification for a validation-only historical block."""
    init_files()
    state = load_state()
    if state.get("status") != "BLOCKED_HUMAN":
        raise RuntimeError("recover-validation-block requires BLOCKED_HUMAN status")
    if args.plan_hash != state.get("plan_hash"):
        raise RuntimeError("recovery hash does not match the approved plan")
    if not is_recoverable_validation_block(state.get("block_reason") or ""):
        raise RuntimeError("current block is not classified as a recoverable validation-only block")
    if PLAN.read_text(encoding="utf-8") != render_plan(state["plan"]):
        raise RuntimeError("approved plan file changed; recovery refused")

    step = state["plan"]["steps"][state["current_step"] - 1]
    files = git_changed_paths()
    if not files:
        raise RuntimeError("no working-tree changes found to qualify")
    validate_recovery_paths(files, step)
    change_class = classify_changes(files)
    if change_class != "product-development":
        raise RuntimeError(f"recovery requires product-development changes only, found {change_class}")

    live_write(f"human-triggered qualification of blocked step {step['id']} over {len(files)} worktree paths", "RECOVER")
    started = time.monotonic()
    passed, gates, fp, gate_output, gate_durations = run_gates()
    stats = {
        "duration_seconds": time.monotonic() - started,
        "codex_seconds": 0.0,
        "commands_executed": 0,
        "files_inspected": 0,
        "gate_durations": gate_durations,
    }
    if passed:
        result = {
            "summary": "Human-triggered controller qualification passed for the previously blocked implementation.",
            "context": {
                "relevant_files": files[:8],
                "accepted_findings": ["Previously blocked implementation passed the full authoritative RALPH qualification gates."],
                "files_inspected": [],
            },
        }
        append_journal(
            state["loop_count"], step["id"], "human-qualification", "PASS",
            summary=result["summary"], files=files, gates=gates, next_action="next approved step",
            change_class=change_class, stats=stats,
        )
        state["last_result"] = "PASS"
        state["last_failure"] = None
        state["active_failure"] = None
        state["block_reason"] = None
        state["last_efficiency"] = {"status": "PASS", "findings": []}
        update_context_after_pass(state, step, result, files)
        state["current_step"] += 1
        state["status"] = "APPROVED"
        save_state(state)
        live_write(f"step={step['id']} recovered qualification PASS; advanced to step={state['current_step']}", "PASS")
        print(f"RECOVERED_PASS plan={state['plan_hash']} step={state['current_step']} loops={state['loop_count']}")
        return 0

    state["last_result"] = "FAIL"
    state["last_failure"] = {"fingerprint": fp, "output": gate_output[-6000:], "gates": gates}
    state["active_failure"] = fp
    state["block_reason"] = None
    state["status"] = "APPROVED"
    append_journal(
        state["loop_count"], step["id"], "human-qualification", "FAIL",
        summary="Controller qualification failed; next RALPH run will repair the same approved step.",
        files=files, gates=gates, fingerprint=fp, next_action="repair same approved step",
        change_class=change_class, stats=stats,
    )
    save_state(state)
    print(f"RECOVERED_FAIL plan={state['plan_hash']} step={state['current_step']} fingerprint={fp}")
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="RALPH-Lite deterministic Codex development-loop supervisor")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init").set_defaults(func=cmd_init)
    propose = sub.add_parser("propose")
    propose.add_argument("--goal", required=True)
    propose.set_defaults(func=cmd_propose)
    approve = sub.add_parser("approve")
    approve.add_argument("plan_hash")
    approve.set_defaults(func=cmd_approve)
    reject = sub.add_parser("reject", help="reject a pending proposal without granting execution authority")
    reject.add_argument("plan_hash")
    reject.add_argument("--reason", required=True)
    reject.set_defaults(func=cmd_reject)

    retire = sub.add_parser(
        "retire-plan",
        help="retire an obsolete active plan without granting execution authority",
    )
    retire.add_argument("plan_hash")
    retire.add_argument("--reason", required=True)
    retire.set_defaults(func=cmd_retire_plan)
    run = sub.add_parser("run")
    run.add_argument("--max-loops", type=int, default=DEFAULT_MAX_LOOPS)
    run.add_argument("--wait-for-limits", action=argparse.BooleanOptionalAction, default=True, help="wait and automatically resume after Codex usage limits recover")
    run.add_argument("--usage-poll-seconds", type=int, default=USAGE_POLL_SECONDS, help="maximum zero-model usage recheck interval while paused")
    run.add_argument("--color", choices=("auto", "always", "never"), default="auto", help="terminal colour mode")
    run.set_defaults(func=cmd_run)
    steer = sub.add_parser("steer", help="record bounded human direction for the current blocked step and retry it")
    steer.add_argument("plan_hash")
    steer.add_argument("--gate", required=True, help="exact current human-gate ID")
    steer.add_argument("--direction", required=True, help="bounded human direction retained in the audit trail and next prompt")
    steer.add_argument("--allow-new-test", action="append", default=[], metavar="PATH", help="explicitly authorise one exact new tests/ path; never permits editing pre-existing tests")
    steer.set_defaults(func=cmd_steer)
    self_host = sub.add_parser(
        "authorize-self-hosting",
        help="grant exact one-step RALPH tooling authority after an explicit authority block",
    )
    self_host.add_argument("plan_hash")
    self_host.add_argument("--gate", required=True, help="exact current human-gate ID")
    self_host.add_argument("--path", action="append", required=True, help="exact registered RALPH tooling path; repeat as needed")
    self_host.add_argument("--reason", required=True, help="operator reason retained with the scoped authority grant")
    self_host.set_defaults(func=cmd_authorize_self_hosting)
    resume = sub.add_parser("resume", help="retry the same blocked approved step after human input")
    resume.add_argument("plan_hash")
    resume.add_argument("--reason", required=True)
    resume.set_defaults(func=cmd_resume)
    resolve_gate = sub.add_parser("resolve-gate", help="human-confirm an explicitly delegated runtime/operator gate and advance")
    resolve_gate.add_argument("plan_hash")
    resolve_gate.add_argument("--gate", required=True, help="exact current human-gate ID, for example HG-0015-04")
    resolve_gate.add_argument("--reason", required=True, help="human evidence/action satisfying the approved gate")
    resolve_gate.set_defaults(func=cmd_resolve_gate)
    recover = sub.add_parser("recover-validation-block")
    recover.add_argument("plan_hash")
    recover.set_defaults(func=cmd_recover_validation_block)
    sub.add_parser("checkpoints", help="list local Git-backed recovery checkpoints").set_defaults(func=cmd_checkpoints)
    checkpoint_info = sub.add_parser("checkpoint-info", help="show one recovery checkpoint manifest")
    checkpoint_info.add_argument("checkpoint_id")
    checkpoint_info.set_defaults(func=cmd_checkpoint_info)
    report = sub.add_parser("report", help="regenerate the current plan completion report")
    report.add_argument("plan_hash")
    report.set_defaults(func=cmd_report)
    finalize = sub.add_parser("finalize", help="review, commit, or push a fully qualified completed plan")
    finalize.add_argument("plan_hash")
    action = finalize.add_mutually_exclusive_group()
    action.add_argument("--commit", action="store_true", help="commit only the recorded plan delta after final guards")
    action.add_argument("--push", action="store_true", help="push the committed plan to the current configured upstream")
    finalize.add_argument("--message", help="explicit commit subject; used only with --commit")
    finalize.set_defaults(func=cmd_finalize)
    reconcile_commit = sub.add_parser("reconcile-commit", help="adopt a manually created qualified commit after strict verification")
    reconcile_commit.add_argument("plan_hash")
    reconcile_commit.add_argument("--commit", required=True, help="commit SHA to adopt")
    reconcile_commit.add_argument("--reason", required=True, help="human explanation for the manual commit path")
    reconcile_commit.set_defaults(func=cmd_reconcile_commit)
    reconcile_push = sub.add_parser("reconcile-push", help="mark the recorded commit pushed after proving it exists on the configured upstream")
    reconcile_push.add_argument("plan_hash")
    reconcile_push.set_defaults(func=cmd_reconcile_push)
    usage = sub.add_parser("usage", help="show RALPH context/token usage and live Codex remaining limits")
    usage.add_argument("--details", action="store_true", help="include per-loop token usage")
    usage.add_argument("--json", action="store_true", help="emit machine-readable report")
    usage.add_argument("--no-save", action="store_true", help=argparse.SUPPRESS)
    usage.set_defaults(func=cmd_usage)
    serve = sub.add_parser("serve", help="run the local operator web console")
    serve.add_argument("--host", default="127.0.0.1", help="bind address; default 127.0.0.1")
    serve.add_argument("--port", type=int, default=8765, help="local console port; default 8765")
    serve.add_argument(
        "--allow-lan",
        action="store_true",
        help="explicitly allow one private LAN bind; LAN mode requires username/password authentication",
    )
    serve.add_argument("--username", default=None, help="LAN login username; defaults to RALPH_WEB_USERNAME or ralph")
    serve.add_argument("--password-file", default=None, help="read LAN login password from a mode-0600 file instead of prompting")
    serve.add_argument("--session-hours", type=float, default=12.0, help="LAN browser session lifetime; default 12 hours")
    serve.add_argument("--usage-refresh-seconds", type=int, default=60, help="live Codex limit refresh interval; minimum 15 seconds")
    serve.set_defaults(func=cmd_serve)
    sub.add_parser("status").set_defaults(func=cmd_status)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if getattr(args, "max_loops", 1) < 1:
        raise SystemExit("--max-loops must be >= 1")
    if getattr(args, "usage_poll_seconds", USAGE_POLL_SECONDS) < 15:
        raise SystemExit("--usage-poll-seconds must be >= 15")
    if getattr(args, "usage_refresh_seconds", 60) < 15:
        raise SystemExit("--usage-refresh-seconds must be >= 15")
    if getattr(args, "session_hours", 12.0) <= 0:
        raise SystemExit("--session-hours must be > 0")
    try:
        return args.func(args)
    except (RuntimeError, ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"RALPH-Lite: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
