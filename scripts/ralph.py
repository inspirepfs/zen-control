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
import secrets
import selectors
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
import uuid
from pathlib import Path
from typing import Iterable

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))
import ralph_tui as tui
import ralph_efficiency as efficiency_policy
import ralph_model as model_policy
from ralph_profile import ZEN_PROFILE

ROOT = ZEN_PROFILE.repository_root(__file__)
RALPH = ZEN_PROFILE.runtime_directory(ROOT)
STATE = ZEN_PROFILE.artifact(ROOT, "state")
PLAN = ZEN_PROFILE.artifact(ROOT, "plan")
IDEAS = ZEN_PROFILE.artifact(ROOT, "ideas")
JOURNAL = ZEN_PROFILE.artifact(ROOT, "journal")
POLICY = ZEN_PROFILE.artifact(ROOT, "policy")
LIVE = ZEN_PROFILE.artifact(ROOT, "live")
CONTEXT = ZEN_PROFILE.artifact(ROOT, "context")
EVENTS = ZEN_PROFILE.artifact(ROOT, "events")
RECOVERY = ZEN_PROFILE.artifact(ROOT, "recovery")
REPORTS = ZEN_PROFILE.artifact(ROOT, "reports")
# Retirement manifests are controller artifacts but intentionally outside the
# profile's mutable artifact map: records are append-only and self-validating.
RETIREMENTS = RALPH / "retirements"
USAGE_LEDGER = ZEN_PROFILE.artifact(ROOT, "usage_ledger")
USAGE_STATS_RESET = ZEN_PROFILE.artifact(ROOT, "usage_stats_reset")

MAX_REPAIRS_PER_FAILURE = 3
DEFAULT_MAX_LOOPS = 40
# Codex exec currently has no native max-agent-turns/max-steps control. These
# budgets therefore act as a safe post-loop circuit breaker: finish the current
# qualified step, then pause before another model turn if efficiency regresses.
# Backward-compatible constant aliases. Runtime decisions reload the live policy
# from .ralph/efficiency-policy.json before each model turn / efficiency decision.
_DEFAULT_EFFICIENCY = efficiency_policy.DEFAULT_POLICY
PROMPT_COMMAND_BUDGET = int(_DEFAULT_EFFICIENCY["normal_prompt_command_budget"])
EFFICIENCY_MAX_COMMANDS = int(_DEFAULT_EFFICIENCY["normal_max_commands"])
EFFICIENCY_MAX_CUMULATIVE_INPUT = int(_DEFAULT_EFFICIENCY["normal_max_cumulative_input"])
EFFICIENCY_MAX_NONCACHED_INPUT = int(_DEFAULT_EFFICIENCY["normal_max_noncached_input"])
EFFICIENCY_MAX_REPORTED_FILES = int(_DEFAULT_EFFICIENCY["normal_max_reported_files"])
EFFICIENCY_MODES = efficiency_policy.MODES
# Emergency ceilings remain active even when the ordinary efficiency governor is OFF.
RUNAWAY_MAX_COMMANDS = int(_DEFAULT_EFFICIENCY["runaway_max_commands"])
RUNAWAY_MAX_CUMULATIVE_INPUT = int(_DEFAULT_EFFICIENCY["runaway_max_cumulative_input"])
RUNAWAY_MAX_NONCACHED_INPUT = int(_DEFAULT_EFFICIENCY["runaway_max_noncached_input"])
RUNAWAY_MAX_REPORTED_FILES = int(_DEFAULT_EFFICIENCY["runaway_max_reported_files"])
USAGE_RESERVE_PERCENT = float(_DEFAULT_EFFICIENCY["reserve_percent"])
USAGE_APP_SERVER_TIMEOUT_SECONDS = 15
USAGE_POLL_SECONDS = 300
USAGE_LEDGER_MAX_ROWS = 20_000
PLAN_MIN_STEPS_DEFAULT = 5
PLAN_MAX_STEPS_DEFAULT = 10
PLAN_MAX_STEPS_LIMIT = 20
_CODEX_PREFIX: list[str] | None = None
EXCLUDED_DIRS = ZEN_PROFILE.excluded_dirs
PROTECTED_PREFIXES = ZEN_PROFILE.protected_prefixes
PROTECTED_EXACT = ZEN_PROFILE.protected_exact
PROTECTED_DIR_PREFIXES = ZEN_PROFILE.protected_dir_prefixes
PROTECTED_SUFFIXES = ZEN_PROFILE.protected_suffixes
TOOLING_PATHS = ZEN_PROFILE.tooling_paths
REPOSITORY_AUTHORITY_FIELD = "repository_authority"
REPOSITORY_AUTHORITIES = frozenset({"read-only", "write"})
PLAN_SCHEMA = {
    "type": "object",
    "properties": {
        "goal": {"type": "string"},
        "steps": {
            "type": "array", "minItems": 1, "maxItems": PLAN_MAX_STEPS_LIMIT,
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


def proposal_step_bounds(min_steps: object = None, max_steps: object = None) -> tuple[int, int]:
    """Validate operator-selected planning bounds without granting execution authority."""
    minimum = PLAN_MIN_STEPS_DEFAULT if min_steps is None else int(min_steps)
    maximum = PLAN_MAX_STEPS_DEFAULT if max_steps is None else int(max_steps)
    if minimum < 1:
        raise ValueError("minimum plan steps must be at least 1")
    if maximum < minimum:
        raise ValueError("maximum plan steps must be greater than or equal to minimum plan steps")
    if maximum > PLAN_MAX_STEPS_LIMIT:
        raise ValueError(f"maximum plan steps must not exceed {PLAN_MAX_STEPS_LIMIT}")
    return minimum, maximum


def plan_step_bounds(plan: dict) -> tuple[int, int]:
    planning = plan.get("planning") if isinstance(plan, dict) and isinstance(plan.get("planning"), dict) else {}
    return proposal_step_bounds(planning.get("min_steps"), planning.get("max_steps"))


def validate_plan(plan: dict) -> None:
    steps = plan.get("steps") if isinstance(plan, dict) else None
    if not isinstance(plan.get("goal") if isinstance(plan, dict) else None, str) or not plan["goal"].strip():
        raise ValueError("plan goal must be a non-empty string")
    minimum, maximum = plan_step_bounds(plan)
    if not isinstance(steps, list) or not minimum <= len(steps) <= maximum:
        raise ValueError(f"plan must contain {minimum}-{maximum} steps")
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


def validate_complete_plan(plan: dict, expected_hash: str | None = None) -> None:
    """Validate the controller-completed approval candidate and its authority."""
    validate_plan(plan)
    authority = plan.get(REPOSITORY_AUTHORITY_FIELD) if isinstance(plan, dict) else None
    if authority in REPOSITORY_AUTHORITIES:
        return
    raise ValueError("plan is missing controller-injected repository authority")


def sandbox_for_approved_plan(plan: dict, expected_hash: str | None = None) -> str:
    """Select the model sandbox from the controller-bound plan authority only.
    """
    validate_complete_plan(plan, expected_hash)
    authority = plan.get(REPOSITORY_AUTHORITY_FIELD) if isinstance(plan, dict) else None
    if authority == "read-only":
        return "read-only"
    if authority == "write":
        return "workspace-write"
    raise ValueError("approved plan has no sandbox-selecting repository authority")


def controller_inject_repository_authority(plan: dict, authority: object) -> None:
    """Bind an operator-selected controller contract after model planning."""
    if not isinstance(plan, dict):
        raise ValueError("model proposal must be an object")
    if REPOSITORY_AUTHORITY_FIELD in plan:
        raise ValueError("model proposal must not supply repository authority")
    if authority not in REPOSITORY_AUTHORITIES:
        raise ValueError("proposal requires repository authority: read-only or write")
    plan[REPOSITORY_AUTHORITY_FIELD] = authority


def render_plan(plan: dict) -> str:
    digest = plan_hash(plan)
    minimum, maximum = plan_step_bounds(plan)
    authority = plan.get(REPOSITORY_AUTHORITY_FIELD)
    lines = [
        "# RALPH-Lite Approved-Plan Candidate",
        "",
        f"**Goal:** {plan['goal']}",
        f"**Plan size:** `{minimum}-{maximum}` steps",
    ]
    if authority in REPOSITORY_AUTHORITIES:
        lines.append(f"**Repository authority:** `{authority}`")
    lines += [f"**Plan SHA-256:** `{digest}`", ""]
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
        "approved_plan_artifact": None,
        "approval_repository_evidence": None,
        "operation_attributions": [],
        "pending_step_delta_paths": [],
        "plan_changed_files": [],
        "plan_owned_files": [],
        "test_reconciliation_adoptions": [],
        "human_steering": [],
        "steering_allowed_new_tests": [],
        "self_hosting_grant": None,
        "self_hosting_candidate": None,
        "self_hosting_grant_history": [],
        "step_results": [],
        "final_qualification": None,
        "commit_sha": None,
        "commit_message": None,
        "commit_reconciled": False,
        "commit_reconcile_note": None,
        "commit_reconciled_at": None,
        "push_upstream": None,
        "push_reconciled": False,
        "pushed_at": None,
        "completion_changes": None,
        "efficiency_mode": "NORMAL",
        "efficiency_recommendation": None,
        "usage_admission": None,
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
    repository_evidence = approval_repository_evidence()
    manifest = {
        "schema": "zen_ralph_recovery_v2",
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
        "repository_evidence": repository_evidence,
        "approved_plan_artifact": dict(state.get("approved_plan_artifact") or {}),
    }
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tui.write_event(EVENTS, "CHECKPOINT", f"created {checkpoint_id}", checkpoint=manifest)
    live_write(f"{checkpoint_id} · HEAD {head[:12]} · dirty={len(dirty)} · ref={ref}", "CHECKPOINT")
    return manifest


def _approval_status_records() -> dict[str, str]:
    """Return current porcelain status codes keyed by their worktree paths."""
    proc = _git(["status", "--porcelain=v1", "-z", "--untracked-files=all"])
    records: dict[str, str] = {}
    entries = proc.stdout.split("\0")
    index = 0
    while index < len(entries):
        entry = entries[index]
        index += 1
        if not entry:
            continue
        code, path = entry[:2], entry[3:].strip()
        if path:
            records[_normalize_repo_path(path)] = code
        # In -z mode renamed/copied entries have a second, source-path field.
        if len(code) == 2 and (code[0] in {"R", "C"} or code[1] in {"R", "C"}):
            index += 1
    return records


def _approval_path_evidence(path: str, status: str) -> dict:
    """Capture status and safe content evidence without conferring ownership."""
    path = _normalize_repo_path(path)
    full = ROOT / path
    head = git_head()
    tracked_at_head = _git(["cat-file", "-e", f"{head}:{path}"], check=False).returncode == 0
    tracked_in_index = _git(["ls-files", "--error-unmatch", "--", path], check=False).returncode == 0
    index_status = status[:1] if status else " "
    worktree_status = status[1:2] if len(status) > 1 else " "
    if status == "??":
        baseline_kind = "preexisting-untracked"
    elif tracked_at_head:
        baseline_kind = "tracked"
    elif tracked_in_index:
        baseline_kind = "index-created"
    else:
        baseline_kind = "unknown"
    evidence = {
        "path": path,
        "baseline_kind": baseline_kind,
        "index_status": index_status,
        "worktree_status": worktree_status,
        "tracked_at_head": tracked_at_head,
        "tracked_in_index": tracked_in_index,
    }
    if is_protected_path(path) or _is_runtime_authority_path(path):
        return evidence | {"content_fingerprint": None, "content_not_read": "protected-or-runtime"}
    if full.is_symlink() or (full.exists() and not full.is_file()):
        return evidence | {"content_fingerprint": None, "content_not_read": "not-a-regular-file"}
    if full.is_file():
        return evidence | {"content_fingerprint": file_hash(full), "bytes": full.stat().st_size}
    return evidence | {"content_fingerprint": None, "missing": True}


def approval_repository_evidence() -> dict:
    """Describe approval-time residue; evidence is explicitly not plan ownership."""
    records = [_approval_path_evidence(path, status) for path, status in sorted(_approval_status_records().items())]
    return {
        "schema": "zen_ralph_approval_repository_evidence_v1",
        "captured_at": utc_now(),
        "tracked_index_worktree": [item for item in records if item["baseline_kind"] != "preexisting-untracked"],
        "untracked_content_fingerprints": [item for item in records if item["baseline_kind"] == "preexisting-untracked"],
        "operator_residue": [item | {"ownership": "operator-residue"} for item in records],
    }


def bind_approved_plan_artifact(state: dict) -> dict:
    """Bind the exact approved bytes once, independent of future rendering code."""
    if not PLAN.is_file():
        raise RuntimeError("approved plan artifact is missing")
    artifact = {
        "schema": "zen_ralph_approved_plan_artifact_v1",
        "path": PLAN.relative_to(ROOT).as_posix(),
        "plan_hash": str(state.get("plan_hash") or ""),
        "sha256": file_hash(PLAN),
        "bytes": PLAN.stat().st_size,
        "bound_at": utc_now(),
    }
    state["approved_plan_artifact"] = artifact
    return artifact


def verify_approved_plan_artifact(state: dict) -> None:
    """Verify the immutable approved-plan bytes bound by ``cmd_approve``."""
    artifact = state.get("approved_plan_artifact")
    if not isinstance(artifact, dict):
        raise RuntimeError("approved plan artifact binding is missing")
    if artifact.get("schema") != "zen_ralph_approved_plan_artifact_v1":
        raise RuntimeError("approved plan artifact binding is invalid")
    if artifact.get("path") != ".ralph/plan.md" or artifact.get("plan_hash") != state.get("plan_hash"):
        raise RuntimeError("approved plan artifact binding does not match the active plan")
    if not PLAN.is_file() or artifact.get("bytes") != PLAN.stat().st_size or artifact.get("sha256") != file_hash(PLAN):
        raise RuntimeError("approved plan file changed")


def verify_approval_execution_evidence(state: dict) -> dict:
    """Require the native approval bindings before execution or recovery.

    Only ``cmd_approve`` creates these linked records.  Later lifecycle paths
    are verification-only: they must never reconstruct absent authority.
    """
    verify_approved_plan_artifact(state)
    artifact = state["approved_plan_artifact"]
    checkpoint_id = str(state.get("recovery_checkpoint") or "")
    checkpoint = load_recovery_checkpoint(checkpoint_id)
    if (
        not checkpoint_id
        or checkpoint.get("schema") != "zen_ralph_recovery_v2"
        or checkpoint.get("id") != checkpoint_id
        or checkpoint.get("plan_hash") != state.get("plan_hash")
    ):
        raise RuntimeError("matching approval recovery checkpoint is missing or invalid")
    if checkpoint.get("approved_plan_artifact") != artifact:
        raise RuntimeError("approval checkpoint artifact does not match the approved plan")
    evidence = checkpoint.get("repository_evidence")
    evidence_fields = (
        "tracked_index_worktree",
        "untracked_content_fingerprints",
        "operator_residue",
    )
    if (
        not isinstance(evidence, dict)
        or evidence.get("schema") != "zen_ralph_approval_repository_evidence_v1"
        or not isinstance(evidence.get("captured_at"), str)
        or any(not isinstance(evidence.get(field), list) for field in evidence_fields)
        or any(not isinstance(item, dict) for field in evidence_fields for item in evidence[field])
    ):
        raise RuntimeError("structured approval repository evidence is missing or invalid")
    if state.get("approval_repository_evidence") != evidence:
        raise RuntimeError("approval repository evidence does not match the approval checkpoint")
    return checkpoint


OPERATION_ATTRIBUTION_SCHEMA = "zen_ralph_operation_attribution_v2"


def _evidence_digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _json_copy(value: object) -> object:
    """Detach durable evidence from mutable state and caller-owned dictionaries."""
    return json.loads(json.dumps(value, sort_keys=True))


def _originating_step(state: dict, step: dict) -> dict:
    plan = state.get("plan") if isinstance(state.get("plan"), dict) else {}
    if plan_hash(plan) != state.get("plan_hash"):
        raise RuntimeError("operation attribution approved-plan origin is stale or altered")
    steps = plan.get("steps") if isinstance(plan.get("steps"), list) else []
    step_id = int(step.get("id") or 0) if isinstance(step, dict) else 0
    matches = [item for item in steps if isinstance(item, dict) and int(item.get("id") or 0) == step_id]
    if len(matches) != 1 or not isinstance(step, dict) or _evidence_digest(matches[0]) != _evidence_digest(step):
        raise RuntimeError("operation attribution has missing or ambiguous approved-step origin")
    return matches[0]


def _checkpoint_identity(checkpoint_id: str, checkpoint: dict) -> dict:
    manifest = RECOVERY / checkpoint_id / "manifest.json"
    if not manifest.is_file():
        raise RuntimeError("operation attribution approval checkpoint manifest is missing")
    identity = {
        "id": checkpoint_id,
        "ref": checkpoint.get("ref"),
        "recovery_oid": checkpoint.get("recovery_oid"),
        "manifest_sha256": file_hash(manifest),
    }
    if not all(isinstance(identity[key], str) and identity[key] for key in ("id", "ref", "recovery_oid", "manifest_sha256")):
        raise RuntimeError("operation attribution approval checkpoint identity is invalid")
    return identity


def _self_hosting_grants_for_origin(state: dict, step_no: int, path: str) -> list[dict]:
    """Return durable grants that explicitly cover one originating tooling path."""
    if not is_tooling_path(path):
        return []
    candidates: list[dict] = []
    active = state.get("self_hosting_grant")
    history = state.get("self_hosting_grant_history")
    for raw in [active, *((history if isinstance(history, list) else []))]:
        if not isinstance(raw, dict):
            continue
        if raw.get("plan_hash") != state.get("plan_hash") or int(raw.get("step") or 0) != int(step_no):
            continue
        paths = sorted({_normalize_repo_path(str(item)) for item in raw.get("paths") or [] if str(item).strip()})
        if path not in paths:
            continue
        candidate = _json_copy(raw)
        if candidate not in candidates:
            candidates.append(candidate)
    candidates.sort(key=lambda item: str(item.get("granted_at") or ""))
    return candidates


def _origin_self_hosting_grant(state: dict, origin_step: dict, path: str) -> dict | None:
    if not is_tooling_path(path):
        return None
    step_no = int(origin_step["id"])
    grants = _self_hosting_grants_for_origin(state, step_no, path)
    if not grants:
        raise RuntimeError("operation attribution has no applicable durable self-hosting grant")
    # Prefer the currently active exact grant when it is applicable. Otherwise
    # use the newest durable grant for the originating step. This is critical
    # when validating accepted operations after the controller has moved on to
    # a later step and the active grant has changed.
    active = state.get("self_hosting_grant") if isinstance(state.get("self_hosting_grant"), dict) else None
    if active is not None:
        active_copy = _json_copy(active)
        if active_copy in grants:
            return active_copy
    return grants[-1]


def _reconciliation_evidence(state: dict) -> dict:
    if state.get("retirement_record_id"):
        snapshot = reconciliation_snapshot(state)
        return {"schema": "zen_ralph_operation_reconciliation_v1", "state": "replacement", "snapshot": _json_copy(snapshot)}
    return {"schema": "zen_ralph_operation_reconciliation_v1", "state": "not-applicable"}


def _operation_record_hash(record: dict) -> str:
    unsigned = {key: value for key, value in record.items() if key != "record_sha256"}
    return _evidence_digest(unsigned)


def _validated_operation_records(state: dict) -> list[dict]:
    """Validate native attribution records before they can confer plan ownership."""
    records = state.get("operation_attributions")
    if not isinstance(records, list):
        raise RuntimeError("operation attribution collection is invalid")
    checkpoint = verify_approval_execution_evidence(state)
    checkpoint_id = str(state.get("recovery_checkpoint") or "")
    artifact = state["approved_plan_artifact"]
    evidence = checkpoint["repository_evidence"]
    expected_checkpoint = _checkpoint_identity(checkpoint_id, checkpoint)
    plan = state.get("plan") if isinstance(state.get("plan"), dict) else {}
    repository_authority = plan.get(REPOSITORY_AUTHORITY_FIELD)
    if not isinstance(repository_authority, str) or not repository_authority:
        raise RuntimeError("operation attribution repository authority is invalid")
    seen: set[tuple[str, int, int]] = set()
    accepted: list[dict] = []
    for record in records:
        if not isinstance(record, dict) or record.get("schema") != OPERATION_ATTRIBUTION_SCHEMA:
            raise RuntimeError("operation attribution record schema is invalid")
        required = {
            "schema", "record_sha256", "plan_hash", "approved_plan_artifact", "approved_plan_artifact_sha256",
            "approval_checkpoint", "approval_repository_evidence", "approval_repository_evidence_sha256",
            "repository_authority", "loop", "originating_step", "originating_step_sha256",
            "originating_test_change_policy", "self_hosting_grant", "self_hosting_grant_sha256",
            "path", "baseline_kind", "operation", "current_fingerprint", "controller_verification",
            "reconciliation_evidence",
        }
        if set(record) != required or record.get("record_sha256") != _operation_record_hash(record):
            raise RuntimeError("operation attribution record is incomplete or altered")
        if record["plan_hash"] != state.get("plan_hash") or record["approved_plan_artifact"] != artifact or record["approved_plan_artifact_sha256"] != _evidence_digest(artifact):
            raise RuntimeError("operation attribution approved-artifact origin is stale or altered")
        if record["approval_checkpoint"] != expected_checkpoint or record["approval_repository_evidence"] != evidence or record["approval_repository_evidence_sha256"] != _evidence_digest(evidence):
            raise RuntimeError("operation attribution approval checkpoint/evidence origin is stale or altered")
        if record["repository_authority"] != repository_authority:
            raise RuntimeError("operation attribution repository authority is stale or altered")
        origin = _originating_step(state, record["originating_step"])
        if record["originating_step_sha256"] != _evidence_digest(origin) or record["originating_test_change_policy"] != origin.get("test_change_policy"):
            raise RuntimeError("operation attribution originating test policy is stale or altered")
        path = _normalize_repo_path(str(record["path"] or ""))
        if not path or path != record["path"] or path in approval_baseline_residue_paths(state) or is_protected_path(path) or _is_runtime_authority_path(path):
            raise RuntimeError("operation attribution path is protected, runtime, residue, or ambiguous")
        baseline = plan_baseline_path_kind(state, path)
        if record["baseline_kind"] != baseline or baseline not in {"tracked", "absent"}:
            raise RuntimeError("operation attribution baseline classification is invalid")
        fingerprint = record["current_fingerprint"]
        if not isinstance(fingerprint, dict) or fingerprint.get("kind") not in {"tracked", "untracked", "missing"}:
            raise RuntimeError("operation attribution current fingerprint is invalid")
        expected_operation = "create" if baseline == "absent" and fingerprint["kind"] != "missing" else ("delete" if fingerprint["kind"] == "missing" else "edit")
        if record["operation"] != expected_operation:
            raise RuntimeError("operation attribution kind is invalid")
        grant = record["self_hosting_grant"]
        if is_tooling_path(path):
            history = state.get("self_hosting_grant_history") if isinstance(state.get("self_hosting_grant_history"), list) else []
            if not isinstance(grant, dict) or grant not in history or record["self_hosting_grant_sha256"] != _evidence_digest(grant):
                raise RuntimeError("operation attribution self-hosting grant is missing or altered")
            allowed, reason = self_hosting_grant_allows({**state, "self_hosting_grant": grant}, int(origin["id"]), [path])
            if not allowed:
                raise RuntimeError(f"operation attribution self-hosting grant is stale: {reason}")
        elif grant is not None or record["self_hosting_grant_sha256"] is not None:
            raise RuntimeError("operation attribution has inapplicable self-hosting grant evidence")
        verification = record["controller_verification"]
        if not isinstance(verification, dict) or verification.get("schema") != "zen_ralph_post_turn_repository_verification_v1" or verification.get("state") != "PASS" or verification.get("checkpoint") != checkpoint_id or verification.get("plan_hash") != state.get("plan_hash") or int(verification.get("step") or 0) != int(origin["id"]) or path not in verification.get("new_project_delta", []):
            raise RuntimeError("operation attribution controller verification evidence is invalid")
        fingerprints = verification.get("current_fingerprints")
        if not isinstance(fingerprints, dict) or fingerprints.get(path) != fingerprint:
            raise RuntimeError("operation attribution current fingerprint evidence is stale or altered")
        reconciliation = record["reconciliation_evidence"]
        if reconciliation != _reconciliation_evidence(state):
            raise RuntimeError("operation attribution reconciliation evidence is stale or altered")
        key = (path, int(record["loop"]), int(origin["id"]))
        if key in seen:
            raise RuntimeError(f"duplicate operation attribution record: {path}")
        seen.add(key)
        accepted.append(record)
    return accepted


def _latest_operation_records_by_path(state: dict) -> dict[str, dict]:
    """Return the newest validated accepted record for each path."""
    latest: dict[str, dict] = {}
    for record in _validated_operation_records(state):
        path = str(record["path"])
        origin = record.get("originating_step") if isinstance(record.get("originating_step"), dict) else {}
        key = (int(record.get("loop") or 0), int(origin.get("id") or 0))
        current = latest.get(path)
        if current is None:
            latest[path] = record
            continue
        current_origin = current.get("originating_step") if isinstance(current.get("originating_step"), dict) else {}
        current_key = (int(current.get("loop") or 0), int(current_origin.get("id") or 0))
        if key > current_key:
            latest[path] = record
    return latest


def current_attributed_paths(state: dict) -> list[str]:
    """Return accepted paths whose newest attribution still matches the worktree."""
    covered: list[str] = []
    for path, record in _latest_operation_records_by_path(state).items():
        if record.get("current_fingerprint") == retirement_path_fingerprint(path):
            covered.append(path)
    return sorted(covered)


def _pending_step_paths(state: dict, step_no: int) -> set[str]:
    pending = state.get("pending_step_delta_paths")
    if not isinstance(pending, dict) or int(pending.get("step") or 0) != int(step_no):
        return set()
    return {
        _normalize_repo_path(str(path))
        for path in pending.get("paths") or []
        if _normalize_repo_path(str(path))
    }


def _remember_pending_step_paths(state: dict, step_no: int, paths: Iterable[str]) -> None:
    existing = _pending_step_paths(state, step_no)
    existing.update(
        _normalize_repo_path(str(path))
        for path in paths
        if _normalize_repo_path(str(path))
    )
    state["pending_step_delta_paths"] = {
        "step": int(step_no),
        "paths": sorted(existing),
        "updated_at": utc_now(),
    }


def _clear_pending_step_paths(state: dict) -> None:
    state["pending_step_delta_paths"] = []


def validated_plan_paths(state: dict, *, owned_only: bool = False) -> list[str]:
    records = _validated_operation_records(state)
    return sorted({str(record["path"]) for record in records if not owned_only or record["baseline_kind"] == "absent"})


def strict_native_provenance(
    state: dict, phase: str, *, require_current_delta: bool = True, require_write: bool = True,
) -> dict:
    """Validate the sole native authority chain used by qualification and terminals.

    Filename projections such as ``plan_changed_files`` are intentionally absent
    from this decision.  Authority comes only from the approval bindings plus the
    validated native operation ledger.  Historical operation policy/grant evidence
    is validated by ``_validated_operation_records`` against each originating step.
    """
    checkpoint = verify_approval_execution_evidence(state)
    plan = state.get("plan") if isinstance(state.get("plan"), dict) else {}
    if plan_hash(plan) != state.get("plan_hash"):
        raise RuntimeError(f"{phase} native provenance plan hash is stale or altered")
    authority = str(plan.get(REPOSITORY_AUTHORITY_FIELD) or "")
    if authority not in REPOSITORY_AUTHORITIES:
        raise RuntimeError(f"{phase} native provenance repository authority is missing or invalid")
    if require_write and authority != "write":
        raise RuntimeError(f"{phase} requires write repository authority")

    records = _validated_operation_records(state)
    latest = _latest_operation_records_by_path(state)
    reconciliation = _reconciliation_evidence(state)
    checkpoint_id = str(state.get("recovery_checkpoint") or "")
    artifact = state.get("approved_plan_artifact")
    evidence = checkpoint.get("repository_evidence")
    binding = {
        "schema": "zen_ralph_native_provenance_binding_v1",
        "plan_hash": str(state.get("plan_hash") or ""),
        "approved_plan_artifact_sha256": _evidence_digest(artifact),
        "approval_checkpoint": _checkpoint_identity(checkpoint_id, checkpoint),
        "approval_repository_evidence_sha256": _evidence_digest(evidence),
        "repository_authority": authority,
        "operations": [
            {
                "path": path,
                "record_sha256": str(record.get("record_sha256") or ""),
                "loop": int(record.get("loop") or 0),
                "originating_step_sha256": str(record.get("originating_step_sha256") or ""),
                "originating_test_change_policy": str(record.get("originating_test_change_policy") or ""),
                "self_hosting_grant_sha256": record.get("self_hosting_grant_sha256"),
                "current_fingerprint": _json_copy(record.get("current_fingerprint")),
            }
            for path, record in sorted(latest.items())
        ],
        "reconciliation_evidence": _json_copy(reconciliation),
    }
    binding_sha256 = _evidence_digest(binding)

    if authority == "write" and require_write and not latest:
        raise RuntimeError(f"{phase} native provenance has no accepted write attribution")
    if authority == "read-only" and records:
        raise RuntimeError(f"{phase} read-only provenance contains operation attribution")

    result = {
        "schema": "zen_ralph_strict_native_provenance_v1",
        "binding": binding,
        "binding_sha256": binding_sha256,
        "new_plan_paths": sorted(latest),
        "repository_authority": authority,
    }
    if not require_current_delta:
        return result

    repository = recompute_repository_against_approval_checkpoint(state)
    changed_residue = sorted(repository.get("changed_approval_residue") or [])
    if changed_residue:
        raise RuntimeError(f"{phase} refuses changed approval residue: {changed_residue}")
    current_delta = {
        _normalize_repo_path(str(path))
        for path in repository.get("new_project_delta") or []
        if _normalize_repo_path(str(path))
    }
    attributed = set(latest)
    if authority == "read-only":
        if current_delta:
            raise RuntimeError(f"{phase} read-only provenance has repository delta: {sorted(current_delta)}")
    elif current_delta != attributed:
        raise RuntimeError(
            f"{phase} native provenance delta mismatch: "
            f"unattributed={sorted(current_delta - attributed)} stale={sorted(attributed - current_delta)}"
        )

    current_fingerprints: dict[str, dict] = {}
    for path, record in sorted(latest.items()):
        current = retirement_path_fingerprint(path)
        if record.get("current_fingerprint") != current:
            raise RuntimeError(f"{phase} native provenance fingerprint is stale or altered: {path}")
        current_fingerprints[path] = current
    result["current_delta"] = sorted(current_delta)
    result["current_fingerprints"] = current_fingerprints
    result["current_sha256"] = _evidence_digest({
        "binding_sha256": binding_sha256,
        "current_delta": result["current_delta"],
        "current_fingerprints": current_fingerprints,
    })
    return result


def verified_read_only_completion(state: dict, phase: str = "read-only completion") -> dict:
    """Prove that a read-only plan has no repository mutation authority to finalize.

    READ_ONLY_COMPLETE is deliberately not a commit-capable state.  Admission is
    derived from the approval/checkpoint binding and the native operation ledger,
    never from filename projections.  Cached ownership/change projections must also
    remain empty so the durable state cannot contradict the native zero-delta proof.
    """
    provenance = strict_native_provenance(
        state, phase, require_current_delta=True, require_write=False,
    )
    if provenance.get("repository_authority") != "read-only":
        raise RuntimeError(f"{phase} requires read-only repository authority")
    if provenance.get("new_plan_paths"):
        raise RuntimeError(f"{phase} refuses native operation attribution")
    if validated_plan_paths(state, owned_only=True):
        raise RuntimeError(f"{phase} refuses native plan ownership")
    projected_changes = sorted({
        _normalize_repo_path(str(path))
        for path in state.get("plan_changed_files") or []
        if _normalize_repo_path(str(path))
    })
    projected_owned = sorted({
        _normalize_repo_path(str(path))
        for path in state.get("plan_owned_files") or []
        if _normalize_repo_path(str(path))
    })
    if projected_changes or projected_owned:
        raise RuntimeError(
            f"{phase} refuses stale read-only ownership projections: "
            f"changed={projected_changes} owned={projected_owned}"
        )
    return provenance


def _qualified_native_provenance(
    state: dict, phase: str, *, require_current_delta: bool, require_write: bool = True,
) -> dict:
    qualification = state.get("final_qualification") if isinstance(state.get("final_qualification"), dict) else {}
    if qualification.get("state") != "PASS":
        raise RuntimeError(f"{phase} requires PASS final qualification")
    provenance = strict_native_provenance(
        state, phase, require_current_delta=require_current_delta, require_write=require_write,
    )
    expected = str(qualification.get("native_provenance_sha256") or "")
    if not expected or not secrets.compare_digest(expected, provenance["binding_sha256"]):
        raise RuntimeError(f"{phase} native provenance binding is missing, stale, or altered")
    if require_current_delta:
        delta = str(qualification.get("delta_fingerprint") or "")
        if not delta or not secrets.compare_digest(delta, provenance.get("current_sha256") or ""):
            raise RuntimeError(f"{phase} qualified repository delta is stale or altered")
    return provenance


def _commit_blob_sha256(commit_sha: str, path: str) -> str | None:
    """Return one commit blob content digest, or ``None`` when the path is absent."""
    exists = subprocess.run(
        ["git", "cat-file", "-e", f"{commit_sha}:{path}"], cwd=ROOT,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    if exists.returncode != 0:
        return None
    proc = subprocess.run(
        ["git", "show", f"{commit_sha}:{path}"], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"cannot inspect commit content for {path}")
    return hashlib.sha256(proc.stdout).hexdigest()


def _verify_commit_native_provenance(state: dict, commit_sha: str, provenance: dict, phase: str) -> list[str]:
    """Prove a consumed commit exactly contains the qualified native operation set."""
    planned = set(provenance.get("new_plan_paths") or [])
    commit_paths = set(_commit_paths(commit_sha))
    if commit_paths != planned:
        raise RuntimeError(
            f"{phase} commit scope differs from native provenance: "
            f"missing={sorted(planned - commit_paths)} unexpected={sorted(commit_paths - planned)}"
        )
    latest = _latest_operation_records_by_path(state)
    for path in sorted(planned):
        record = latest[path]
        operation = str(record.get("operation") or "")
        expected_content = (record.get("current_fingerprint") or {}).get("content_sha256")
        actual_content = _commit_blob_sha256(commit_sha, path)
        if operation == "delete":
            if actual_content is not None:
                raise RuntimeError(f"{phase} deleted path remains present in commit: {path}")
        elif not expected_content or actual_content != expected_content:
            raise RuntimeError(f"{phase} commit content differs from qualified attribution: {path}")
    return sorted(commit_paths)


def verified_attribution_result(
    state: dict, step: dict, verification: dict, observed_paths: Iterable[str], *, loop: int, phase: str,
) -> dict:
    """Turn checkpoint verification into the sole authority for accepted paths.

    ``observed_paths`` remains useful as a per-turn witness, but can never by
    itself make a path plan-owned.  Conversely, a pre-existing accepted delta
    remains visible in checkpoint evidence without being re-attributed to a
    later turn.
    """
    checkpoint = verify_approval_execution_evidence(state)
    checkpoint_id = str(state.get("recovery_checkpoint") or "")
    origin_step = _originating_step(state, step)
    if verification.get("state") != "PASS" or verification.get("sandbox") not in {"read-only", "workspace-write"}:
        raise RuntimeError("verified attribution requires a passing controller checkpoint verification")
    if verification.get("checkpoint") != checkpoint_id or verification.get("plan_hash") != state.get("plan_hash"):
        raise RuntimeError("verified attribution does not match the active approval checkpoint")
    verification_fingerprints = verification.get("current_fingerprints")
    if not isinstance(verification_fingerprints, dict):
        raise RuntimeError("verified attribution requires controller current-fingerprint evidence")

    verified_delta = {
        _normalize_repo_path(str(path)) for path in verification.get("new_project_delta") or []
        if _normalize_repo_path(str(path))
    }
    observed = {
        _normalize_repo_path(str(path)) for path in observed_paths
        if _normalize_repo_path(str(path))
    }
    pending = _pending_step_paths(state, int(origin_step["id"]))
    witness = observed | pending
    latest = _latest_operation_records_by_path(state)
    paths = sorted(
        path for path in (verified_delta & witness)
        if path not in latest
        or latest[path].get("current_fingerprint") != verification_fingerprints.get(path)
    )
    if verification["sandbox"] == "read-only" and paths:
        raise RuntimeError(f"read-only turn cannot create attributed operations: {paths}")

    residue = approval_baseline_residue_paths(state)
    operations: list[dict] = []
    for raw_path in paths:
        if not raw_path or raw_path in residue or is_protected_path(raw_path) or _is_runtime_authority_path(raw_path):
            raise RuntimeError(f"verified attribution includes forbidden path: {raw_path}")
        baseline_kind = plan_baseline_path_kind(state, raw_path)
        if baseline_kind in {"preexisting-dirty", "preexisting-untracked", "unknown"}:
            raise RuntimeError(f"verified attribution includes non-plan baseline path: {raw_path}")
        current = verification_fingerprints.get(raw_path)
        if not isinstance(current, dict) or current != retirement_path_fingerprint(raw_path):
            raise RuntimeError(f"verified attribution current fingerprint is missing or stale: {raw_path}")
        operation = "create" if baseline_kind == "absent" and current["kind"] != "missing" else ("delete" if current["kind"] == "missing" else "edit")
        grant = _origin_self_hosting_grant(state, origin_step, raw_path)
        record = {
            "schema": OPERATION_ATTRIBUTION_SCHEMA,
            "plan_hash": state["plan_hash"],
            "approved_plan_artifact": _json_copy(state["approved_plan_artifact"]),
            "approved_plan_artifact_sha256": _evidence_digest(state["approved_plan_artifact"]),
            "approval_checkpoint": _checkpoint_identity(checkpoint_id, checkpoint),
            "approval_repository_evidence": _json_copy(checkpoint["repository_evidence"]),
            "approval_repository_evidence_sha256": _evidence_digest(checkpoint["repository_evidence"]),
            "repository_authority": state["plan"][REPOSITORY_AUTHORITY_FIELD],
            "loop": loop,
            "originating_step": _json_copy(origin_step),
            "originating_step_sha256": _evidence_digest(origin_step),
            "originating_test_change_policy": origin_step["test_change_policy"],
            "self_hosting_grant": grant,
            "self_hosting_grant_sha256": _evidence_digest(grant) if grant is not None else None,
            "path": raw_path,
            "baseline_kind": baseline_kind,
            "operation": operation,
            "current_fingerprint": current,
            "controller_verification": _json_copy(verification),
            "reconciliation_evidence": _reconciliation_evidence(state),
        }
        record["record_sha256"] = _operation_record_hash(record)
        operations.append(record)
    return {
        "schema": "zen_ralph_verified_attribution_v1",
        "plan_hash": state["plan_hash"],
        "checkpoint": checkpoint_id,
        "loop": loop,
        "step": step,
        "phase": phase,
        "sandbox": verification["sandbox"],
        "paths": paths,
        "operations": operations,
        "verification_fingerprint": verification.get("fingerprint"),
    }


def record_accepted_operations(state: dict, attribution: dict) -> list[dict]:
    """Persist only the operation records produced by verified attribution."""
    if attribution.get("schema") != "zen_ralph_verified_attribution_v1":
        raise RuntimeError("accepted operation recording requires verified attribution")
    if attribution.get("plan_hash") != state.get("plan_hash") or attribution.get("checkpoint") != state.get("recovery_checkpoint"):
        raise RuntimeError("accepted operation attribution does not match active plan authority")
    accepted = [dict(item) for item in attribution.get("operations") or [] if isinstance(item, dict)]
    existing = state.get("operation_attributions")
    if not isinstance(existing, list):
        raise RuntimeError("operation attribution collection is invalid")
    # Validate the proposed collection before mutating controller state.  A
    # malformed or duplicate native record must not become durable evidence,
    # even transiently on an error path.
    prospective = dict(state)
    # A grant used for an accepted native record remains evidence even after
    # the one-step active grant is cleared.  Retain the exact grant before
    # validation; do not later reconstruct it from the mutable active field.
    history = list(state.get("self_hosting_grant_history") or [])
    for record in accepted:
        grant = record.get("self_hosting_grant")
        if isinstance(grant, dict) and grant not in history:
            history.append(_json_copy(grant))
    prospective["self_hosting_grant_history"] = history[-20:]
    prospective["operation_attributions"] = [*existing, *accepted]
    validated = _validated_operation_records(prospective)
    state["self_hosting_grant_history"] = prospective["self_hosting_grant_history"]
    state["operation_attributions"] = prospective["operation_attributions"]
    state["plan_changed_files"] = sorted({str(item["path"]) for item in validated})
    state["plan_owned_files"] = sorted({str(item["path"]) for item in validated if item["baseline_kind"] == "absent"})
    return accepted


def _accepted_step_results_by_id(state: dict) -> dict[int, dict]:
    accepted: dict[int, dict] = {}
    for item in state.get("step_results") or []:
        if not isinstance(item, dict) or item.get("result") != "PASS":
            continue
        step_no = int(item.get("step") or 0)
        if step_no > 0:
            accepted[step_no] = item
    return accepted


def _step_by_id(state: dict, step_no: int) -> dict:
    plan = state.get("plan") if isinstance(state.get("plan"), dict) else {}
    matches = [
        item for item in plan.get("steps") or []
        if isinstance(item, dict) and int(item.get("id") or 0) == int(step_no)
    ]
    if len(matches) != 1:
        raise RuntimeError(f"self-upgrade recovery cannot resolve approved step {step_no}")
    return matches[0]


def _recovery_verification_for_path(
    state: dict, origin_step: dict, path: str, fingerprint: dict, *, loop: int, source: str,
) -> dict:
    verification = {
        "schema": "zen_ralph_post_turn_repository_verification_v1",
        "state": "PASS",
        "sandbox": "workspace-write",
        "checkpoint": state.get("recovery_checkpoint"),
        "plan_hash": state.get("plan_hash"),
        "new_project_delta": [path],
        "changed_approval_residue": [],
        "current_fingerprints": {path: _json_copy(fingerprint)},
        "loop": int(loop),
        "step": int(origin_step["id"]),
        "recorded_at": utc_now(),
        "recovery": {
            "schema": "zen_ralph_self_upgrade_attribution_recovery_v1",
            "source": source,
            "recovered_at": utc_now(),
        },
    }
    verification["fingerprint"] = _evidence_digest(
        {key: value for key, value in verification.items() if key != "fingerprint"}
    )
    return verification


def _native_recovery_record(
    state: dict, origin_step: dict, path: str, fingerprint: dict, *, loop: int, source: str,
) -> dict:
    checkpoint_id = str(state.get("recovery_checkpoint") or "")
    checkpoint = verify_approval_execution_evidence(state)
    baseline_kind = plan_baseline_path_kind(state, path)
    if baseline_kind not in {"tracked", "absent"}:
        raise RuntimeError(f"self-upgrade recovery refuses non-plan baseline path: {path}")
    if path in approval_baseline_residue_paths(state) or is_protected_path(path) or _is_runtime_authority_path(path):
        raise RuntimeError(f"self-upgrade recovery refuses protected/runtime/residue path: {path}")
    if not isinstance(fingerprint, dict) or fingerprint.get("kind") not in {"tracked", "untracked", "missing"}:
        raise RuntimeError(f"self-upgrade recovery has invalid fingerprint: {path}")
    operation = "create" if baseline_kind == "absent" and fingerprint["kind"] != "missing" else (
        "delete" if fingerprint["kind"] == "missing" else "edit"
    )
    grant = _origin_self_hosting_grant(state, origin_step, path)
    verification = _recovery_verification_for_path(
        state, origin_step, path, fingerprint, loop=loop, source=source,
    )
    record = {
        "schema": OPERATION_ATTRIBUTION_SCHEMA,
        "plan_hash": state["plan_hash"],
        "approved_plan_artifact": _json_copy(state["approved_plan_artifact"]),
        "approved_plan_artifact_sha256": _evidence_digest(state["approved_plan_artifact"]),
        "approval_checkpoint": _checkpoint_identity(checkpoint_id, checkpoint),
        "approval_repository_evidence": _json_copy(checkpoint["repository_evidence"]),
        "approval_repository_evidence_sha256": _evidence_digest(checkpoint["repository_evidence"]),
        "repository_authority": state["plan"][REPOSITORY_AUTHORITY_FIELD],
        "loop": int(loop),
        "originating_step": _json_copy(origin_step),
        "originating_step_sha256": _evidence_digest(origin_step),
        "originating_test_change_policy": origin_step["test_change_policy"],
        "self_hosting_grant": grant,
        "self_hosting_grant_sha256": _evidence_digest(grant) if grant is not None else None,
        "path": path,
        "baseline_kind": baseline_kind,
        "operation": operation,
        "current_fingerprint": _json_copy(fingerprint),
        "controller_verification": verification,
        "reconciliation_evidence": _reconciliation_evidence(state),
    }
    record["record_sha256"] = _operation_record_hash(record)
    return record


def _legacy_v1_origin_step(state: dict, record: dict) -> dict:
    raw = record.get("step")
    if isinstance(raw, dict):
        return _originating_step(state, raw)
    try:
        step_no = int(raw)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("self-upgrade recovery found v1 attribution without an approved step") from exc
    return _step_by_id(state, step_no)


def _accepted_origin_for_recovery(state: dict, path: str, accepted: dict[int, dict]) -> tuple[dict, int]:
    baseline = plan_baseline_path_kind(state, path)
    candidates: list[tuple[int, dict, int]] = []
    for step_no, result in accepted.items():
        step = _step_by_id(state, step_no)
        policy = str(step.get("test_change_policy") or "none")
        if path == "tests" or path.startswith("tests/"):
            if policy == "none" or (policy == "add-only" and baseline != "absent"):
                continue
        if is_tooling_path(path):
            if not _self_hosting_grants_for_origin(state, step_no, path):
                continue
        elif path not in {_normalize_repo_path(str(item)) for item in result.get("files") or []}:
            continue
        attr = result.get("attribution") if isinstance(result.get("attribution"), dict) else {}
        loop = int(attr.get("loop") or result.get("loop") or 0)
        candidates.append((step_no, step, loop))
    if not candidates:
        raise RuntimeError(f"self-upgrade recovery cannot prove an accepted origin for: {path}")
    _step_no, step, loop = sorted(candidates, key=lambda item: item[0])[-1]
    return step, loop


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
    return _normalize_repo_path(str(path)) in set(validated_plan_paths(state, owned_only=True))


def approval_baseline_residue_paths(state: dict) -> set[str]:
    """Return paths that were already dirty/untracked when this plan was approved."""
    checkpoint = load_recovery_checkpoint(state.get("recovery_checkpoint"))
    if not checkpoint:
        return set()
    return {
        _normalize_repo_path(str(path))
        for path in [
            *(checkpoint.get("baseline_dirty_paths") or []),
            *(checkpoint.get("baseline_untracked_paths") or []),
        ]
        if str(path).strip()
    }


def _project_repository_evidence(evidence: dict) -> dict[str, dict]:
    """Normalize checkpoint/current residue evidence without treating it as plan work."""
    records = evidence.get("operator_residue") if isinstance(evidence, dict) else []
    result: dict[str, dict] = {}
    for item in records if isinstance(records, list) else []:
        if not isinstance(item, dict):
            continue
        path = _normalize_repo_path(str(item.get("path") or ""))
        if not path or _is_runtime_authority_path(path):
            continue
        result[path] = {key: value for key, value in item.items() if key != "ownership"}
    return result


def recompute_repository_against_approval_checkpoint(state: dict) -> dict:
    """Independently compare the current project worktree with approval evidence."""
    checkpoint_id = str(state.get("recovery_checkpoint") or "")
    checkpoint = load_recovery_checkpoint(checkpoint_id)
    if not checkpoint or checkpoint.get("plan_hash") != state.get("plan_hash"):
        raise RuntimeError("post-turn verification requires the matching approval checkpoint")
    expected_evidence = checkpoint.get("repository_evidence")
    if not isinstance(expected_evidence, dict) or expected_evidence.get("schema") != "zen_ralph_approval_repository_evidence_v1":
        raise RuntimeError("post-turn verification requires structured approval repository evidence")

    expected = _project_repository_evidence(expected_evidence)
    current = _project_repository_evidence(approval_repository_evidence())
    expected_paths, current_paths = set(expected), set(current)
    changed_residue = sorted(
        path for path in expected_paths
        if path not in current or current[path] != expected[path]
    )
    new_delta = sorted(current_paths - expected_paths)
    evidence = {
        "schema": "zen_ralph_post_turn_repository_verification_v1",
        "checkpoint": checkpoint_id,
        "plan_hash": state.get("plan_hash"),
        "new_project_delta": new_delta,
        "changed_approval_residue": changed_residue,
    }
    evidence["fingerprint"] = hashlib.sha256(
        json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return evidence


def verify_post_turn_repository_state(
    state: dict, step: dict, sandbox: str, observed_paths: Iterable[str],
) -> dict:
    """Fail closed on checkpoint-relative deltas before any outcome decision.

    This deliberately recomputes Git/content evidence rather than trusting the
    pre-turn in-memory snapshot.  Sandboxing limits what a turn can do; this is
    the authority decision that determines whether its result can proceed.
    """
    evidence = recompute_repository_against_approval_checkpoint(state)
    new_delta = set(evidence["new_project_delta"])
    changed_residue = list(evidence["changed_approval_residue"])
    if sandbox == "read-only":
        if new_delta or changed_residue:
            raise RuntimeError(
                "READ_ONLY_CHECKPOINT_DELTA: "
                f"new={sorted(new_delta)} residue_changed={changed_residue}"
            )
        return evidence | {"sandbox": sandbox, "state": "PASS"}
    if sandbox != "workspace-write":
        raise RuntimeError(f"post-turn verification received unsupported sandbox {sandbox!r}")
    if changed_residue:
        raise RuntimeError(f"APPROVAL_RESIDUE_CHANGED: {changed_residue}")

    recorded = set(current_attributed_paths(state))
    pending = _pending_step_paths(state, int(step["id"]))
    observed = {_normalize_repo_path(str(path)) for path in observed_paths if _normalize_repo_path(str(path))}
    candidates = recorded | pending | observed
    unexpected = sorted(new_delta - candidates)
    if unexpected:
        raise RuntimeError(f"UNATTRIBUTED_CHECKPOINT_DELTA: {unexpected}")
    protected = sorted(path for path in new_delta if is_protected_path(path) or _is_runtime_authority_path(path))
    if protected:
        raise RuntimeError(f"CHECKPOINT_PROTECTED_OR_RUNTIME_DELTA: {protected}")
    # Accepted paths whose current fingerprints still match their native record
    # retain their originating step/grant authority. Only uncovered current
    # delta is governed by the live step's self-hosting and test policy.
    current_step_delta = new_delta - recorded
    tooling = sorted(path for path in current_step_delta if is_tooling_path(path))
    authorized_tooling = authorized_self_hosting_paths(state)
    current_grant, _grant_reason = self_hosting_grant_allows(state, int(step["id"]), tooling) if tooling else (True, "")
    if tooling and not current_grant:
        unauthorized = sorted(set(tooling) - authorized_tooling)
        if unauthorized:
            raise RuntimeError(f"CHECKPOINT_UNAUTHORIZED_TOOLING_DELTA: {unauthorized}")
    after = {path: "checkpoint-delta" for path in current_step_delta}
    test_violations = test_policy_violation(
        {}, after, str(step.get("test_change_policy") or "none"), state=state, step_no=int(step["id"]),
    )
    if test_violations:
        raise RuntimeError(f"CHECKPOINT_TEST_POLICY_DELTA: {test_violations}")
    return evidence | {
        "sandbox": sandbox,
        "state": "PASS",
        # These controller-derived categories are retained with the successful
        # verification so later acceptance cannot reinterpret raw model paths.
        "verified_tooling_paths": tooling,
        "verified_test_paths": sorted(path for path in new_delta if path == "tests" or path.startswith("tests/")),
    }


def record_post_turn_repository_verification(
    state: dict, step: dict, sandbox: str, observed_paths: Iterable[str], *, loop: int,
) -> dict:
    """Retain PASS/refusal evidence so every model turn has an audit record."""
    try:
        verification = verify_post_turn_repository_state(state, step, sandbox, observed_paths)
    except RuntimeError as exc:
        verification = {
            "schema": "zen_ralph_post_turn_repository_verification_v1",
            "state": "REFUSED",
            "sandbox": sandbox,
            "checkpoint": state.get("recovery_checkpoint"),
            "plan_hash": state.get("plan_hash"),
            "loop": loop,
            "step": int(step["id"]),
            "error": str(exc),
            "recorded_at": utc_now(),
        }
    else:
        verification = verification | {
            "loop": loop,
            "step": int(step["id"]),
            "recorded_at": utc_now(),
            "current_fingerprints": {
                path: retirement_path_fingerprint(path)
                for path in verification.get("new_project_delta") or []
            },
        }
    state["last_post_turn_verification"] = verification
    return verification


def remember_plan_files(state: dict, paths: Iterable[str]) -> None:
    requested = sorted({_normalize_repo_path(str(path)) for path in paths if _normalize_repo_path(str(path))})
    derived = validated_plan_paths(state)
    missing = set(requested) - set(derived)
    # Replacement reconciliation can ask the controller to re-verify a
    # checkpoint-relative delta.  This preserves the old reconciliation flow
    # without allowing filenames to confer ownership: only records generated
    # by the same native attribution verifier can update the display lists.
    if missing and state.get("retirement_record_id"):
        step_no = int(state.get("current_step") or 0)
        steps = list(((state.get("plan") or {}).get("steps") or []))
        if not (1 <= step_no <= len(steps)):
            raise RuntimeError("replacement reconciliation cannot resolve the current approved step")
        step = steps[step_no - 1]
        verification = record_post_turn_repository_verification(
            state, step, "workspace-write", requested,
            loop=int(state.get("loop_count") or 0),
        )
        if verification.get("state") == "PASS":
            attribution = verified_attribution_result(
                state, step, verification, requested,
                loop=int(state.get("loop_count") or 0), phase="controller-reconciliation",
            )
            record_accepted_operations(state, attribution)
            derived = validated_plan_paths(state)
        missing = set(requested) - set(derived)
    # Approval-time residue is deliberately visible to reconciliation but can
    # never become native plan ownership or cause a raw-path rejection.
    if missing - approval_baseline_residue_paths(state):
        raise RuntimeError("plan file ownership requires validated native operation attribution")
    state["plan_changed_files"] = derived
    state["plan_owned_files"] = validated_plan_paths(state, owned_only=True)


_CARRY_FORWARD_PENDING = "PENDING_RECONCILIATION"
_CARRY_FORWARD_ADOPTED = "ADOPTED_PLAN_CARRY_FORWARD"
_CARRY_FORWARD_OUTSIDE = "LEFT_OUTSIDE_PLAN_BOUNDARY"
_CARRY_FORWARD_REJECTED = "REJECTED_EXTERNAL_RECONCILIATION_REQUIRED"


def _carry_forward_manifest(state: dict) -> dict:
    record_id = str(state.get("retirement_record_id") or "")
    if not record_id:
        raise RuntimeError("carry-forward reconciliation requires a replacement retirement record")
    return load_retirement_manifest(record_id, retirement_record_digest(state, record_id))


def _carry_forward_candidate(state: dict, path: str) -> tuple[dict, dict]:
    rel = _retirement_path(path)
    candidates = state.get("carry_forward_candidates") if isinstance(state.get("carry_forward_candidates"), list) else []
    matches = [item for item in candidates if isinstance(item, dict) and item.get("path") == rel]
    if len(matches) != 1:
        raise RuntimeError("carry-forward reconciliation requires one known candidate path")
    candidate = matches[0]
    manifest = _carry_forward_manifest(state)
    source = [item for item in manifest["paths"] if item["path"] == rel]
    if len(source) != 1 or str(candidate.get("retirement_record_id") or "") != manifest["id"]:
        raise RuntimeError("carry-forward candidate is forged or no longer bound to retirement evidence")
    evidence = source[0]["evidence"]
    if candidate.get("inherited_fingerprint") != evidence.get("fingerprint") or candidate.get("source_kind") != source[0]["current"]:
        raise RuntimeError("carry-forward candidate inherited evidence is forged or mismatched")
    if not retirement_fingerprint_matches(evidence):
        raise RuntimeError(f"carry-forward candidate changed since retirement: {rel}")
    return candidate, source[0]


def _carry_forward_step(state: dict, step_no: int) -> dict:
    plan = state.get("plan") if isinstance(state.get("plan"), dict) else {}
    steps = plan.get("steps") if isinstance(plan.get("steps"), list) else []
    if not (1 <= step_no <= len(steps)):
        raise RuntimeError("carry-forward adoption must claim an approved plan step")
    return steps[step_no - 1]


def _current_carry_forward_step(state: dict, step_no: int) -> dict:
    """Require reconciliation to be claimed by the live approved plan step."""
    if state.get("status") != "APPROVED":
        raise RuntimeError(f"carry-forward reconciliation requires current APPROVED plan, found {state.get('status')}")
    if int(state.get("current_step") or 0) != int(step_no):
        raise RuntimeError("carry-forward reconciliation must claim the current approved plan step")
    return _carry_forward_step(state, step_no)


def _validate_carry_forward_action_scope(state: dict, path: str, step_no: int) -> dict:
    step = _current_carry_forward_step(state, step_no)
    if path == "tests" or path.startswith("tests/"):
        policy = str(step.get("test_change_policy") or "none")
        # Carried-forward tests are retained evidence, not a modification of an
        # existing test.  The active step must nevertheless explicitly permit
        # test content, including the add-only policy.
        if policy not in {"add-only", "modify"}:
            raise RuntimeError(f"carry-forward reconciliation violates test policy {policy}: {path}")
    if is_tooling_path(path):
        allowed, reason = self_hosting_grant_allows(state, step_no, [path])
        if not allowed:
            raise RuntimeError(f"carry-forward reconciliation lacks current self-hosting authority: {reason}")
    return step


def _invalidate_carry_forward_qualification(state: dict, action_hash: str) -> None:
    """Never let a reconciliation action inherit an earlier qualification."""
    qualification = state.get("final_qualification")
    if not isinstance(qualification, dict):
        return
    state["final_qualification"] = {
        "state": "STALE",
        "invalidated_by": "carry-forward-reconciliation",
        "action_hash": action_hash,
        "prior_delta_fingerprint": qualification.get("delta_fingerprint"),
        "invalidated_at": utc_now(),
    }


def reconciliation_snapshot(state: dict) -> dict:
    """Return controller-derived reconciliation data; persisted records grant no authority."""
    record_id = str(state.get("retirement_record_id") or "")
    if not record_id:
        return {"replacement": False}
    manifest = _carry_forward_manifest(state)
    candidates = state.get("carry_forward_candidates")
    if not isinstance(candidates, list):
        raise RuntimeError("replacement reconciliation state lacks a candidate inventory")
    sources = {item["path"]: item for item in manifest["paths"]}
    snapshot: list[dict] = []
    seen: set[str] = set()
    final = {_CARRY_FORWARD_ADOPTED, _CARRY_FORWARD_OUTSIDE, _CARRY_FORWARD_REJECTED}
    for candidate in candidates:
        if not isinstance(candidate, dict):
            raise RuntimeError("replacement reconciliation state contains a malformed candidate")
        raw_path = str(candidate.get("path") or "")
        normalized = _normalize_repo_path(raw_path)
        path_parts = Path(normalized)
        malformed = (
            not normalized
            or path_parts.is_absolute()
            or any(part in {"", ".", ".."} for part in path_parts.parts)
        )
        # The inventory deliberately records controller/protected residue without
        # reading it.  It must remain visible to inspection and qualification,
        # but can never become an adoption target or gain authority from state.
        if malformed:
            raise RuntimeError(f"replacement reconciliation state contains an ambiguous candidate path: {raw_path!r}")
        path = path_parts.as_posix()
        if path in seen:
            raise RuntimeError("replacement reconciliation state contains duplicate candidate paths")
        seen.add(path)
        disposition = str(candidate.get("disposition") or "")
        if disposition not in final | {_CARRY_FORWARD_PENDING}:
            raise RuntimeError("replacement reconciliation state contains an invalid disposition")
        item = {"path": path, "classification": str(candidate.get("classification") or "INVALID"),
                "eligible": candidate.get("eligible") is True, "disposition": disposition,
                "reason": str(candidate.get("reason") or candidate.get("evidence_error") or ""),
                "claiming_step": None,
                "evidence_status": "controller-rejected" if candidate.get("eligible") is False else "pending",
                "qualification_impact": "STALE" if disposition != _CARRY_FORWARD_PENDING else "BLOCKS_EXECUTION"}
        source = sources.get(path)
        if is_protected_path(path) or _is_runtime_authority_path(path):
            if candidate.get("eligible") is not False or disposition != _CARRY_FORWARD_REJECTED or source is not None:
                raise RuntimeError("replacement reconciliation state grants protected or runtime path authority")
            snapshot.append(item)
            continue
        _retirement_path(path)
        record = candidate.get("adoption") if disposition == _CARRY_FORWARD_ADOPTED else candidate.get("reconciliation")
        if disposition in {_CARRY_FORWARD_ADOPTED, _CARRY_FORWARD_OUTSIDE}:
            if not isinstance(source, dict) or not isinstance(record, dict):
                raise RuntimeError("replacement reconciliation state lacks manifest-bound action evidence")
            # Diagnose an action against the live approved policy before its
            # integrity check.  A persisted action can never preserve policy
            # authority after the plan context changes; the hash check below
            # still rejects any corresponding record mutation.
            step_no = int(record.get("claiming_step") or 0)
            step = _carry_forward_step(state, step_no)
            if record.get("test_change_policy") != step.get("test_change_policy"):
                raise RuntimeError("replacement reconciliation action policy context is stale")
            provided_hash = str(record.get("action_hash") or "")
            canonical = {key: value for key, value in record.items() if key != "action_hash"}
            actual_hash = hashlib.sha256(json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            if not re.fullmatch(r"[0-9a-f]{64}", provided_hash) or not secrets.compare_digest(provided_hash, actual_hash):
                raise RuntimeError("replacement reconciliation action hash is malformed or stale")
            if (record.get("plan_hash") != state.get("plan_hash") or record.get("retirement_record_id") != record_id
                    or record.get("path") != path or record.get("disposition") != disposition
                    or record.get("retirement_evidence") != source.get("evidence")):
                raise RuntimeError("replacement reconciliation action is not bound to current immutable provenance")
            authority = record.get("self_hosting_authority")
            if authority is not None and (not isinstance(authority, dict) or authority.get("plan_hash") != state.get("plan_hash")):
                raise RuntimeError("replacement reconciliation action authority evidence is stale")
            item.update({"claiming_step": step_no, "evidence_status": "manifest-bound-unchanged",
                         "qualification_impact": "REQUIRES_REQUALIFICATION", "action_hash": provided_hash,
                         "authority_evidence": authority})
        elif disposition == _CARRY_FORWARD_REJECTED and source is not None and record is not None:
            item["evidence_status"] = "manifest-bound-rejected"
        snapshot.append(item)
    return {"replacement": True, "retirement_record_id": record_id,
            "retirement_manifest_sha256": retirement_record_digest(state, record_id),
            "candidates": sorted(
                snapshot,
                key=lambda item: (
                    0 if item["classification"] == "MANIFEST_BOUND_UNCHANGED" else 1,
                    item["path"],
                ),
            )}


def _carry_forward_action(state: dict, candidate: dict, source: dict, *, disposition: str, step: dict, ownership_basis: str, reason: str | None = None) -> dict:
    """Create an immutable-style, plan-bound record for one disposition."""
    action = {
        "schema": "zen_ralph_carry_forward_reconciliation_v3",
        "plan_hash": state["plan_hash"],
        "retirement_record_id": state["retirement_record_id"],
        "path": candidate["path"],
        "disposition": disposition,
        "claiming_step": int(step["id"]),
        "ownership_basis": ownership_basis,
        "retirement_evidence": source["evidence"],
        "inherited_fingerprint": source["evidence"]["fingerprint"],
        "source_kind": source["current"],
        "test_change_policy": step.get("test_change_policy"),
        "self_hosting_authority": state.get("self_hosting_grant") if is_tooling_path(candidate["path"]) else None,
        "reason": reason,
        "recorded_at": utc_now(),
    }
    action["action_hash"] = hashlib.sha256(json.dumps(action, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return action


def _validate_carry_forward_adoption(state: dict, path: str, step_no: int) -> tuple[dict, dict]:
    candidate, source = _carry_forward_candidate(state, path)
    if candidate.get("disposition") != _CARRY_FORWARD_PENDING:
        raise RuntimeError("carry-forward candidate already has a durable disposition")
    if candidate.get("owned") is not False or path in set(state.get("plan_changed_files") or []):
        raise RuntimeError("carry-forward candidate is duplicate or already absorbed by the plan")
    if is_protected_path(path) or _is_runtime_authority_path(path):
        raise RuntimeError("carry-forward adoption refuses protected or runtime paths")
    _validate_carry_forward_action_scope(state, path, step_no)
    return candidate, source


def cmd_inspect_carry_forward(args: argparse.Namespace) -> int:
    init_files()
    state = load_state()
    if not secrets.compare_digest(str(args.plan_hash or ""), str(state.get("plan_hash") or "")):
        raise RuntimeError("inspect-carry-forward hash does not match the current plan")
    if state.get("status") != "APPROVED":
        raise RuntimeError(f"inspect-carry-forward requires current APPROVED plan, found {state.get('status')}")
    print(json.dumps(reconciliation_snapshot(state), indent=2, sort_keys=True))
    return 0


def cmd_adopt_carry_forward(args: argparse.Namespace) -> int:
    init_files()
    state = load_state()
    if not secrets.compare_digest(str(args.plan_hash or ""), str(state.get("plan_hash") or "")):
        raise RuntimeError("adopt-carry-forward hash does not match the current plan")
    if str(args.confirm or "") != "ADOPT":
        raise RuntimeError("adopt-carry-forward requires --confirm ADOPT")
    path = _retirement_path(str(args.path or ""))
    step_no = int(args.step or 0)
    basis = " ".join(str(args.ownership_basis or "").split())
    if basis != "retired-unchanged-content":
        raise RuntimeError("adopt-carry-forward requires --ownership-basis retired-unchanged-content")
    candidate, source = _validate_carry_forward_adoption(state, path, step_no)
    step = _current_carry_forward_step(state, step_no)
    action = _carry_forward_action(state, candidate, source, disposition=_CARRY_FORWARD_ADOPTED, step=step, ownership_basis=basis)
    candidate.update({"disposition": _CARRY_FORWARD_ADOPTED, "owned": True, "adoption": action})
    # Retained content is controller-owned plan context, not a newly produced
    # working-tree delta.  In particular, it must never enter the staging,
    # qualification, or commit path reserved for newly changed plan files.
    state["plan_carry_forward_files"] = sorted(set(state.get("plan_carry_forward_files") or []) | {path})
    _invalidate_carry_forward_qualification(state, action["action_hash"])
    save_state(state)
    print(f"CARRY_FORWARD_ADOPTED plan={state['plan_hash']} path={path} step={step_no}")
    return 0


def _cmd_dispose_carry_forward(args: argparse.Namespace, disposition: str, action: str) -> int:
    init_files()
    state = load_state()
    if not secrets.compare_digest(str(args.plan_hash or ""), str(state.get("plan_hash") or "")):
        raise RuntimeError(f"{action} hash does not match the current plan")
    path = _retirement_path(str(args.path or ""))
    step_no = int(getattr(args, "step", state.get("current_step") or 0) or 0)
    candidate, source = _carry_forward_candidate(state, path)
    if candidate.get("disposition") != _CARRY_FORWARD_PENDING:
        raise RuntimeError("carry-forward candidate already has a durable disposition")
    reason = " ".join(str(args.reason or "").split())
    if not reason:
        raise RuntimeError(f"{action} requires a non-empty --reason")
    step = _validate_carry_forward_action_scope(state, path, step_no)
    basis = "outside-plan-boundary" if disposition == _CARRY_FORWARD_OUTSIDE else "external-reconciliation-required"
    record = _carry_forward_action(state, candidate, source, disposition=disposition, step=step, ownership_basis=basis, reason=reason[:1200])
    candidate.update({"disposition": disposition, "owned": False, "reason": reason[:1200], "disposed_at": record["recorded_at"], "reconciliation": record})
    _invalidate_carry_forward_qualification(state, record["action_hash"])
    save_state(state)
    print(f"{disposition} plan={state['plan_hash']} path={path}")
    return 0


def cmd_leave_carry_forward_outside(args: argparse.Namespace) -> int:
    return _cmd_dispose_carry_forward(args, _CARRY_FORWARD_OUTSIDE, "leave-carry-forward-outside")


def _cmd_reject_carry_forward(args: argparse.Namespace) -> int:
    return _cmd_dispose_carry_forward(args, _CARRY_FORWARD_REJECTED, "reject-carry-forward")


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
    gates.extend(ZEN_PROFILE.final_validator_gates(ROOT, sys.executable))
    gates.append(("diff-check", ["git", "diff", "--check"]))
    return gates


def run_final_qualification(requalification_state: dict | None = None) -> tuple[bool, list[str], dict[str, float], str]:
    """Run final gates, guarding the recorded delta when requalifying."""
    if requalification_state is not None:
        _requalification_delta_guard(requalification_state)
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
    if requalification_state is not None:
        _requalification_delta_guard(requalification_state)
    return True, results, durations, output


def _step_results_from_state(state: dict) -> list[dict]:
    values = state.get("step_results") if isinstance(state.get("step_results"), list) else []
    return [dict(value) for value in values if isinstance(value, dict)]


def record_step_result(state: dict, step: dict, result: str, *, summary: str = "", files: Iterable[str] = (), gates: Iterable[str] = (), stats: dict | None = None, attribution: dict | None = None) -> None:
    values = _step_results_from_state(state)
    values.append({
        "step": int(step.get("id") or 0),
        "title": str(step.get("title") or ""),
        "result": result,
        "summary": " ".join(str(summary or "").split())[:1000],
        "files": list(files),
        "attribution": dict(attribution or {}),
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
    # Cached filename fields are conveniences for state inspection only.  The
    # report is an authority-facing display and must be rebuilt from native
    # records every time.
    try:
        files = validated_plan_paths(state)
        owned_files = validated_plan_paths(state, owned_only=True)
        attribution_error = None
    except RuntimeError as exc:
        # A terminal report must retain a controller refusal without turning
        # stale filename fields into authority-facing change lists.
        files, owned_files, attribution_error = [], [], str(exc)
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

    qualification_record = state.get("final_qualification") if isinstance(state.get("final_qualification"), dict) else {}
    try:
        replacement_snapshot = reconciliation_snapshot(state)
    except RuntimeError as exc:
        # Reports are evidence only and must never turn malformed reconciliation
        # state into authority.  Preserve the exact controller refusal so a
        # terminal block can still produce an operator-visible report.
        replacement_snapshot = {
            "replacement": bool(state.get("retirement_record_id")),
            "retirement_record_id": state.get("retirement_record_id"),
            "error": str(exc),
        }

    report = {
        "schema": "zen_ralph_completion_v1",
        "generated_at": utc_now(),
        "plan_hash": state.get("plan_hash"),
        "goal": plan.get("goal"),
        "status": state.get("status"),
        "repository_authority": plan.get(REPOSITORY_AUTHORITY_FIELD),
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
        "qualification": {
            "state": str(qualification_record.get("state") or "UNKNOWN"),
            "stage": qualification_record.get("stage"),
            "error": qualification_record.get("error"),
            "gates": final_gates,
        },
        "attribution": {
            "state": "REFUSED" if attribution_error else "PASS",
            "error": attribution_error,
        },
        "changes": {"files": len(entries), "added": added, "removed": removed, "entries": entries},
        "step_results": step_results,
        "recovery_checkpoint": state.get("recovery_checkpoint"),
        "recovery_ref": (load_recovery_checkpoint(state.get("recovery_checkpoint")) or {}).get("ref"),
        "authority": {
            "ralph_tooling_changed": any(is_tooling_path(path) for path in files),
            "protected_paths_changed": any(is_protected_path(path) for path in files),
            "plan_owned_files": owned_files,
            "human_steering": list(state.get("human_steering") or []),
        },
        "usage": token_totals,
        "suggested_commit": (
            None if plan.get(REPOSITORY_AUTHORITY_FIELD) == "read-only"
            else state.get("commit_message") or _default_commit_message(state)
        ),
        "commit": state.get("commit_sha"),
        "push": state.get("push_upstream"),
        "reconciliation": {
            "commit_adopted": bool(state.get("commit_reconciled")),
            "push_adopted": bool(state.get("push_reconciled")),
            "commit_note": state.get("commit_reconcile_note"),
            "replacement_snapshot": replacement_snapshot,
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
        f"- State: {report['qualification']['state']}",
        *([f"- Stage: {report['qualification']['stage']}"] if report['qualification'].get('stage') else []),
        *([f"- Error: {report['qualification']['error']}"] if report['qualification'].get('error') else []),
        *([f"- Native attribution refusal: {attribution_error}"] if attribution_error else []),
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
    replacement = report["reconciliation"]["replacement_snapshot"]
    if replacement.get("replacement"):
        lines += ["", "## Replacement reconciliation", "",
                  f"- Retirement record: `{replacement.get('retirement_record_id') or '-'}`"]
        if replacement.get("error"):
            lines.append(f"- Controller refusal: {replacement['error']}")
        else:
            lines.append(f"- Immutable manifest digest: `{replacement['retirement_manifest_sha256']}`")
            for item in replacement["candidates"]:
                lines.append(f"- `{item['path']}` — {item['classification']}; {item['disposition']}; step={item['claiming_step'] or '-'}; evidence={item['evidence_status']}; qualification={item['qualification_impact']}; reason={item['reason'] or '-'}")
    lines += [
        "", "## Authority", "",
        f"- Repository authority: `{plan.get(REPOSITORY_AUTHORITY_FIELD) or '-'}`",
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
    ]
    if plan.get(REPOSITORY_AUTHORITY_FIELD) == "read-only":
        lines += [
            f"- Terminal: `{state.get('status')}`",
            "- Repository delta: zero required",
            "- Commit/push/reconciliation: prohibited for this read-only plan",
            "- Next action: no repository finalization is required",
            "",
        ]
    else:
        lines += [
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


def _is_runtime_authority_path(path: str) -> bool:
    path = _normalize_repo_path(path)
    return path == ".ralph" or path.startswith(".ralph/")


def authorized_self_hosting_paths(state: dict) -> set[str]:
    """Return tooling paths explicitly granted during this exact approved plan."""
    plan_digest = str(state.get("plan_hash") or "")
    allowed: set[str] = set()
    history = state.get("self_hosting_grant_history") if isinstance(state.get("self_hosting_grant_history"), list) else []
    for grant in history:
        if not isinstance(grant, dict) or str(grant.get("plan_hash") or "") != plan_digest:
            continue
        for raw in grant.get("paths") or []:
            path = _normalize_repo_path(str(raw))
            if not path or _is_runtime_authority_path(path) or is_protected_path(path) or not is_tooling_path(path):
                continue
            allowed.add(path)
    return allowed


def plan_delta_fingerprint(state: dict) -> str:
    """Bind qualification to exact native authority and current attributed delta."""
    # A pending retirement reconciliation is an independently disqualifying
    # condition.  Preserve its precise refusal before checking the native plan
    # artifact so controller diagnostics cannot mask unresolved residue.
    pending = unresolved_replacement_dispositions(state)
    if pending and pending != ["<inventory-missing>"]:
        raise RuntimeError(f"PENDING_RECONCILIATION: {', '.join(pending)}")
    provenance = strict_native_provenance(state, "delta fingerprint", require_current_delta=True)
    return str(provenance["current_sha256"])


def _reconciled_provenance_guard(
    state: dict, phase: str, *, require_new_plan_delta: bool = True,
) -> dict:
    """Derive the only worktree provenance eligible for qualification.

    Carry-forward content remains approval-time residue: it is revalidated and
    fingerprinted as evidence, but is never returned as new-plan staging scope.
    """
    # Every executable approved plan has a native approval artifact.  Do not
    # let this older reconciliation-shaped entry point turn its convenience
    # filename projections into authority when it is called directly.
    if isinstance(state.get("approved_plan_artifact"), dict):
        native = strict_native_provenance(
            state, phase, require_current_delta=require_new_plan_delta, require_write=True,
        )
        return {
            "new_plan_paths": list(native["new_plan_paths"]),
            "adopted_carry_forward_paths": [],
            "approval_baseline_paths": [],
            "adopted_evidence": {},
            "untracked_residue": [],
            "native_provenance_sha256": native["binding_sha256"],
        }

    # This compatibility branch is retained solely for non-executable legacy
    # diagnostic fixtures which have no controller-bound approval artifact.
    # Approval, qualification, staging, and terminal commands never authorize
    # an approved plan through this branch.
    checkpoint = load_recovery_checkpoint(state.get("recovery_checkpoint"))
    if not checkpoint:
        raise RuntimeError(f"{phase} requires a recovery checkpoint")
    baseline = {
        _normalize_repo_path(str(path)) for path in checkpoint.get("baseline_dirty_paths") or []
    } | {
        _normalize_repo_path(str(path)) for path in checkpoint.get("baseline_untracked_paths") or []
    }
    new_paths = {_normalize_repo_path(str(path)) for path in state.get("plan_changed_files") or [] if str(path).strip()}
    adopted_paths = {_normalize_repo_path(str(path)) for path in state.get("plan_carry_forward_files") or [] if str(path).strip()}
    overlap = sorted((new_paths & baseline) | (new_paths & adopted_paths))
    if overlap:
        raise RuntimeError(f"APPROVAL_BASELINE_RESIDUE_AS_NEW_PLAN: {overlap}")
    if not new_paths:
        raise RuntimeError(f"{phase} requires recorded new-plan changes")
    candidates = state.get("carry_forward_candidates")
    if state.get("retirement_record_id"):
        # Re-derive and validate the durable action records before trusting any
        # state-owned list.  The snapshot itself grants no ownership.
        reconciliation_snapshot(state)
        if not isinstance(candidates, list):
            raise RuntimeError("MALFORMED_RECONCILIATION_INVENTORY")
        by_path = {str(item.get("path") or ""): item for item in candidates if isinstance(item, dict)}
        for path, candidate in sorted(by_path.items()):
            disposition = str(candidate.get("disposition") or "")
            if disposition == _CARRY_FORWARD_PENDING:
                raise RuntimeError(f"PENDING_RECONCILIATION: {path}")
            if disposition == _CARRY_FORWARD_REJECTED:
                raise RuntimeError(f"REJECTED_EXTERNAL_RECONCILIATION_REQUIRED: {path}")
            if disposition == _CARRY_FORWARD_OUTSIDE:
                raise RuntimeError(f"OUTSIDE_BOUNDARY_RECONCILIATION: {path}")
            if disposition != _CARRY_FORWARD_ADOPTED:
                raise RuntimeError(f"INVALID_RECONCILIATION_DISPOSITION: {path}")
            if path not in adopted_paths:
                raise RuntimeError(f"ADOPTED_CARRY_FORWARD_NOT_IN_PROVENANCE: {path}")
            evidence = candidate.get("retirement_evidence")
            if not isinstance(evidence, dict) or not retirement_fingerprint_matches(evidence):
                raise RuntimeError(f"ALTERED_ADOPTED_CARRY_FORWARD: {path}")
        unrecorded = sorted(adopted_paths - set(by_path))
        if unrecorded:
            raise RuntimeError(f"UNRECORDED_ADOPTED_CARRY_FORWARD: {unrecorded}")
    elif adopted_paths:
        raise RuntimeError(f"CARRY_FORWARD_WITHOUT_RECONCILIATION: {sorted(adopted_paths)}")
    current = {_normalize_repo_path(path) for path in git_changed_paths() if not path.startswith(".ralph/")}
    missing_new = sorted(new_paths - current)
    if require_new_plan_delta and missing_new:
        raise RuntimeError(f"MISSING_NEW_PLAN_DELTA: {missing_new}")
    unexpected = sorted(current - baseline - new_paths)
    if unexpected:
        raise RuntimeError(f"UNEXPECTED_DELTA: {unexpected}")
    untracked_residue = sorted((current & baseline) - adopted_paths - (baseline - current))
    # Approval-time residue is allowed to remain outside the commit, but an
    # untracked baseline path cannot silently be absorbed or disappear.
    baseline_untracked = {_normalize_repo_path(str(path)) for path in checkpoint.get("baseline_untracked_paths") or []}
    exposed_untracked = sorted((current & baseline_untracked) - adopted_paths)
    if exposed_untracked:
        raise RuntimeError(f"UNTRACKED_APPROVAL_RESIDUE: {exposed_untracked}")
    protected = sorted(path for path in new_paths if is_protected_path(path) or _is_runtime_authority_path(path))
    if protected:
        raise RuntimeError(f"PROTECTED_NEW_PLAN_PATH: {protected}")
    tooling = sorted(path for path in new_paths if is_tooling_path(path))
    unauthorized = sorted(set(tooling) - authorized_self_hosting_paths(state))
    if unauthorized:
        raise RuntimeError(f"UNAUTHORIZED_TOOLING_NEW_PLAN_PATH: {unauthorized}")
    adopted_evidence = {
        path: retirement_path_fingerprint(path) for path in sorted(adopted_paths)
    }
    return {"new_plan_paths": sorted(new_paths), "adopted_carry_forward_paths": sorted(adopted_paths),
            "approval_baseline_paths": sorted(baseline), "adopted_evidence": adopted_evidence,
            "untracked_residue": untracked_residue}


RETIREMENT_MANIFEST_SCHEMA = "zen_ralph_retirement_v4"
RETIREMENT_MANIFEST_LEGACY_SCHEMA = "zen_ralph_retirement_v3"
_RETIREMENT_ID_RE = re.compile(r"^RT-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}$")
_RETIREMENT_PATH_KINDS = {"tracked", "untracked", "missing"}


def retirement_record_id() -> str:
    """Return an opaque, sortable identifier for one immutable retirement record."""
    return f"RT-{dt.datetime.now(dt.timezone.utc):%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:12]}"


def restored_retirement_paths_match_checkpoint(
    state: dict,
    checkpoint: dict,
    records: list[dict],
) -> tuple[bool, str]:
    """Verify every path recorded by a stranded plan is back at approval state.

    This grants no ownership and performs no restoration. It exists only to
    prove that an operator has already restored the plan's recorded paths to
    the controller-owned recovery checkpoint.

    Approval-time dirty/untracked paths are deliberately unsupported here:
    their provenance is ambiguous and must continue to fail closed.
    """
    recovery_ref = str(checkpoint.get("ref") or "")
    if not recovery_ref:
        return False, "recovery checkpoint has no Git ref"

    if not secrets.compare_digest(
        str(checkpoint.get("plan_hash") or ""),
        str(state.get("plan_hash") or ""),
    ):
        return False, "recovery checkpoint belongs to another plan"

    for item in records:
        path = _retirement_path(str(item.get("path") or ""))
        baseline = str(item.get("baseline") or "")
        full = ROOT / path

        status = _git(
            ["status", "--porcelain=v1", "--untracked-files=all", "--", path],
            check=False,
        )
        if status.returncode != 0:
            return False, f"cannot determine current status for {path}"

        if baseline == "tracked":
            if status.stdout:
                return False, f"tracked path is not clean: {path}"
            if full.is_symlink() or not full.is_file():
                return False, f"tracked path is not a regular file: {path}"

            expected = _git(
                ["rev-parse", f"{recovery_ref}:{path}"],
                check=False,
            )
            current = _git(
                ["hash-object", "--", path],
                check=False,
            )

            expected_oid = expected.stdout.strip()
            current_oid = current.stdout.strip()

            if (
                expected.returncode != 0
                or current.returncode != 0
                or not expected_oid
                or not current_oid
            ):
                return False, f"cannot fingerprint tracked path: {path}"

            if not secrets.compare_digest(expected_oid, current_oid):
                return False, f"tracked path differs from approval checkpoint: {path}"

        elif baseline == "absent":
            if status.stdout or full.exists() or full.is_symlink():
                return False, f"approval-absent path still exists: {path}"

        else:
            return False, (
                f"unsupported approval baseline for restored reconciliation: "
                f"{path} ({baseline})"
            )

    return True, "all recorded plan paths match the approval checkpoint"


def _retirement_path(path: str) -> str:
    """Canonicalize an artifact path, refusing protected or ambiguous targets."""
    value = _normalize_repo_path(path)
    candidate = Path(value)
    if (
        not value
        or candidate.is_absolute()
        or any(part in {"", ".", ".."} for part in candidate.parts)
        or is_protected_path(value)
        or _is_runtime_authority_path(value)
    ):
        raise RuntimeError(f"retirement record rejects protected or ambiguous path: {path!r}")
    return candidate.as_posix()


def _retirement_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def retirement_path_fingerprint(path: str) -> dict:
    """Capture canonical Git status plus content and HEAD-delta evidence for one path.

    A missing path is a legitimate, distinct state.  Directories and symlinks are
    deliberately rejected: neither provides unambiguous file-content ownership.
    """
    rel = _retirement_path(path)
    full = ROOT / rel
    tracked = _git(["ls-files", "--error-unmatch", "--", rel], check=False).returncode == 0
    status_proc = _git(["status", "--porcelain=v1", "-z", "--untracked-files=all", "--", rel], check=False)
    if status_proc.returncode != 0:
        raise RuntimeError(f"cannot determine Git status for retirement path {rel!r}")
    status = status_proc.stdout
    if full.is_symlink() or (full.exists() and not full.is_file()):
        raise RuntimeError(f"retirement record rejects non-regular path: {rel}")
    if full.exists():
        try:
            content = full.read_bytes()
        except OSError as exc:
            raise RuntimeError(f"cannot read retirement path {rel!r}: {exc}") from exc
        kind = "tracked" if tracked else "untracked"
        content_sha256: str | None = _retirement_sha256(content)
    else:
        kind = "missing"
        content_sha256 = None
    delta = _git(["diff", "--binary", "HEAD", "--", rel], check=False)
    if delta.returncode != 0:
        raise RuntimeError(f"cannot determine Git delta for retirement path {rel!r}")
    record = {
        "path": rel,
        "kind": kind,
        "git_status": status,
        "content_sha256": content_sha256,
        "delta_sha256": _retirement_sha256(delta.stdout.encode("utf-8")),
    }
    record["fingerprint"] = _retirement_sha256(
        json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    return record


def retirement_fingerprint_matches(record: dict) -> bool:
    """Return whether a recorded path still has exactly its captured evidence."""
    try:
        path = record["path"]
        expected = str(record["fingerprint"])
        if not expected:
            return False
        return retirement_path_fingerprint(path) == record
    except (KeyError, TypeError, RuntimeError):
        return False


def replacement_dirty_inventory(manifest: dict) -> list[dict]:
    """Record a fail-closed disposition for every current dirty worktree path.

    Retirement evidence can prove that a path is retained, but the repository
    snapshot is only audit context: it never grants replacement-plan ownership.
    Protected and malformed paths deliberately receive status-only evidence so
    the controller does not read their content while still making them visible.
    """
    dirty, untracked = _status_sets()
    manifest_paths = manifest.get("paths") if isinstance(manifest.get("paths"), list) else []
    snapshot = manifest.get("repository_after") if isinstance(manifest.get("repository_after"), dict) else {}
    by_path: dict[str, list[dict]] = {}
    for item in manifest_paths:
        if isinstance(item, dict) and isinstance(item.get("path"), str):
            by_path.setdefault(item["path"], []).append(item)
    inventory: list[dict] = []
    retained = {item["path"] for item in manifest_paths if isinstance(item, dict) and item.get("current") != "missing" and isinstance(item.get("path"), str)}
    # Include unchanged retained records as well: they remain explicit adoption
    # candidates, while the dirty set is still exhaustively inventoried.
    for raw_path in sorted(set(dirty) | set(untracked) | retained):
        source_kind = "untracked" if raw_path in untracked else "modified"
        status = _git(["status", "--porcelain=v1", "-z", "--untracked-files=all", "--", raw_path], check=False)
        base = {"path": raw_path, "source_kind": source_kind, "owned": False,
                "retirement_record_id": manifest.get("id"), "current_status": status.stdout}
        normalized = _normalize_repo_path(raw_path)
        candidate = Path(normalized)
        if (not normalized or candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts)):
            inventory.append(base | {"classification": "MALFORMED_NON_ADOPTABLE", "eligible": False,
                                     "disposition": _CARRY_FORWARD_REJECTED, "evidence_error": "ambiguous path"})
            continue
        path = candidate.as_posix()
        base["path"] = path
        if is_protected_path(path):
            inventory.append(base | {"classification": "PROTECTED_NON_ADOPTABLE", "eligible": False,
                                     "disposition": _CARRY_FORWARD_REJECTED, "evidence_error": "protected path content not read"})
            continue
        if _is_runtime_authority_path(path):
            inventory.append(base | {"classification": "RUNTIME_AUTHORITY_NON_ADOPTABLE", "eligible": False,
                                     "disposition": _CARRY_FORWARD_REJECTED, "evidence_error": "runtime authority path"})
            continue
        sources = by_path.get(path, [])
        if len(sources) > 1:
            inventory.append(base | {"classification": "DUPLICATE_MANIFEST_EVIDENCE_NON_ADOPTABLE", "eligible": False,
                                     "disposition": _CARRY_FORWARD_REJECTED, "evidence_error": "duplicate retirement path evidence"})
            continue
        try:
            evidence = retirement_path_fingerprint(path)
        except RuntimeError as exc:
            inventory.append(base | {"classification": "UNREADABLE_NON_ADOPTABLE", "eligible": False,
                                     "disposition": _CARRY_FORWARD_REJECTED, "evidence_error": str(exc)})
            continue
        base["current_evidence"] = evidence
        if len(sources) == 1:
            source = sources[0]
            recorded = source.get("evidence")
            if not isinstance(recorded, dict) or not retirement_fingerprint_matches(recorded):
                inventory.append(base | {"classification": "MANIFEST_BOUND_CHANGED_NON_ADOPTABLE", "eligible": False,
                                         "disposition": _CARRY_FORWARD_REJECTED, "retirement_evidence": recorded})
                continue
            inventory.append(base | {"classification": "MANIFEST_BOUND_UNCHANGED", "eligible": True,
                                     "disposition": _CARRY_FORWARD_PENDING, "baseline": source.get("baseline"),
                                     "current": source.get("current"), "source_kind": source.get("current"), "inherited_fingerprint": recorded.get("fingerprint"),
                                     "retirement_evidence": recorded})
            continue
        if path in snapshot:
            inventory.append(base | {"classification": "SNAPSHOT_ONLY_EXTERNAL_RECONCILIATION", "eligible": False,
                                     "disposition": _CARRY_FORWARD_REJECTED,
                                     "repository_after_fingerprint": snapshot[path]})
        else:
            inventory.append(base | {"classification": "UNKNOWN_NON_ADOPTABLE", "eligible": False,
                                     "disposition": _CARRY_FORWARD_REJECTED})
    # Keep the complete inventory visible, but put manifest-bound evidence
    # first. Controller runtime residue remains recorded and fail-closed, but
    # must not obscure the exact candidate reconciled from retirement evidence.
    return sorted(
        inventory,
        key=lambda item: (
            0 if item.get("classification") == "MANIFEST_BOUND_UNCHANGED" else 1,
            str(item.get("path") or ""),
        ),
    )


def replacement_inventory_binding(candidate: dict) -> dict:
    """Return the immutable evidence portion of one replacement candidate."""
    if not isinstance(candidate, dict):
        return {"invalid_candidate": True}
    mutable = {"disposition", "owned", "reason", "disposed_at", "adoption"}
    return {key: value for key, value in candidate.items() if key not in mutable}


def refresh_replacement_dirty_inventory(state: dict) -> bool:
    """Refresh inventory evidence, retaining new fail-closed records on mismatch."""
    record_id = str(state.get("retirement_record_id") or "")
    if not record_id:
        return True
    manifest, _ = replacement_retirement_context(record_id, retirement_record_digest(state, record_id))
    current = replacement_dirty_inventory(manifest)
    recorded = state.get("carry_forward_candidates")
    if not isinstance(recorded, list):
        state["carry_forward_candidates"] = current
        return False
    expected = [replacement_inventory_binding(item) for item in recorded]
    actual = [replacement_inventory_binding(item) for item in current]
    if expected != actual:
        state["carry_forward_candidates"] = current
        return False
    return True


def unresolved_replacement_dispositions(state: dict) -> list[str]:
    """Return manifest-bound candidates not explicitly disposed by an operator.

    Inventory records are durable evidence, but PENDING_RECONCILIATION is not a
    final disposition and cannot authorize execution.  This deliberately makes
    adoption, outside-boundary treatment, or external reconciliation explicit.
    """
    candidates = state.get("carry_forward_candidates")
    if not isinstance(candidates, list):
        return ["<inventory-missing>"]
    return sorted(
        str(item.get("path") or "<invalid-candidate>")
        for item in candidates
        if not isinstance(item, dict) or item.get("disposition") == _CARRY_FORWARD_PENDING
    )


def retirement_path_records(state: dict, paths: Iterable[str]) -> list[dict]:
    """Capture carry-forward inventory evidence without granting rollback authority.

    These records intentionally preserve the historical retirement/carry-forward
    contract: a replacement plan needs immutable evidence for retained paths even
    though rollback authority now comes exclusively from native operation
    attribution.  The projection fields identify what the retiring controller
    knew; the embedded attribution marker explicitly grants no mutation authority.
    """
    explicit_owned = {_retirement_path(str(item)) for item in state.get("plan_owned_files") or []}
    checkpoint_id = str(state.get("recovery_checkpoint") or "")
    records: list[dict] = []
    for raw in sorted({_retirement_path(str(item)) for item in paths}):
        baseline = plan_baseline_path_kind(state, raw)
        fingerprint = retirement_path_fingerprint(raw)
        current = fingerprint["kind"]
        # Ownership is exclusively the controller's explicit plan-owned record;
        # neither a current pathname nor a clean Git state confers ownership.
        plan_owned = raw in explicit_owned
        unexpected = current != "missing" and baseline == "absent" and not plan_owned
        records.append({
            "path": raw,
            "baseline": baseline,
            "plan_owned": plan_owned,
            "current": current,
            "unexpected": unexpected,
            "evidence": fingerprint,
            "attribution": {
                "schema": "zen_ralph_carry_forward_inventory_v1",
                "authority": "inventory-only",
                "plan_hash": state.get("plan_hash"),
                "checkpoint": checkpoint_id,
                "source": "controller-plan-file-projection",
            },
            "before": fingerprint,
            "after": fingerprint,
            "restoration": {
                "disposition": "preserved",
                "action": "none",
                "checkpoint": checkpoint_id,
            },
        })
    return records


def retirement_attribution_records(state: dict) -> list[dict]:
    """Derive one fail-closed rollback record per current native attribution.

    Retirement deliberately does not consult the convenience plan-file lists:
    those lists are reporting projections, not recovery authority.  Every
    checkpoint-relative delta must instead have one intact native operation
    record whose fingerprint still describes the current worktree.
    """
    latest = _latest_operation_records_by_path(state)
    validated = _validated_operation_records(state)
    if len(latest) != len(validated):
        raise RuntimeError("retire-plan refuses duplicate operation attribution")

    repository = recompute_repository_against_approval_checkpoint(state)
    changed_residue = sorted(repository.get("changed_approval_residue") or [])
    if changed_residue:
        raise RuntimeError(f"retire-plan refuses changed approval residue: {changed_residue}")
    current_delta = {
        _retirement_path(str(path))
        for path in repository.get("new_project_delta") or []
    }
    attributed = set(latest)
    if current_delta != attributed:
        raise RuntimeError(
            "retire-plan refuses unattributed or stale checkpoint delta: "
            f"unattributed={sorted(current_delta - attributed)} "
            f"stale={sorted(attributed - current_delta)}"
        )

    records: list[dict] = []
    for path in sorted(attributed):
        attribution = latest[path]
        baseline = str(attribution.get("baseline_kind") or "")
        if baseline not in {"tracked", "absent"}:
            raise RuntimeError(f"retire-plan refuses unsupported attribution baseline: {path} ({baseline})")
        before = retirement_path_fingerprint(path)
        if attribution.get("current_fingerprint") != before:
            raise RuntimeError(f"retire-plan refuses stale attribution fingerprint: {path}")
        if baseline == "tracked" and before["kind"] not in {"tracked", "missing"}:
            raise RuntimeError(f"retire-plan refuses invalid tracked attribution state: {path}")
        if baseline == "absent" and before["kind"] == "missing":
            raise RuntimeError(f"retire-plan refuses stale creation attribution: {path}")
        records.append({
            "path": path,
            "baseline": baseline,
            "plan_owned": baseline == "absent",
            "current": before["kind"],
            "unexpected": False,
            "evidence": before,
            "attribution": _json_copy(attribution),
            "before": before,
            "after": None,
            "restoration": None,
        })
    return records


def _restore_attributed_retirement_path(recovery_ref: str, record: dict) -> dict:
    """Restore exactly one pre-validated attribution and return post-state proof."""
    path = _retirement_path(str(record["path"]))
    baseline = str(record["baseline"])
    if baseline == "tracked":
        restored = _git(["checkout", recovery_ref, "--", path], check=False)
        if restored.returncode != 0:
            raise RuntimeError(f"retire-plan cannot restore tracked checkpoint path: {path}")
        after = retirement_path_fingerprint(path)
        if after["kind"] != "tracked":
            raise RuntimeError(f"retire-plan tracked restoration is not a regular tracked file: {path}")
        index_diff = _git(["diff", "--quiet", recovery_ref, "--", path], check=False)
        worktree_diff = _git(["diff", "--quiet", "--", path], check=False)
        if index_diff.returncode != 0 or worktree_diff.returncode != 0:
            raise RuntimeError(f"retire-plan tracked restoration differs from recovery checkpoint: {path}")
        return after
    if baseline == "absent":
        full = ROOT / path
        if full.is_symlink() or not full.is_file():
            raise RuntimeError(f"retire-plan creation target is no longer a regular file: {path}")
        full.unlink()
        after = retirement_path_fingerprint(path)
        if after["kind"] != "missing":
            raise RuntimeError(f"retire-plan checkpoint-absent creation remains present: {path}")
        return after
    raise RuntimeError(f"retire-plan refuses unsupported attribution baseline: {path} ({baseline})")


def validate_retirement_manifest(manifest: dict) -> dict:
    """Validate the complete immutable retirement-artifact schema, fail closed."""
    if not isinstance(manifest, dict):
        raise RuntimeError("retirement manifest must be an object")
    required = {"schema", "id", "created_at", "plan_hash", "status_before", "reason", "disposition", "checkpoint", "step", "step_count", "loop_count", "paths", "operations", "repository_before", "repository_after", "planning_context"}
    schema = manifest.get("schema")
    if set(manifest) != required or schema not in {RETIREMENT_MANIFEST_SCHEMA, RETIREMENT_MANIFEST_LEGACY_SCHEMA}:
        raise RuntimeError("retirement manifest schema is invalid")
    if not _RETIREMENT_ID_RE.fullmatch(str(manifest["id"])):
        raise RuntimeError("retirement manifest identifier is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", str(manifest["plan_hash"])):
        raise RuntimeError("retirement manifest plan hash is invalid")
    if not all(isinstance(manifest[key], str) and manifest[key].strip() for key in ("created_at", "status_before", "reason", "checkpoint")):
        raise RuntimeError("retirement manifest metadata is invalid")
    if manifest["disposition"] not in {"ROLLED_BACK", "RETIRED_WITH_CARRY_FORWARD"}:
        raise RuntimeError("retirement manifest disposition is invalid")
    if not all(isinstance(manifest[key], int) and manifest[key] >= 0 for key in ("step", "step_count", "loop_count")):
        raise RuntimeError("retirement manifest lifecycle audit fields are invalid")
    if not isinstance(manifest["operations"], dict) or set(manifest["operations"]) != {"restore", "delete", "preserved"} or not all(isinstance(manifest["operations"][key], list) for key in ("restore", "delete", "preserved")):
        raise RuntimeError("retirement manifest operations are invalid")
    if not all(isinstance(manifest[key], dict) for key in ("repository_before", "repository_after")):
        raise RuntimeError("retirement manifest repository audit state is invalid")
    planning = manifest["planning_context"]
    required_planning = {"goal", "blockers", "prior_steps", "policies", "review_evidence"}
    if not isinstance(planning, dict) or set(planning) != required_planning:
        raise RuntimeError("retirement manifest planning context is invalid")
    if not isinstance(planning["goal"], str) or not planning["goal"].strip():
        raise RuntimeError("retirement manifest planning goal is invalid")
    if not isinstance(planning["blockers"], list) or not isinstance(planning["prior_steps"], list):
        raise RuntimeError("retirement manifest planning history is invalid")
    if not isinstance(planning["policies"], dict) or not isinstance(planning["review_evidence"], dict):
        raise RuntimeError("retirement manifest planning evidence is invalid")
    paths = manifest["paths"]
    if not isinstance(paths, list):
        raise RuntimeError("retirement manifest requires path evidence")
    seen: set[str] = set()
    for item in paths:
        expected_fields = {"path", "baseline", "plan_owned", "current", "unexpected", "evidence"}
        if schema == RETIREMENT_MANIFEST_SCHEMA:
            expected_fields |= {"attribution", "before", "after", "restoration"}
        if not isinstance(item, dict) or set(item) != expected_fields:
            raise RuntimeError("retirement manifest path record is invalid")
        path = _retirement_path(str(item.get("path") or ""))
        if path in seen or item["baseline"] not in {"tracked", "preexisting-untracked", "preexisting-dirty", "absent", "unknown"}:
            raise RuntimeError("retirement manifest path classification is invalid")
        seen.add(path)
        if not isinstance(item["plan_owned"], bool) or not isinstance(item["unexpected"], bool) or item["current"] not in _RETIREMENT_PATH_KINDS:
            raise RuntimeError("retirement manifest ownership classification is invalid")
        evidence = item["evidence"]
        if not isinstance(evidence, dict) or set(evidence) != {"path", "kind", "git_status", "content_sha256", "delta_sha256", "fingerprint"}:
            raise RuntimeError("retirement manifest fingerprint evidence is invalid")
        canonical = dict(evidence)
        if canonical["path"] != path or canonical["kind"] != item["current"] or not isinstance(canonical["git_status"], str):
            raise RuntimeError("retirement manifest fingerprint does not bind its path")
        if canonical["kind"] == "missing":
            if canonical["content_sha256"] is not None:
                raise RuntimeError("missing retirement path has content evidence")
        elif not isinstance(canonical["content_sha256"], str):
            raise RuntimeError("retirement path lacks content evidence")
        expected = canonical.pop("fingerprint")
        if not all(isinstance(canonical[key], str) and re.fullmatch(r"[0-9a-f]{64}", canonical[key]) for key in ("delta_sha256",)) or (canonical["content_sha256"] is not None and not re.fullmatch(r"[0-9a-f]{64}", canonical["content_sha256"])):
            raise RuntimeError("retirement manifest digest evidence is invalid")
        actual = _retirement_sha256(json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        if not isinstance(expected, str) or expected != actual:
            raise RuntimeError("retirement manifest fingerprint integrity check failed")
        if schema == RETIREMENT_MANIFEST_LEGACY_SCHEMA:
            # v3 artifacts are immutable historical evidence.  They remain
            # readable for replacement/carry-forward reconciliation, but no v3
            # path record can satisfy the v4 native rollback contract.
            continue
        if not isinstance(item["attribution"], dict) or item["before"] != evidence:
            raise RuntimeError("retirement manifest attribution restoration evidence is invalid")
        restoration = item["restoration"]
        if not isinstance(restoration, dict) or set(restoration) != {"disposition", "action", "checkpoint"}:
            raise RuntimeError("retirement manifest restoration disposition is invalid")
        if restoration["checkpoint"] != manifest["checkpoint"]:
            raise RuntimeError("retirement manifest restoration checkpoint is invalid")
        if manifest["disposition"] == "ROLLED_BACK":
            if restoration["disposition"] != "restored" or restoration["action"] not in {"checkout", "delete"}:
                raise RuntimeError("retirement manifest rollback restoration is invalid")
            after = item["after"]
            if not isinstance(after, dict) or set(after) != set(evidence):
                raise RuntimeError("retirement manifest rollback lacks post-restoration evidence")
        elif restoration["disposition"] != "preserved" or restoration["action"] != "none" or item["after"] != evidence:
            raise RuntimeError("retirement manifest carry-forward preservation evidence is invalid")
    return manifest


def retirement_planning_context(state: dict) -> dict:
    """Capture only review/planning evidence; execution authority never retires forward."""
    plan = state.get("plan") if isinstance(state.get("plan"), dict) else {}
    steps = plan.get("steps") if isinstance(plan.get("steps"), list) else []
    results = state.get("step_results") if isinstance(state.get("step_results"), list) else []
    return {
        "goal": str(plan.get("goal") or "").strip(),
        "blockers": [str(state.get("block_reason") or "").strip()] if state.get("block_reason") else [],
        "prior_steps": [
            {"id": step.get("id"), "title": step.get("title"), "objective": step.get("objective"),
             "acceptance": step.get("acceptance"), "test_change_policy": step.get("test_change_policy"),
             "outcome": next((item.get("result") for item in results if isinstance(item, dict) and item.get("step") == step.get("id")), None)}
            for step in steps
        ],
        "policies": {"test_change_policies": [step.get("test_change_policy") for step in steps]},
        "review_evidence": {"final_qualification": state.get("final_qualification"), "recovery_checkpoint": state.get("recovery_checkpoint")},
    }


def retirement_record_digest(state: dict, record_id: str) -> str:
    """Return the controller-bound digest for one known retirement artifact."""
    records = state.get("retired_plans") if isinstance(state.get("retired_plans"), list) else []
    matches = [item for item in records if isinstance(item, dict) and item.get("record_id") == record_id]
    if len(matches) != 1:
        raise RuntimeError("replacement proposal requires a known retirement record")
    digest = str(matches[0].get("manifest_sha256") or "")
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise RuntimeError("retirement record lacks immutable digest evidence")
    return digest


def replacement_retirement_context(record_id: str, expected_digest: str) -> tuple[dict, dict]:
    """Load current retirement evidence plus historical planning context only."""
    manifest = load_retirement_manifest(record_id, expected_digest)
    if manifest["disposition"] != "RETIRED_WITH_CARRY_FORWARD":
        raise RuntimeError("replacement proposal requires a carry-forward retirement record")
    return manifest, {
        "current_retirement_record_id": manifest["id"],
        "current_retirement_reason": manifest["reason"],
        "source_plan_hash": manifest["plan_hash"],
        "source_status": manifest["status_before"],
        "source_step": manifest["step"],
        "source_step_count": manifest["step_count"],
        "historical_planning_context": manifest["planning_context"],
    }


def replacement_plan_goal(manifest: dict) -> str:
    """Derive a replacement objective from the newest retirement, never an ancestor goal."""
    record_id = str(manifest.get("id") or "").strip()
    reason = " ".join(str(manifest.get("reason") or "").split())
    if not record_id or not reason:
        raise RuntimeError("retirement manifest lacks current replacement objective evidence")
    return f"Continue from {record_id} to resolve the retirement condition: {reason}"


def load_retirement_manifest(record_id: str, expected_digest: str | None = None) -> dict:
    """Load an existing immutable artifact; absent or malformed records are errors."""
    if not _RETIREMENT_ID_RE.fullmatch(str(record_id or "")):
        raise RuntimeError("retirement manifest identifier is invalid")
    path = RALPH / "retirements" / f"{record_id}.json"
    try:
        raw = path.read_bytes()
        if expected_digest is not None and not secrets.compare_digest(_retirement_sha256(raw), expected_digest):
            raise RuntimeError("retirement manifest immutable digest does not match")
        manifest = json.loads(raw.decode("utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"cannot load retirement manifest {record_id!r}") from exc
    manifest = validate_retirement_manifest(manifest)
    if manifest["id"] != record_id:
        raise RuntimeError("retirement manifest filename and identifier disagree")
    return manifest


def write_retirement_manifest(manifest: dict) -> Path:
    """Create one manifest without ever replacing an existing retirement artifact."""
    manifest = validate_retirement_manifest(manifest)
    retirements = RALPH / "retirements"
    retirements.mkdir(parents=True, exist_ok=True)
    path = retirements / f"{manifest['id']}.json"
    try:
        with path.open("x", encoding="utf-8") as handle:
            handle.write(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    except FileExistsError as exc:
        raise RuntimeError(f"retirement manifest already exists: {manifest['id']}") from exc
    return path


def qualified_delta_matches(state: dict) -> tuple[bool, str]:
    qualification = state.get("final_qualification") if isinstance(state.get("final_qualification"), dict) else {}
    if str(qualification.get("state") or "") != "PASS":
        return False, "final qualification is not PASS"
    # Native approved plans must bind qualification to exact operation provenance.
    # Legacy in-memory fixtures without native approval bindings retain the old
    # diagnostic behavior, but no executable native plan can reach this branch.
    if isinstance(state.get("approved_plan_artifact"), dict):
        try:
            _qualified_native_provenance(state, "qualified delta", require_current_delta=True)
        except RuntimeError as exc:
            return False, str(exc)
        return True, "qualified native provenance and delta match"
    expected = str(qualification.get("delta_fingerprint") or "").strip()
    if not expected:
        planned = {_normalize_repo_path(str(path)) for path in state.get("plan_changed_files") or []}
        self_hosted = any(is_tooling_path(path) for path in planned) or bool(authorized_self_hosting_paths(state))
        if self_hosted:
            return False, "self-hosting final qualification predates delta binding; requalification is required"
        return True, "legacy non-self-hosting qualification has no delta fingerprint"
    try:
        actual = plan_delta_fingerprint(state)
    except RuntimeError as exc:
        return False, f"reconciled provenance is stale: {exc}"
    if expected != actual:
        return False, "working-tree delta changed after final qualification; requalification is required"
    return True, "qualified delta fingerprint matches"


def finalization_review(state: dict) -> dict:
    provenance_error = None
    native = None
    try:
        if isinstance(state.get("approved_plan_artifact"), dict):
            native = strict_native_provenance(state, "finalization review", require_current_delta=True)
            planned = set(native["new_plan_paths"])
            provenance = native
        else:
            provenance = _reconciled_provenance_guard(state, "finalization review")
            planned = set(provenance["new_plan_paths"])
    except RuntimeError as exc:
        provenance, provenance_error = None, str(exc)
        planned = set()
    checkpoint = load_recovery_checkpoint(state.get("recovery_checkpoint"))
    baseline = set(checkpoint.get("baseline_dirty_paths") or []) if checkpoint else set()
    current = {path for path in git_changed_paths() if not path.startswith(".ralph/")}
    overlap = sorted((baseline & planned) - {path for path in planned if path.startswith(".ralph/")})
    unexpected = sorted(current - baseline - planned)
    protected = sorted(path for path in planned if is_protected_path(path) or _is_runtime_authority_path(path))
    tooling = sorted(path for path in planned if is_tooling_path(path) and not _is_runtime_authority_path(path))
    unauthorized_tooling = sorted(set(tooling) - authorized_self_hosting_paths(state))
    return {
        "baseline": sorted(baseline),
        "planned": sorted(planned),
        "current": sorted(current),
        "overlap": overlap,
        "unexpected": unexpected,
        "protected": protected,
        "tooling": tooling,
        "unauthorized_tooling": unauthorized_tooling,
        "checkpoint": checkpoint,
        "provenance": provenance,
        "provenance_error": provenance_error,
    }


def _commit_paths(commit_sha: str) -> list[str]:
    proc = _git(["diff-tree", "--no-commit-id", "--name-only", "-r", commit_sha], check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"cannot inspect commit {commit_sha}: {proc.stdout[-2000:]}")
    return sorted({line.strip() for line in proc.stdout.splitlines() if line.strip()})


def _verify_reconciled_commit(state: dict, commit_sha: str) -> dict:
    if state.get("status") != "READY_TO_COMMIT":
        raise RuntimeError(f"reconcile-commit requires READY_TO_COMMIT, found {state.get('status')}")
    provenance = _qualified_native_provenance(
        state, "commit reconciliation", require_current_delta=False, require_write=True,
    )
    resolved = _git(["rev-parse", "--verify", f"{commit_sha}^{{commit}}"], check=False)
    if resolved.returncode != 0:
        raise RuntimeError(f"commit {commit_sha} does not exist")
    sha = resolved.stdout.strip()
    reachable = _git(["merge-base", "--is-ancestor", sha, "HEAD"], check=False)
    if reachable.returncode != 0:
        raise RuntimeError("commit is not reachable from current HEAD")
    commit_paths = _verify_commit_native_provenance(state, sha, provenance, "commit reconciliation")
    return {
        "sha": sha,
        "commit_paths": commit_paths,
        "baseline_extras": [],
        "native_provenance_sha256": provenance["binding_sha256"],
    }


def _finalization_guard(state: dict) -> tuple[list[str], list[str]]:
    if isinstance(state.get("approved_plan_artifact"), dict):
        native = _qualified_native_provenance(
            state, "automated commit", require_current_delta=True, require_write=True,
        )
        planned = set(native["new_plan_paths"])
    else:
        provenance = _reconciled_provenance_guard(state, "automated commit")
        planned = set(provenance["new_plan_paths"])
    checkpoint = load_recovery_checkpoint(state.get("recovery_checkpoint"))
    if not checkpoint:
        raise RuntimeError("recovery checkpoint is missing; finalization refused")
    baseline = set(checkpoint.get("baseline_dirty_paths") or [])
    baseline_staged = sorted(checkpoint.get("baseline_staged_paths") or [])
    if baseline_staged:
        raise RuntimeError(f"pre-existing staged changes were present at approval; automated commit refused: {baseline_staged}")
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
    protected = sorted(path for path in planned if is_protected_path(path) or _is_runtime_authority_path(path))
    if protected:
        raise RuntimeError(f"automated commit refuses protected/runtime authority paths: {protected}")
    tooling = sorted(path for path in planned if is_tooling_path(path))
    unauthorized_tooling = sorted(set(tooling) - authorized_self_hosting_paths(state))
    if unauthorized_tooling:
        raise RuntimeError(f"automated commit refuses RALPH tooling without same-plan self-hosting authority: {unauthorized_tooling}")
    staged_now = sorted(line.strip() for line in _git(["diff", "--cached", "--name-only"], check=False).stdout.splitlines() if line.strip())
    if staged_now:
        raise RuntimeError(f"working tree contains staged changes before RALPH commit; automated commit refused: {staged_now}")
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


def _requalification_delta_guard(state: dict) -> tuple[list[str], list[str]]:
    """Require final qualification to cover exact current native provenance."""
    if isinstance(state.get("approved_plan_artifact"), dict):
        native = strict_native_provenance(
            state, "requalification", require_current_delta=True, require_write=True,
        )
        planned = set(native["new_plan_paths"])
    else:
        provenance = _reconciled_provenance_guard(state, "requalification")
        planned = set(provenance["new_plan_paths"])
    checkpoint = load_recovery_checkpoint(state.get("recovery_checkpoint"))
    if not checkpoint:
        raise RuntimeError("requalification requires a recovery checkpoint")
    baseline = {
        str(path) for path in checkpoint.get("baseline_dirty_paths") or []
    } | {
        str(path) for path in checkpoint.get("baseline_untracked_paths") or []
    }
    if not planned:
        raise RuntimeError("requalification requires recorded plan changes")
    overlap = sorted(baseline & planned)
    if overlap:
        raise RuntimeError(f"requalification refuses plan paths dirty at approval: {overlap}")
    current = {path for path in git_changed_paths() if not path.startswith(".ralph/")}
    unexpected = sorted(current - baseline - planned)
    if unexpected:
        raise RuntimeError(f"unexpected working-tree delta outside baseline/plan; requalification refused: {unexpected}")
    missing = sorted(planned - current)
    if missing:
        raise RuntimeError(f"recorded plan paths are no longer present in the working-tree delta: {missing}")
    protected = sorted(path for path in planned if is_protected_path(path) or _is_runtime_authority_path(path))
    if protected:
        raise RuntimeError(f"requalification refuses protected/runtime authority paths: {protected}")
    tooling = sorted(path for path in planned if is_tooling_path(path))
    unauthorized_tooling = sorted(set(tooling) - authorized_self_hosting_paths(state))
    if unauthorized_tooling:
        raise RuntimeError(f"requalification refuses RALPH tooling without same-plan self-hosting authority: {unauthorized_tooling}")
    return sorted(planned), sorted(baseline)


def _default_commit_message(state: dict) -> str:
    goal = " ".join(str(((state.get("plan") or {}).get("goal") or "RALPH plan completion")).split())
    goal = re.sub(r"[^A-Za-z0-9 ._/-]+", "", goal).strip()
    if len(goal) > 64:
        goal = goal[:61].rstrip() + "..."
    return f"{ZEN_PROFILE.completion_commit_prefix} {goal[0].lower() + goal[1:] if goal else 'ralph plan completion'}"


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


def _reject_read_only_terminal(state: dict, action: str) -> None:
    if state.get("status") == "READ_ONLY_COMPLETE":
        raise RuntimeError(
            f"{action} is prohibited for READ_ONLY_COMPLETE read-only terminal"
        )


def cmd_requalify(args: argparse.Namespace) -> int:
    """Re-run final qualification and bind it to exact native provenance."""
    init_files()
    state = load_state()
    if args.plan_hash != state.get("plan_hash"):
        raise RuntimeError("requalify hash does not match the current plan")
    _reject_read_only_terminal(state, "requalify")
    if state.get("status") != "READY_TO_COMMIT":
        raise RuntimeError(f"requalify requires READY_TO_COMMIT, found {state.get('status')}")
    # Check the exact current scope before spending gate time.  Executable
    # plans always have a controller-bound artifact, so this invokes strict
    # native provenance and never derives authority from filename projections.
    # Artifact-less objects are non-executable diagnostic fixtures only.
    if isinstance(state.get("approved_plan_artifact"), dict):
        _requalification_delta_guard(state)
    passed, gates, durations, output = run_final_qualification(state)
    provenance = None
    fingerprint = None
    planned: list[str] = []
    if passed:
        if isinstance(state.get("approved_plan_artifact"), dict):
            provenance = strict_native_provenance(
                state, "requalification result", require_current_delta=True, require_write=True,
            )
            fingerprint = str(provenance["current_sha256"])
            planned = list(provenance["new_plan_paths"])
        else:
            # Artifact-less states are retained solely for non-executable
            # controller diagnostic fixtures.  They cannot reach terminal
            # admission, staging, commit, or push; retain their historical
            # fingerprint seam without granting filename-list authority.
            fingerprint = plan_delta_fingerprint(state)
    state["final_qualification"] = {
        "state": "PASS" if passed else "FAIL",
        "gates": gates,
        "durations": durations,
        "output": output[-6000:],
        "completed_at": utc_now(),
        "delta_fingerprint": fingerprint,
        "native_provenance_sha256": provenance.get("binding_sha256") if provenance else None,
        "completion_summary": {
            "delta_fingerprint": fingerprint,
            "native_provenance_sha256": provenance.get("binding_sha256") if provenance else None,
            "recorded_plan_paths": planned,
        } if passed else None,
    }
    if not passed:
        state["status"] = "BLOCKED_HUMAN"
        state["block_reason"] = "final requalification failed for current plan delta"
        save_state(state)
        live_write(state["block_reason"], "FAIL")
        if output:
            print(output[-6000:])
        return 2
    entries = change_entries(planned)
    state["completion_changes"] = {
        "entries": entries,
        "files": len(entries),
        "added": sum(int(item.get("added") or 0) for item in entries),
        "removed": sum(int(item.get("removed") or 0) for item in entries),
    }
    state["block_reason"] = None
    save_state(state)
    build_completion_report(state, gates)
    live_write(f"final requalification PASS · delta={fingerprint[:12]}", "READY")
    print(f"REQUALIFIED plan={state['plan_hash']} delta={fingerprint}")
    return 0


def cmd_finalize(args: argparse.Namespace) -> int:
    init_files()
    state = load_state()
    if args.plan_hash != state.get("plan_hash"):
        raise RuntimeError("finalize hash does not match the current plan")
    action = "push" if args.push else "commit" if args.commit else "review"
    terminal_action = f"finalize --{action}" if action != "review" else "finalize review"
    _reject_read_only_terminal(state, terminal_action)
    if action == "review":
        if state.get("status") not in {"READY_TO_COMMIT", "COMMITTED", "PUSHED"}:
            raise RuntimeError(f"finalize review requires READY_TO_COMMIT/COMMITTED/PUSHED, found {state.get('status')}")
        if state.get("status") == "READY_TO_COMMIT":
            qualified, qualified_reason = qualified_delta_matches(state)
            if not qualified:
                raise RuntimeError(f"finalize review refused: {qualified_reason}")
            review = finalization_review(state)
        else:
            provenance = _qualified_native_provenance(
                state, "finalize review", require_current_delta=False, require_write=True,
            )
            sha = str(state.get("commit_sha") or "")
            if not sha:
                raise RuntimeError("finalize review requires recorded commit SHA")
            _verify_commit_native_provenance(state, sha, provenance, "finalize review")
            review = {"overlap": [], "planned": provenance["new_plan_paths"], "checkpoint": load_recovery_checkpoint(state.get("recovery_checkpoint"))}
        report = build_completion_report(state, list((state.get("final_qualification") or {}).get("gates") or []))
        print(tui.completion_card(report))
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
        provenance = _qualified_native_provenance(
            state, "automated commit", require_current_delta=True, require_write=True,
        )
        planned, _baseline = _finalization_guard(state)
        _git(["add", "--", *planned])
        staged = sorted(line.strip() for line in _git(["diff", "--cached", "--name-only"], check=False).stdout.splitlines() if line.strip())
        if staged != sorted(planned):
            _git(["reset"], check=False)
            raise RuntimeError(f"staged commit scope does not exactly match qualified plan delta: staged={staged} planned={sorted(planned)}")
        message = args.message or _default_commit_message(state)
        proc = _git(["commit", "-m", message, "-m", f"RALPH-Plan: {state.get('plan_hash')}"] , check=False)
        if proc.returncode != 0:
            _git(["reset"], check=False)
            raise RuntimeError(f"git commit failed ({proc.returncode}): {proc.stdout[-4000:]}")
        sha = git_head()
        _verify_commit_native_provenance(state, sha, provenance, "automated commit")
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
    provenance = _qualified_native_provenance(
        state, "automated push", require_current_delta=False, require_write=True,
    )
    sha = str(state.get("commit_sha") or "")
    if not sha:
        raise RuntimeError("automated push requires recorded commit SHA")
    _verify_commit_native_provenance(state, sha, provenance, "automated push")
    upstream = git_upstream()
    if not upstream or "/" not in upstream:
        raise RuntimeError("current branch has no configured upstream; push refused")
    remote, _remote_branch = upstream.split("/", 1)
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
    live_write(f"pushed commit {sha[:12]} to configured upstream {upstream}", "COMPLETE")
    print(f"PUSHED plan={state['plan_hash']} upstream={upstream}")
    return 0


def cmd_reconcile_commit(args: argparse.Namespace) -> int:
    """Adopt an already-created qualified commit after strict controller verification."""
    init_files()
    state = load_state()
    if args.plan_hash != state.get("plan_hash"):
        raise RuntimeError("reconcile-commit hash does not match the current plan")
    _reject_read_only_terminal(state, "reconcile-commit")
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
    """Mark a reconciled/created commit PUSHED only after native provenance proof."""
    init_files()
    state = load_state()
    if args.plan_hash != state.get("plan_hash"):
        raise RuntimeError("reconcile-push hash does not match the current plan")
    _reject_read_only_terminal(state, "reconcile-push")
    if state.get("status") not in {"COMMITTED", "PUSHED"}:
        raise RuntimeError(f"reconcile-push requires COMMITTED/PUSHED, found {state.get('status')}")
    sha = str(state.get("commit_sha") or "").strip()
    if not sha:
        raise RuntimeError("no recorded commit SHA")
    provenance = _qualified_native_provenance(
        state, "reconciled push", require_current_delta=False, require_write=True,
    )
    _verify_commit_native_provenance(state, sha, provenance, "reconciled push")
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


def cmd_adopt_test_reconciliation(args: argparse.Namespace) -> int:
    """Adopt the single controller-validated late test delta into plan scope."""
    init_files()
    state = load_state()
    active_plan_hash = str(state.get("plan_hash") or "")
    if not active_plan_hash or not secrets.compare_digest(str(args.plan_hash or ""), active_plan_hash):
        raise RuntimeError("adopt-test-reconciliation hash does not match the current plan")
    if state.get("status") != "READY_TO_COMMIT":
        raise RuntimeError(f"adopt-test-reconciliation requires READY_TO_COMMIT, found {state.get('status')}")
    path = str(args.path or "")
    if path != READY_TO_COMMIT_TEST_RECONCILIATION_PATH:
        raise RuntimeError("adopt-test-reconciliation requires the exact approved test path")
    if str(args.confirm or "") != "ADOPT":
        raise RuntimeError("adopt-test-reconciliation requires --confirm ADOPT")
    reason = " ".join(str(args.reason or "").split())
    if not reason:
        raise RuntimeError("adopt-test-reconciliation requires a non-empty --reason")

    candidate = ready_to_commit_test_reconciliation_candidate(state)
    if candidate is None or candidate.get("path") != path:
        raise RuntimeError("adopt-test-reconciliation refused: validated candidate is missing, stale, duplicate, or not exact")
    if candidate.get("delta_kind") not in {"untracked", "modified"}:
        raise RuntimeError("adopt-test-reconciliation refused nonqualifying test delta")
    adopted_path = str(candidate["path"])
    baseline_kind = plan_baseline_path_kind(state, adopted_path)
    if baseline_kind != "absent":
        raise RuntimeError("adopt-test-reconciliation refused: test path existed at approval")
    adoptions = state.get("test_reconciliation_adoptions")
    adoptions = list(adoptions) if isinstance(adoptions, list) else []
    if any(isinstance(item, dict) and item.get("path") == adopted_path for item in adoptions):
        raise RuntimeError("adopt-test-reconciliation refused duplicate adoption")

    qualification = state.get("final_qualification") if isinstance(state.get("final_qualification"), dict) else {}
    if str(qualification.get("state") or "") != "PASS":
        raise RuntimeError("adopt-test-reconciliation requires prior final qualification PASS")
    fingerprint = str(qualification.get("delta_fingerprint") or "").strip()
    if not fingerprint:
        raise RuntimeError("adopt-test-reconciliation requires a bound prior qualification fingerprint")
    # A plan may consist solely of the approved late test.  There is no
    # pre-adoption delta to fingerprint in that narrow case; the recorded PASS
    # binding remains required, while a nonempty existing scope is rechecked.
    if state.get("plan_changed_files"):
        qualified, qualified_reason = qualified_delta_matches(state)
        if not qualified:
            raise RuntimeError(f"adopt-test-reconciliation refused stale qualification: {qualified_reason}")

    prior_binding = {
        "state": "PASS",
        "completed_at": qualification.get("completed_at"),
        "delta_fingerprint": fingerprint,
    }
    baseline_result = _ApprovalBaselineAbsence(path)
    adoption = {
        "schema": "zen_ralph_test_reconciliation_adoption_v1",
        "plan_hash": state["plan_hash"],
        "path": adopted_path,
        "approval_baseline": baseline_result,
        "operator_reason": reason[:1200],
        "adopted_at": utc_now(),
        "prior_qualification": prior_binding,
        "prior_qualification_binding": prior_binding,
    }
    adoption["entry_hash"] = hashlib.sha256(json.dumps(adoption, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    state["test_reconciliation_adoptions"] = [*adoptions, adoption]

    # `ready_to_commit_test_reconciliation_candidate` cannot produce a real
    # candidate without a recovery checkpoint.  Keep the historical in-memory
    # command fixtures (which deliberately replace that derivation) compatible,
    # but never allow this branch in a controller-derived invocation.  A real
    # adoption always immediately requalifies the expanded, guarded delta.
    if not state.get("recovery_checkpoint"):
        # This is only reachable by an in-memory/mocked candidate: the real
        # candidate derivation requires the checkpoint above.  It remains
        # explicitly blocked and never gains validated plan ownership.
        state["plan_changed_files"] = sorted(
            set(state.get("plan_changed_files") or []) | {adopted_path}
        )
        state["final_qualification"] = {
            "state": "STALE",
            "requalified_after": None,
            "prior_delta_fingerprint": fingerprint,
        }
        state["status"] = "BLOCKED_HUMAN"
        state["block_reason"] = "final requalification requires a recovery checkpoint"
        save_state(state)
        append_journal(
            int(state.get("loop_count") or 0), int(state.get("current_step") or 0),
            "test-reconciliation-adoption", "ADOPTED", summary=reason, files=[adopted_path],
            next_action="requalify the expanded plan delta",
        )
        tui.write_event(EVENTS, "TEST_ADOPTION", f"adopted {adopted_path}", adoption=adoption)
        live_write(state["block_reason"], "FAIL")
        print(f"TEST_ADOPTED plan={state['plan_hash']} path={adopted_path}; requalification required")
        return 0

    remember_plan_files(state, [adopted_path])
    passed, gates, durations, output = run_final_qualification(state)
    resulting_fingerprint = plan_delta_fingerprint(state) if passed else None
    state["final_qualification"] = {
        "state": "PASS" if passed else "FAIL",
        "gates": gates,
        "durations": durations,
        "output": output[-6000:],
        "completed_at": utc_now(),
        "delta_fingerprint": resulting_fingerprint,
        "completion_summary": {
            "delta_fingerprint": resulting_fingerprint,
            "recorded_plan_paths": sorted({str(item) for item in state.get("plan_changed_files") or []}),
        } if passed else None,
        "requalified_after": "test-reconciliation-adoption",
        "prior_delta_fingerprint": fingerprint,
    }
    if not passed:
        state["status"] = "BLOCKED_HUMAN"
        state["block_reason"] = "final requalification failed after test-reconciliation adoption"
    else:
        state["block_reason"] = None
    save_state(state)
    append_journal(
        int(state.get("loop_count") or 0), int(state.get("current_step") or 0),
        "test-reconciliation-adoption", "ADOPTED" if passed else "REQUALIFICATION_FAIL", summary=reason, files=[adopted_path],
        gates=gates, next_action="finalize review" if passed else "human review final requalification output",
    )
    tui.write_event(EVENTS, "TEST_ADOPTION", f"adopted {adopted_path}", adoption=adoption)
    if not passed:
        live_write(state["block_reason"], "FAIL")
        if output:
            print(output[-6000:])
        return 2
    live_write(f"adopted validated test delta {adopted_path}; final qualification PASS · delta={resulting_fingerprint[:12]}", "READY")
    print(f"TEST_ADOPTED plan={state['plan_hash']} path={adopted_path}; requalified delta={resulting_fingerprint}")
    return 0


def init_files() -> None:
    RALPH.mkdir(parents=True, exist_ok=True)
    RECOVERY.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)
    EVENTS.touch(exist_ok=True)
    USAGE_LEDGER.touch(exist_ok=True)
    efficiency_policy.ensure_policy(ROOT)
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


def plan_control_event(
    state: dict,
    control_kind: str,
    message: str,
    *,
    step: int | None = None,
    loop: int | None = None,
    **data,
) -> None:
    """Persist plan-bound human/control activity without relying on current state later.

    Legacy events intentionally remain un-attributed.  Only this explicit schema is
    consumed by historical per-plan control statistics so old/test-generated generic
    GATE events can never be guessed onto a plan.
    """
    plan_hash_value = str(state.get("plan_hash") or "").strip()
    if not plan_hash_value:
        return
    now = dt.datetime.now(dt.timezone.utc)
    tui.write_event(
        EVENTS,
        "CONTROL",
        message,
        schema="zen_ralph_plan_control_v1",
        epoch=int(now.timestamp()),
        plan_hash=plan_hash_value,
        control_kind=str(control_kind),
        loop=int(state.get("loop_count") or 0) if loop is None else int(loop),
        step=int(state.get("current_step") or 0) if step is None else int(step),
        **data,
    )


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


def clear_self_hosting_context(state: dict) -> None:
    """Expire one-step authority material when its gate can no longer be current."""
    state["self_hosting_grant"] = None
    state["self_hosting_candidate"] = None


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
    selected_model = selected_codex_model()
    selected_effort = selected_codex_effort()
    with tempfile.TemporaryDirectory(prefix="ralph-lite-") as temp_dir:
        schema_path = Path(temp_dir) / "schema.json"
        output_path = Path(temp_dir) / "result.json"
        schema_path.write_text(json.dumps(schema), encoding="utf-8")
        command = [*prefix, "exec"]
        if selected_model:
            command += ["--model", selected_model]
        if selected_effort:
            command += ["--config", f'model_reasoning_effort="{selected_effort}"']
        command += [
            "--ephemeral", "--json", "--sandbox", sandbox,
            "--output-schema", str(schema_path), "-o", str(output_path), prompt,
        ]
        live_write(
            f"{context} · model={selected_model or 'codex-default'} · effort={selected_effort or 'codex-default'} "
            f"· sandbox={sandbox} backend=default",
            "CODEX",
        )
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
    return ZEN_PROFILE.qualification_gates(ROOT, sys.executable)


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


def _efficiency_mode(value: str | None) -> str:
    mode = str(value or "NORMAL").upper()
    if mode not in EFFICIENCY_MODES:
        raise ValueError(f"invalid efficiency mode {value!r}; expected one of {', '.join(EFFICIENCY_MODES)}")
    return mode


def efficiency_findings(stats: dict | None, mode: str | None = None, policy: dict | None = None) -> list[str]:
    """Return live policy-level efficiency findings; OFF disables ordinary policy only."""
    policy_source = efficiency_policy.load_policy(ROOT) if policy is None else policy
    policy = efficiency_policy.normalize_policy(policy_source)
    mode = _efficiency_mode(mode or str(policy.get("mode") or "NORMAL"))
    if mode == "OFF":
        return []
    stats = dict(stats or {})
    commands = int(stats.get("commands_executed") or 0)
    files = int(stats.get("files_inspected") or 0)
    cumulative = int(stats.get("input_tokens") or 0)
    cached = int(stats.get("cached_input_tokens") or 0)
    noncached = max(0, cumulative - cached)
    limits = efficiency_policy.limits(policy, mode)
    findings: list[str] = []
    if commands > limits["commands"]:
        findings.append(f"commands {commands}>{limits['commands']}")
    if files > limits["files"]:
        findings.append(f"reported-files {files}>{limits['files']}")
    if cumulative > limits["cumulative"]:
        findings.append(f"cumulative-input {cumulative}>{limits['cumulative']}")
    if noncached > limits["noncached"]:
        findings.append(f"non-cached-input {noncached}>{limits['noncached']}")
    return findings


def runaway_findings(stats: dict | None, policy: dict | None = None) -> list[str]:
    """Return emergency findings from live policy; these remain active in every mode."""
    policy_source = efficiency_policy.load_policy(ROOT) if policy is None else policy
    policy = efficiency_policy.normalize_policy(policy_source)
    limits = efficiency_policy.runaway_limits(policy)
    stats = dict(stats or {})
    commands = int(stats.get("commands_executed") or 0)
    files = int(stats.get("files_inspected") or 0)
    cumulative = int(stats.get("input_tokens") or 0)
    cached = int(stats.get("cached_input_tokens") or 0)
    noncached = max(0, cumulative - cached)
    findings: list[str] = []
    if commands > limits["commands"]:
        findings.append(f"commands {commands}>{limits['commands']}")
    if files > limits["files"]:
        findings.append(f"reported-files {files}>{limits['files']}")
    if cumulative > limits["cumulative"]:
        findings.append(f"cumulative-input {cumulative}>{limits['cumulative']}")
    if noncached > limits["noncached"]:
        findings.append(f"non-cached-input {noncached}>{limits['noncached']}")
    return findings


def recommended_efficiency_mode(goal: str) -> str:
    """Recommend, but never silently select, a mode for broad/high-context plans."""
    text = str(goal or "").lower()
    broad = (
        "documentation", "docs", "repository-wide", "repository wide", "architecture review",
        "migration", "extraction", "audit", "deep review", "full review", "inventory",
    )
    return "RELAXED" if any(marker in text for marker in broad) else "NORMAL"


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


READY_TO_COMMIT_TEST_RECONCILIATION_PATH = "tests/test_ralph_profile.py"


class _ApprovalBaselineAbsence(dict):
    """Structured adoption evidence with compatibility for older in-memory callers."""

    def __init__(self, path: str):
        super().__init__(path=path, result="absent")

    def __eq__(self, other: object) -> bool:
        if other == "absent":
            return self.get("result") == "absent"
        return super().__eq__(other)


def _worktree_delta_kind(path: str) -> str | None:
    """Classify one exact current worktree path without normalizing its input."""
    proc = _git(["status", "--porcelain=v1", "-z", "--untracked-files=all", "--", path], check=False)
    if proc.returncode != 0:
        return None
    for entry in proc.stdout.split("\0"):
        if len(entry) < 4 or entry[3:] != path:
            continue
        status = entry[:2]
        if status == "??":
            return "untracked"
        if status.strip():
            return "modified"
    return None


def validate_ready_to_commit_test_reconciliation(
    state: dict, requested_path: str | None = None,
) -> tuple[bool, str]:
    """Validate the sole controller-owned READY_TO_COMMIT test delta."""
    path = READY_TO_COMMIT_TEST_RECONCILIATION_PATH
    # This is intentionally an exact comparison: the caller may ask whether a
    # value is eligible, but never normalize it into a selectable adoption path.
    if requested_path is not None and requested_path != path:
        return False, "test reconciliation requires the exact controller-owned test path"
    if state.get("status") != "READY_TO_COMMIT":
        return False, "test reconciliation requires READY_TO_COMMIT"
    plan = state.get("plan")
    plan_digest = str(state.get("plan_hash") or "").strip()
    if plan is not None or plan_digest:
        if not isinstance(plan, dict) or not plan_digest:
            return False, "test reconciliation requires an active approved plan"
        try:
            validate_plan(plan)
        except (TypeError, ValueError):
            return False, "test reconciliation requires a valid active plan"
        if not secrets.compare_digest(plan_hash(plan), plan_digest):
            return False, "test reconciliation refuses stale active-plan authority"
    if is_protected_path(path) or _is_runtime_authority_path(path) or is_tooling_path(path):
        return False, "test reconciliation refuses protected, runtime, or tooling paths"
    checkpoint = load_recovery_checkpoint(state.get("recovery_checkpoint"))
    if not checkpoint:
        return False, "recovery checkpoint is missing"
    checkpoint_plan_hash = str(checkpoint.get("plan_hash") or "")
    if plan_digest and not secrets.compare_digest(checkpoint_plan_hash, plan_digest):
        return False, "test reconciliation refuses a checkpoint outside the active plan"
    if plan_baseline_path_kind(state, path) != "absent":
        return False, "test path existed at approval"
    planned = {str(item) for item in state.get("plan_changed_files") or []}
    if path in planned:
        return False, "test path is already a recorded plan change"
    baseline = {
        str(item) for item in checkpoint.get("baseline_dirty_paths") or []
    } | {
        str(item) for item in checkpoint.get("baseline_untracked_paths") or []
    }
    current = {item for item in git_changed_paths() if not item.startswith(".ralph/")}
    unexpected = current - baseline - planned
    if unexpected != {path}:
        return False, "test reconciliation requires the test path to be the sole unexpected delta"
    return True, "eligible test reconciliation delta"


def ready_to_commit_test_reconciliation_candidate(state: dict) -> dict | None:
    """Derive, rather than accept, the only test-reconciliation candidate."""
    path = READY_TO_COMMIT_TEST_RECONCILIATION_PATH
    valid, _reason = validate_ready_to_commit_test_reconciliation(state)
    if not valid:
        return None
    delta_kind = _worktree_delta_kind(path)
    if delta_kind not in {"untracked", "modified"}:
        return None
    return {"path": path, "delta_kind": delta_kind}


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


def plan_prompt(goal: str, carry_forward: dict | None = None, *, min_steps: int = PLAN_MIN_STEPS_DEFAULT, max_steps: int = PLAN_MAX_STEPS_DEFAULT) -> str:
    carry_forward_text = ""
    if carry_forward:
        carry_forward_text = (
            "\nCURRENT REPLACEMENT RETIREMENT (authoritative for this proposal):\n"
            f"- RT: {carry_forward.get('current_retirement_record_id') or '-'}\n"
            f"- Reason: {carry_forward.get('current_retirement_reason') or '-'}\n"
            f"- Source plan: {carry_forward.get('source_plan_hash') or '-'}\n"
            "Historical planning context follows for background only. It grants no execution, "
            "test-change, self-hosting, path ownership, or goal authority. Do not promote an "
            "ancestor planning goal over the current Goal/RT reason, and preserve already-accepted "
            "prior work unless the current retirement reason specifically requires its repair.\n"
            + json.dumps(carry_forward.get("historical_planning_context") or {}, sort_keys=True, ensure_ascii=False)
            + "\n"
        )
    return f"""You are planning work for {ZEN_PROFILE.identity} under RALPH-Lite. Inspect the repository read-only.
Goal: {goal}
{carry_forward_text}
Return between {min_steps} and {max_steps} ordered, concrete implementation steps. Keep steps small enough to implement and qualify independently.
For each step choose test_change_policy: none, add-only, or modify. Prefer add-only; use modify only when modifying existing tests is genuinely required.
Use targeted symbol/range reads instead of broad repository ingestion. Avoid reading docs, README, CHANGELOG, or Git history unless directly needed for the goal.
Do not execute or edit anything. Respect .ralph/policy.md. Put discovered nice-to-have work into later plan steps only if it directly serves the goal; otherwise it belongs in the ideas bucket during execution.
"""


def step_prompt(state: dict, step: dict, repair_fp: str | None, repair_no: int) -> str:
    policy = efficiency_policy.load_policy(ROOT)
    mode = _efficiency_mode(str(policy.get("mode") or "NORMAL"))
    command_budget = int(efficiency_policy.limits(policy, mode)["prompt_commands"])
    repair_text = ""
    if repair_fp:
        repair_text = (
            f"\nThis is repair attempt {repair_no} for failure fingerprint {repair_fp}. "
            "Fix the failure without weakening qualification.\n"
            + repair_failure_evidence(state, repair_fp)
        )
    prior = context_handoff(state)
    return f"""Execute exactly ONE approved RALPH-Lite plan step in {ZEN_PROFILE.identity}.
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
- HARD BUDGET: use at most {command_budget} shell command executions for this implementation turn. If safe completion genuinely needs another normal implementation/shell turn while remaining inside this approved step, return blocker_class="continuation", needs_human=false, explain the next bounded action in blockers, and stop this turn. The controller will schedule another loop without creating a human gate.
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



def _configured_codex_selection() -> tuple[str | None, str | None]:
    """Read only model/effort selection from Codex config; retain nothing else."""
    path = Path.home() / ".codex" / "config.toml"
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return None, None
    if not isinstance(data, dict):
        return None, None
    model = data.get("model")
    effort = data.get("model_reasoning_effort")
    model_value = str(model).strip() if isinstance(model, str) and model.strip() else None
    effort_value = str(effort).strip().lower() if isinstance(effort, str) and effort.strip() else None
    return model_value, effort_value


def configured_codex_model() -> str | None:
    return _configured_codex_selection()[0]


def configured_codex_effort() -> str | None:
    return _configured_codex_selection()[1]


def selected_codex_model() -> str | None:
    """Return RALPH's project-local model override, otherwise the Codex default."""
    selected = model_policy.load_policy(ROOT).get("model")
    return str(selected).strip() if selected else configured_codex_model()


def selected_codex_effort() -> str | None:
    """Return RALPH's project-local effort override, otherwise the Codex default."""
    selected = model_policy.load_policy(ROOT).get("reasoning_effort")
    return str(selected).strip().lower() if selected else configured_codex_effort()


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


def query_codex_rate_limits(*, timeout: float = USAGE_APP_SERVER_TIMEOUT_SECONDS, include_reset_credit_details: bool = False) -> dict:
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
                "clientInfo": {"name": "ralph-lite", "title": "RALPH-Lite", "version": "0.4.0"},
                "capabilities": {"experimentalApi": True},
            },
        })
        _app_server_read_response(proc, 1, timeout)
        _app_server_send(proc.stdin, {"jsonrpc": "2.0", "method": "initialized", "params": {}})
        _app_server_send(proc.stdin, {
            "jsonrpc": "2.0", "id": 2, "method": "account/rateLimits/read",
            "params": {"supportsLunaReserve": False, "excludeResetCreditDetails": not include_reset_credit_details},
        })
        raw = _app_server_read_response(proc, 2, timeout)
        return normalise_codex_usage(raw, selected_codex_model())
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            try:
                proc.kill()
            except OSError:
                pass


def query_codex_models(*, timeout: float = USAGE_APP_SERVER_TIMEOUT_SECONDS) -> dict:
    """Read the authenticated Codex model picker catalog through app-server model/list."""
    codex = shutil.which("codex")
    if not codex:
        raise RuntimeError("codex not found")
    proc = subprocess.Popen(
        [codex, "app-server", "--stdio"], cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, bufsize=1,
    )
    try:
        assert proc.stdin is not None
        _app_server_send(proc.stdin, {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "clientInfo": {"name": "ralph-lite", "title": "RALPH-Lite", "version": "0.4.0"},
                "capabilities": {"experimentalApi": True},
            },
        })
        _app_server_read_response(proc, 1, timeout)
        _app_server_send(proc.stdin, {"jsonrpc": "2.0", "method": "initialized", "params": {}})
        _app_server_send(proc.stdin, {
            "jsonrpc": "2.0", "id": 2, "method": "model/list",
            "params": {"limit": 100, "cursor": None, "includeHidden": False},
        })
        raw = _app_server_read_response(proc, 2, timeout)
        data = raw.get("data") if isinstance(raw.get("data"), list) else []
        models: list[dict] = []
        for item in data:
            if not isinstance(item, dict):
                continue
            model_id = str(item.get("model") or item.get("id") or "").strip()
            if not model_id:
                continue
            efforts = []
            for option in item.get("supportedReasoningEfforts") or []:
                if isinstance(option, dict) and option.get("reasoningEffort"):
                    efforts.append(str(option.get("reasoningEffort")))
            models.append({
                "id": model_id,
                "display_name": str(item.get("displayName") or model_id),
                "description": str(item.get("description") or ""),
                "is_default": bool(item.get("isDefault")),
                "reasoning_efforts": efforts,
                "default_reasoning_effort": (
                    str(item.get("defaultReasoningEffort")).strip().lower()
                    if item.get("defaultReasoningEffort") is not None
                    else None
                ),
            })
        selected = selected_codex_model()
        return {
            "selected": selected,
            "selected_effort": selected_codex_effort(),
            "configured_default": configured_codex_model(),
            "configured_default_effort": configured_codex_effort(),
            "models": models,
            "captured_at": utc_now(),
        }
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            try:
                proc.kill()
            except OSError:
                pass


def consume_codex_reset_credit(credit_id: str | None = None, *, timeout: float = USAGE_APP_SERVER_TIMEOUT_SECONDS) -> dict:
    """Redeem one explicitly confirmed banked reset through the supported app-server API."""
    codex = shutil.which("codex")
    if not codex:
        raise RuntimeError("codex not found")
    proc = subprocess.Popen(
        [codex, "app-server", "--stdio"], cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, bufsize=1,
    )
    idempotency_key = str(uuid.uuid4())
    try:
        assert proc.stdin is not None
        _app_server_send(proc.stdin, {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "clientInfo": {"name": "ralph-lite", "title": "RALPH-Lite", "version": "0.4.0"},
                "capabilities": {"experimentalApi": True},
            },
        })
        _app_server_read_response(proc, 1, timeout)
        _app_server_send(proc.stdin, {"jsonrpc": "2.0", "method": "initialized", "params": {}})
        params: dict[str, str] = {"idempotencyKey": idempotency_key}
        if credit_id:
            params["creditId"] = str(credit_id)
        _app_server_send(proc.stdin, {
            "jsonrpc": "2.0", "id": 2, "method": "account/rateLimitResetCredit/consume", "params": params,
        })
        result = _app_server_read_response(proc, 2, timeout)
        outcome = str(result.get("outcome") or "unknown")
        if outcome not in {"reset", "nothingToReset", "noCredit", "alreadyRedeemed"}:
            raise RuntimeError(f"unexpected banked-reset outcome: {outcome}")
        return {"outcome": outcome}
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
    reset_credits: list[dict] = []
    for item in reset_summary.get("credits") or []:
        if not isinstance(item, dict):
            continue
        credit_id = str(item.get("id") or "").strip()
        if not credit_id:
            continue
        granted = item.get("grantedAt")
        expires = item.get("expiresAt")
        try:
            granted = int(granted) if granted is not None else None
        except (TypeError, ValueError):
            granted = None
        try:
            expires = int(expires) if expires is not None else None
        except (TypeError, ValueError):
            expires = None
        reset_credits.append({
            "id": credit_id,
            "status": str(item.get("status") or "unknown"),
            "reset_type": str(item.get("resetType") or "unknown"),
            "granted_at": granted,
            "expires_at": expires,
            "title": str(item.get("title") or "Banked reset"),
            "description": str(item.get("description") or ""),
        })
    reset_credits.sort(key=lambda item: (item.get("expires_at") is None, int(item.get("expires_at") or 2**62)))
    return {
        "captured_at": utc_now(),
        "model": model,
        "plan_type": plan_type,
        "ordinary_usage_allowed": raw.get("ordinaryUsageAllowed") if isinstance(raw.get("ordinaryUsageAllowed"), bool) else None,
        "windows": windows,
        "available_reset_credits": available_resets,
        "reset_credits": reset_credits,
    }


def usage_admission_valid(state: dict) -> bool:
    admission = state.get("usage_admission") if isinstance(state.get("usage_admission"), dict) else {}
    return bool(
        admission
        and admission.get("plan_hash")
        and admission.get("plan_hash") == state.get("plan_hash")
        and admission.get("admitted") is True
    )


def _minimum_remaining(snapshot: dict) -> float | None:
    windows = snapshot.get("windows") if isinstance(snapshot.get("windows"), list) else []
    values = [float(w.get("remaining_percent", 100.0)) for w in windows if isinstance(w, dict)]
    return min(values) if values else None


def admit_usage_for_plan(state: dict, snapshot: dict, reserve_percent: float = USAGE_RESERVE_PERCENT) -> bool:
    """Latch start authority to one plan when it has headroom above the reserve."""
    if usage_admission_valid(state):
        return True
    guard, _ = codex_usage_guard(snapshot, reserve_percent=reserve_percent, admitted=False)
    if guard != "SAFE":
        return False
    state["usage_admission"] = {
        "admitted": True,
        "plan_hash": state.get("plan_hash"),
        "admitted_at": utc_now(),
        "reserve_percent": reserve_percent,
        "remaining_percent_at_admission": _minimum_remaining(snapshot),
    }
    return True


def codex_usage_guard(snapshot: dict, reserve_percent: float = USAGE_RESERVE_PERCENT, *, admitted: bool = False) -> tuple[str, list[str]]:
    """Return SAFE, ADMITTED, PAUSE, or UNKNOWN using backend authority and start-reserve semantics."""
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
        findings = [f"{w.get('name', 'usage')} remaining {float(w.get('remaining_percent', 0.0)):.1f}% <= {reserve_percent:.1f}% reserve" for w in low]
        if admitted:
            return "ADMITTED", findings
        return "PAUSE", findings
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


def record_usage_pause(state: dict, snapshot: dict, findings: list[str], reserve_percent: float) -> None:
    state["status"] = "PAUSED_USAGE_LIMIT"
    state["block_reason"] = "; ".join(findings) or "Codex usage reserve reached"
    state["codex_usage"] = snapshot
    state["usage_pause"] = {
        "recorded_at": utc_now(),
        "reserve_percent": reserve_percent,
        "reason": state["block_reason"],
        "snapshot": snapshot,
    }
    save_state(state)
    with JOURNAL.open("a", encoding="utf-8") as handle:
        handle.write(
            f"## Usage pause — {utc_now()}\n\n"
            f"- Plan: `{state.get('plan_hash') or '-'}`\n"
            f"- Step: {state.get('current_step')}\n"
            f"- Reserve: {reserve_percent:.1f}% remaining\n"
            f"- Reason: {state['block_reason']}\n"
            f"- Snapshot: {usage_snapshot_line(snapshot)}\n"
            "- State: recorded; no new Codex model turn will start until limits recover\n\n"
        )


def ensure_codex_usage_capacity(state: dict, *, wait: bool = True, poll_seconds: int = USAGE_POLL_SECONDS) -> bool:
    """Admit a plan above reserve, then allow that same plan to finish below reserve.

    Backend denial always wins. The configured reserve is a *new-plan admission
    gate*, not an in-flight kill switch. Admission is plan-bound and persisted
    across reruns. The reserve is re-read live for work that is not yet admitted.
    """
    was_paused = state.get("status") == "PAUSED_USAGE_LIMIT"
    while True:
        try:
            policy = efficiency_policy.load_policy(ROOT)
            reserve_percent = float(policy["reserve_percent"])
            snapshot = query_codex_rate_limits()
            admitted = usage_admission_valid(state)
            guard, findings = codex_usage_guard(snapshot, reserve_percent=reserve_percent, admitted=admitted)
        except Exception as exc:
            snapshot = {"captured_at": utc_now(), "model": configured_codex_model(), "plan_type": None, "ordinary_usage_allowed": None, "windows": [], "available_reset_credits": None}
            guard, findings = "UNKNOWN", [f"rate-limit read failed: {exc}"]
        state["codex_usage"] = snapshot

        if guard == "SAFE":
            if not usage_admission_valid(state):
                admit_usage_for_plan(state, snapshot, reserve_percent=reserve_percent)
                live_write(
                    f"plan admitted above {reserve_percent:.1f}% start reserve · {usage_snapshot_line(snapshot)}",
                    "USAGE",
                )
            state["usage_pause"] = None
            state["block_reason"] = None
            if state.get("status") == "PAUSED_USAGE_LIMIT":
                state["status"] = "APPROVED"
                live_write(f"Codex limits recovered; resuming approved plan · {usage_snapshot_line(snapshot)}", "USAGE")
                with JOURNAL.open("a", encoding="utf-8") as handle:
                    handle.write(f"## Usage resumed — {utc_now()}\n\n- Snapshot: {usage_snapshot_line(snapshot)}\n- Next action: continue approved plan\n\n")
            save_state(state)
            return True

        if guard == "ADMITTED":
            # The plan entered execution with >reserve headroom. Continue the exact
            # admitted plan even below reserve so already-spent budget is not wasted.
            state["usage_pause"] = None
            state["block_reason"] = None
            if state.get("status") == "PAUSED_USAGE_LIMIT":
                state["status"] = "APPROVED"
            state["usage_admission"]["last_below_reserve_at"] = utc_now()
            state["usage_admission"]["last_remaining_percent"] = _minimum_remaining(snapshot)
            save_state(state)
            live_write(
                f"below start reserve but admitted plan may finish · {usage_snapshot_line(snapshot)}",
                "USAGE",
            )
            return True

        if not was_paused or state.get("status") != "PAUSED_USAGE_LIMIT":
            record_usage_pause(state, snapshot, findings, reserve_percent)
            was_paused = True
        detail = "; ".join(findings)
        live_write(f"Codex usage guard={guard}: {detail} · {usage_snapshot_line(snapshot)}", "USAGE")
        if not wait:
            print(f"BLOCKED_INSUFFICIENT_START_RESERVE plan={state.get('plan_hash') or '-'} step={state.get('current_step')} reason={detail}")
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
        "model": selected_codex_model(),
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


def usage_stats_reset_info() -> dict:
    try:
        raw = json.loads(USAGE_STATS_RESET.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return raw if isinstance(raw, dict) and raw.get("schema") == "zen_ralph_usage_stats_reset_v1" else {}


def usage_stats_reset_epoch() -> int:
    try:
        return max(0, int(usage_stats_reset_info().get("epoch") or 0))
    except (TypeError, ValueError):
        return 0


def reset_usage_statistics() -> dict:
    """Reset local token-stat views without touching provider quota or deleting the ledger."""
    RALPH.mkdir(parents=True, exist_ok=True)
    now = dt.datetime.now(dt.timezone.utc)
    marker = {
        "schema": "zen_ralph_usage_stats_reset_v1",
        "epoch": int(now.timestamp()),
        "reset_at": now.isoformat(),
    }
    tmp = USAGE_STATS_RESET.with_suffix(".tmp")
    tmp.write_text(json.dumps(marker, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, USAGE_STATS_RESET)
    return marker


def usage_ledger_rows(limit: int = USAGE_LEDGER_MAX_ROWS, *, include_before_reset: bool = False) -> list[dict]:
    if not USAGE_LEDGER.exists():
        return []
    cutoff = 0 if include_before_reset else usage_stats_reset_epoch()
    rows: list[dict] = []
    for raw in USAGE_LEDGER.read_text(encoding="utf-8", errors="replace").splitlines()[-max(1, int(limit)):]:
        try:
            item = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict) or item.get("schema") != "zen_ralph_usage_turn_v1":
            continue
        if cutoff and int(item.get("epoch") or 0) <= cutoff:
            continue
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


def _usage_breakdown(rows: list[dict], key: str) -> list[dict]:
    grouped: dict[str, list[dict]] = {}
    for row in rows:
        name = str(row.get(key) or "unknown")
        grouped.setdefault(name, []).append(row)
    output: list[dict] = []
    for name, items in grouped.items():
        totals = _sum_usage_rows(items)
        output.append({"name": name, **totals})
    output.sort(key=lambda item: int(item.get("input_tokens") or 0), reverse=True)
    return output


def _plan_control_stats(*, cutoff_epoch: int = 0) -> dict[str, dict]:
    """Return only explicitly plan-bound control events.

    Generic historical GATE/AUTHORITY events predate plan binding and may include
    test output, so they are deliberately ignored instead of being heuristically
    attributed.
    """
    output: dict[str, dict] = {}
    if not EVENTS.exists():
        return output
    for raw in EVENTS.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            item = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict) or item.get("schema") != "zen_ralph_plan_control_v1":
            continue
        plan = str(item.get("plan_hash") or "").strip()
        kind = str(item.get("control_kind") or "").strip()
        try:
            epoch = int(item.get("epoch") or 0)
        except (TypeError, ValueError):
            continue
        if not plan or not kind or (cutoff_epoch and epoch <= cutoff_epoch):
            continue
        stats = output.setdefault(plan, {
            "control_stats_status": "partial",
            "human_steers": 0,
            "self_hosting_grants": 0,
            "human_gates_opened": 0,
            "human_gates_resolved": 0,
        })
        if kind == "plan_control_baseline":
            stats["control_stats_status"] = "complete"
        elif kind == "human_steer":
            stats["human_steers"] += 1
        elif kind == "self_hosting_grant":
            stats["self_hosting_grants"] += 1
        elif kind == "human_gate_open":
            stats["human_gates_opened"] += 1
        elif kind == "human_gate_resolution":
            stats["human_gates_resolved"] += 1
    for stats in output.values():
        stats["steering_total"] = int(stats["human_steers"]) + int(stats["self_hosting_grants"])
    return output


def _plan_usage_summary(key: str, rows: list[dict], goal: str, current_hash: str, control_stats: dict | None = None) -> dict:
    totals = _sum_usage_rows(rows)
    first_epoch = min((int(row.get("epoch") or 0) for row in rows), default=0) or None
    last_epoch = max((int(row.get("epoch") or 0) for row in rows), default=0) or None
    turns = max(1, int(totals.get("turns") or 0))
    models = sorted({str(row.get("model") or "").strip() for row in rows if str(row.get("model") or "").strip()})
    controls = {
        "control_stats_status": "legacy",
        "human_steers": 0,
        "self_hosting_grants": 0,
        "human_gates_opened": 0,
        "human_gates_resolved": 0,
        "steering_total": 0,
        **dict(control_stats or {}),
    }
    return {
        "plan_hash": None if key == "unassigned" else key,
        "current": bool(current_hash and key == current_hash),
        "goal": goal,
        "first_epoch": first_epoch,
        "last_epoch": last_epoch,
        "models": models,
        "total_tokens": int(totals.get("input_tokens") or 0) + int(totals.get("output_tokens") or 0),
        "cache_ratio_percent": (float(totals.get("cached_input_tokens") or 0) / float(totals.get("input_tokens") or 1) * 100.0) if totals.get("input_tokens") else 0.0,
        "avg_input_tokens": int(int(totals.get("input_tokens") or 0) / turns),
        "avg_noncached_input_tokens": int(int(totals.get("noncached_input_tokens") or 0) / turns),
        "avg_output_tokens": int(int(totals.get("output_tokens") or 0) / turns),
        "scopes": _usage_breakdown(rows, "scope"),
        "phases": _usage_breakdown(rows, "phase"),
        "steps": _usage_breakdown(rows, "step"),
        **controls,
        **totals,
    }


def usage_ledger_report(state: dict, snapshot: dict | None = None) -> dict:
    """Return reset-aligned token tickers and detailed bounded per-plan consumption."""
    rows = usage_ledger_rows()
    reset_info = usage_stats_reset_info()
    control_by_plan = _plan_control_stats(cutoff_epoch=usage_stats_reset_epoch())
    current_hash = str(state.get("plan_hash") or "")
    current_rows = [row for row in rows if str(row.get("plan_hash") or "") == current_hash] if current_hash else []
    current = _sum_usage_rows(current_rows)
    source = "ledger"
    if current_hash and not current_rows and not reset_info:
        current = _fallback_current_plan_usage(state)
        source = "step-results-fallback" if current.get("turns") else "ledger"
    elif current_hash and not current_rows and reset_info:
        source = "reset-baseline"

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
        plans.append(_plan_usage_summary(
            key,
            list(group["rows"]),
            str(group.get("goal") or ""),
            current_hash,
            control_by_plan.get(key),
        ))
    plans.sort(key=lambda item: (not bool(item.get("current")), -int(item.get("last_epoch") or 0)))

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
        "stats_reset": reset_info or None,
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
    policy = efficiency_policy.load_policy(ROOT)
    reserve_percent = float(policy["reserve_percent"])
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
        "reserve_percent": reserve_percent,
        "efficiency_policy": policy,
        "codex_limits": snapshot,
        "ledger": usage_ledger_report(state, snapshot),
    }
    if snapshot:
        guard, findings = codex_usage_guard(snapshot, reserve_percent=reserve_percent, admitted=usage_admission_valid(state))
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
        snapshot = query_codex_rate_limits(include_reset_credit_details=bool(getattr(args, "include_reset_details", False)))
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
            reserve_percent = float(report["reserve_percent"])
            headroom = float(window["remaining_percent"]) - reserve_percent
            print(f"  {window['name']}: {window['remaining_percent']:.1f}% left (reserve {reserve_percent:.1f}%, headroom {headroom:.1f}pp), resets {_format_reset(window.get('resets_at'))}")
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
    plan_control_event(
        state,
        "human_gate_open",
        f"human gate opened {gate_id_for_state(state)}",
        gate_id=gate_id_for_state(state),
    )


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
    policy = efficiency_policy.load_policy(ROOT)
    reserve_percent = float(policy["reserve_percent"])
    if state.get("status") not in {"IDLE", "PLAN_COMPLETE", "PUSHED", "READ_ONLY_COMPLETE"}:
        raise RuntimeError(f"cannot propose while status={state.get('status')}; finish or resolve the current plan first")
    retirement_record_id = str(getattr(args, "from_retirement", "") or "").strip() or None
    carry_forward = None
    repository_authority = getattr(args, "repository_authority", None)
    # The command-line interface always requires an explicit authority.  Keep
    # the in-process replacement workflow usable for controller callers that
    # predate that argument; it still receives a controller-injected authority
    # and can never reach approval unbound.
    if repository_authority is None and retirement_record_id and not hasattr(args, "repository_authority"):
        repository_authority = "write"
    if repository_authority not in REPOSITORY_AUTHORITIES:
        raise RuntimeError("propose requires --repository-authority read-only or write")
    try:
        min_steps, max_steps = proposal_step_bounds(getattr(args, "min_steps", None), getattr(args, "max_steps", None))
    except (TypeError, ValueError) as exc:
        raise RuntimeError(str(exc)) from exc
    goal = str(getattr(args, "goal", "") or "").strip()
    if retirement_record_id:
        manifest, carry_forward = replacement_retirement_context(
            retirement_record_id, retirement_record_digest(state, retirement_record_id)
        )
        if not goal:
            goal = replacement_plan_goal(manifest)
    if not goal:
        raise RuntimeError("propose requires --goal or --from-retirement")
    try:
        proposal_usage = query_codex_rate_limits()
        proposal_guard, proposal_findings = codex_usage_guard(proposal_usage, reserve_percent=reserve_percent, admitted=False)
    except Exception as exc:
        raise RuntimeError(f"cannot verify new-work start reserve: {exc}") from exc
    if proposal_guard != "SAFE":
        detail = "; ".join(proposal_findings) or proposal_guard
        raise RuntimeError(f"BLOCKED_INSUFFICIENT_START_RESERVE: {detail}")
    proposal_schema = json.loads(json.dumps(PLAN_SCHEMA))
    proposal_schema["properties"]["steps"]["minItems"] = min_steps
    proposal_schema["properties"]["steps"]["maxItems"] = max_steps
    plan = run_codex(
        plan_prompt(goal, carry_forward, min_steps=min_steps, max_steps=max_steps),
        proposal_schema,
        "read-only",
        context="REPLACEMENT PLAN PROPOSAL" if carry_forward else "PLAN PROPOSAL",
    )
    plan["planning"] = {"min_steps": min_steps, "max_steps": max_steps}
    controller_inject_repository_authority(plan, repository_authority)
    validate_complete_plan(plan)
    digest = plan_hash(plan)
    if retirement_record_id and secrets.compare_digest(digest, str(manifest["plan_hash"])):
        raise RuntimeError("replacement proposal must produce a fresh plan hash")
    append_usage_ledger(
        plan.get("_ralph_metrics") if isinstance(plan, dict) else {},
        plan_hash_value=digest, goal=goal, scope="planning", phase="replacement-proposal" if carry_forward else "proposal",
    )
    previous_state = dict(state)
    previous_state.pop("proposal_previous_state", None)
    state.update({
        "status": "AWAITING_APPROVAL",
        "plan_hash": digest,
        "plan": plan,
        "current_step": 1,
        "failure_attempts": {},
        "active_failure": None,
        "last_failure": None,
        "last_result": None,
        "block_reason": None,
        "proposal_previous_state": previous_state,
        "retirement_record_id": retirement_record_id,
        "recovery_checkpoint": None,
        "approved_plan_artifact": None,
        "approval_repository_evidence": None,
        "operation_attributions": [],
        "pending_step_delta_paths": [],
        "plan_changed_files": [],
        "plan_owned_files": [],
        "plan_carry_forward_files": [],
        "carry_forward_candidates": replacement_dirty_inventory(manifest) if retirement_record_id else [],
        "test_reconciliation_adoptions": [],
        "human_gate_resolutions": [],
        "human_steering": [],
        "steering_allowed_new_tests": [],
        "self_hosting_grant": None,
        "self_hosting_candidate": None,
        "self_hosting_grant_history": [],
        "step_results": [],
        "final_qualification": None,
        "completion_changes": None,
        "commit_sha": None,
        "commit_message": None,
        "commit_reconciled": False,
        "commit_reconcile_note": None,
        "commit_reconciled_at": None,
        "push_upstream": None,
        "push_reconciled": False,
        "pushed_at": None,
        "usage_admission": {
            "admitted": True,
            "plan_hash": digest,
            "admitted_at": utc_now(),
            "reserve_percent": reserve_percent,
            "remaining_percent_at_admission": _minimum_remaining(proposal_usage),
            "scope": "proposal-and-plan",
        },
        "codex_usage": proposal_usage,
        "efficiency_mode": str(policy["mode"]),
        "efficiency_recommendation": recommended_efficiency_mode(goal),
    })
    PLAN.write_text(render_plan(plan), encoding="utf-8")
    save_state(state)
    print(render_plan(plan))
    print(f"Efficiency recommendation: {state['efficiency_recommendation']} (operator may select STRICT/NORMAL/RELAXED/OFF when running)")
    return 0


def cmd_approve(args: argparse.Namespace) -> int:
    init_files()
    state = load_state()
    if state.get("status") != "AWAITING_APPROVAL" or not state.get("plan"):
        raise RuntimeError("no plan is awaiting approval")
    validate_complete_plan(state["plan"], state.get("plan_hash"))
    expected = plan_hash(state["plan"])
    if args.plan_hash != expected or state.get("plan_hash") != expected:
        raise RuntimeError("approval hash does not match the proposed plan")
    if PLAN.read_text(encoding="utf-8") != render_plan(state["plan"]):
        raise RuntimeError("plan.md changed after proposal; proposal must be regenerated before approval")
    candidates: list[dict] = []
    retirement_record_id = state.get("retirement_record_id")
    if retirement_record_id:
        manifest, _ = replacement_retirement_context(
            str(retirement_record_id), retirement_record_digest(state, str(retirement_record_id))
        )
        # Re-inventory at approval so evidence is current at the moment
        # execution authority is granted; every dirty path has a final or
        # explicitly pending controller disposition before that point.
        candidates = replacement_dirty_inventory(manifest)
    # Approval starts a fresh native authority ledger. Proposal state must never
    # inherit operation evidence from a retired/completed plan.
    state["operation_attributions"] = []
    state["pending_step_delta_paths"] = []
    bind_approved_plan_artifact(state)
    checkpoint = create_recovery_checkpoint(state)
    state["status"] = "APPROVED"
    state["recovery_checkpoint"] = checkpoint["id"]
    state["approval_repository_evidence"] = checkpoint["repository_evidence"]
    state["plan_changed_files"] = []
    state["plan_owned_files"] = []
    state["plan_carry_forward_files"] = []
    state["carry_forward_candidates"] = candidates
    state["human_steering"] = []
    state["steering_allowed_new_tests"] = []
    clear_self_hosting_context(state)
    state["step_results"] = []
    state.pop("proposal_previous_state", None)
    save_state(state)
    plan_control_event(state, "plan_control_baseline", "plan control accounting baseline created", step=0)
    print(tui.box(
        "PLAN APPROVED · RECOVERY CHECKPOINT CREATED",
        [
            f"Plan {expected}",
            f"Steps {len(state['plan']['steps'])}",
            f"Repository authority {state['plan'][REPOSITORY_AUTHORITY_FIELD]}",
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
    if isinstance(previous, dict) and previous.get("status") in {"IDLE", "PLAN_COMPLETE", "PUSHED", "READ_ONLY_COMPLETE"}:
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


def cmd_reject_carry_forward(args: argparse.Namespace) -> int:
    """Public reconciliation command; kept after lifecycle commands intentionally."""
    return _cmd_reject_carry_forward(args)



def cmd_retire_plan(args: argparse.Namespace) -> int:
    """Retire an active plan by an explicit, auditable disposition."""
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

    # Parser-driven invocations always carry explicit disposition flags.  Keep
    # the pre-existing in-process controller API usable for its legacy callers;
    # it maps only a flag-less invocation to the non-destructive disposition.
    legacy_invocation = not hasattr(args, "rollback") and not hasattr(args, "carry_forward")
    rollback = bool(getattr(args, "rollback", False))
    carry_forward = bool(getattr(args, "carry_forward", False)) or legacy_invocation
    if rollback == carry_forward:
        raise RuntimeError("retire-plan requires exactly one of --rollback or --carry-forward")
    if legacy_invocation and not state.get("recovery_checkpoint"):
        state["recovery_checkpoint"] = create_recovery_checkpoint(state)["id"]
        save_state(state)
    checkpoint = load_recovery_checkpoint(state.get("recovery_checkpoint"))
    if not checkpoint or checkpoint.get("id") != state.get("recovery_checkpoint"):
        raise RuntimeError("retire-plan requires the active recovery checkpoint")
    if not secrets.compare_digest(str(checkpoint.get("plan_hash") or ""), str(expected)):
        raise RuntimeError("retire-plan recovery checkpoint does not belong to the active plan")
    recovery_oid, recovery_ref = str(checkpoint.get("recovery_oid") or ""), str(checkpoint.get("ref") or "")
    resolved = _git(["rev-parse", recovery_ref], check=False).stdout.strip() if recovery_oid and recovery_ref else ""
    if not recovery_oid or not recovery_ref or resolved != recovery_oid:
        raise RuntimeError("retire-plan recovery checkpoint ref is missing or inconsistent")

    old_step = int(state.get("current_step") or 1)
    old_loops = int(state.get("loop_count") or 0)
    steps = list(((state.get("plan") or {}).get("steps") or []))

    # Rollback obtains its entire target set from native operation attribution.
    # Carry-forward still needs immutable inventory evidence for replacement
    # reconciliation; its summary-path projection grants no rollback authority.
    carry_forward_paths = (
        set(state.get("plan_changed_files") or [])
        | set(state.get("plan_owned_files") or [])
        | set(state.get("plan_carry_forward_files") or [])
    )
    records = retirement_attribution_records(state) if rollback else retirement_path_records(state, carry_forward_paths)

    before = repo_snapshot()

    restore_paths = [item["path"] for item in records if item["baseline"] == "tracked"]
    delete_paths = [item["path"] for item in records if item["baseline"] == "absent"]
    if rollback:
        print("ROLLBACK PREVIEW")
        print(f"Recovery checkpoint: {checkpoint['id']} ({recovery_ref})")
        print("Restore paths: " + (", ".join(restore_paths) if restore_paths else "(none)"))
        print("Delete paths: " + (", ".join(delete_paths) if delete_paths else "(none)"))
        if str(getattr(args, "confirm", "") or "") != "ROLLBACK":
            print("No files changed. Re-run with --confirm ROLLBACK to execute this exact rollback.")
            return 0
        for record in records:
            if not retirement_fingerprint_matches(record["before"]):
                raise RuntimeError(f"retire-plan rollback path changed after preview evidence: {record['path']}")
        for record in records:
            record["after"] = _restore_attributed_retirement_path(recovery_ref, record)
            record["restoration"] = {
                "disposition": "restored",
                "action": "checkout" if record["baseline"] == "tracked" else "delete",
                "checkpoint": checkpoint["id"],
            }
        disposition, operations = "ROLLED_BACK", {"restore": restore_paths, "delete": delete_paths, "preserved": []}
    else:
        # Carry-forward remains non-mutating.  Its records are preservation
        # inventory only and cannot be consumed as native rollback authority.
        disposition, operations = "RETIRED_WITH_CARRY_FORWARD", {"restore": [], "delete": [], "preserved": [item["path"] for item in records]}
    after = repo_snapshot()
    if carry_forward and after != before:
        raise RuntimeError("carry-forward changed the worktree; retirement refused")
    manifest = {"schema": RETIREMENT_MANIFEST_SCHEMA, "id": retirement_record_id(), "created_at": utc_now(), "plan_hash": expected, "status_before": status, "reason": reason[:1200], "disposition": disposition, "checkpoint": checkpoint["id"], "step": old_step, "step_count": len(steps), "loop_count": old_loops, "paths": records, "operations": operations, "repository_before": before, "repository_after": after, "planning_context": retirement_planning_context(state)}
    manifest_path = write_retirement_manifest(manifest)
    retirement = {"plan_hash": expected, "status_before": status, "step": old_step, "step_count": len(steps), "loop_count": old_loops, "reason": reason[:1200], "retired_at": manifest["created_at"], "disposition": disposition, "record_id": manifest["id"], "checkpoint": checkpoint["id"], "manifest_sha256": file_hash(manifest_path)}

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
        disposition,
        summary=reason,
        files=[item["path"] for item in records],
        next_action=f"python3 scripts/ralph.py propose --from-retirement {manifest['id']}" if carry_forward else "python3 scripts/ralph.py propose --goal '<next objective>'",
    )

    live_write(
        f"plan={expected} {disposition} record={manifest['id']} at step={old_step}/{len(steps)}; returning controller to IDLE",
        disposition,
    )

    state.update({
        "status": "IDLE",
        "plan_hash": None,
        "plan": None,
        "current_step": 1,
        "failure_attempts": {},
        "active_failure": None,
        "last_failure": None,
        "last_result": "RETIRED" if legacy_invocation else disposition,
        "block_reason": None,
    })
    clear_self_hosting_context(state)
    state.pop("proposal_previous_state", None)

    PLAN.unlink(missing_ok=True)
    save_state(state)

    print(
        f"{disposition} plan={expected} record={manifest['id']} artifact={manifest_path.relative_to(ROOT)} step={old_step}/{len(steps)} loops={old_loops}; state=IDLE\n"
        "Next: python3 scripts/ralph.py propose --goal '<next objective>'"
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
    clear_self_hosting_context(state)
    state["status"] = "APPROVED"
    state["block_reason"] = None
    save_state(state)
    plan_control_event(
        state,
        "human_steer",
        f"human steering recorded for {expected_gate}",
        step=step_no,
        gate_id=expected_gate,
        allowed_new_tests=len(allowed_new_tests),
    )

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
    plan_control_event(
        state,
        "self_hosting_grant",
        f"self-hosting authority granted for {expected_gate}",
        step=step_no,
        gate_id=expected_gate,
        path_count=len(requested),
    )
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
    if state.get("retirement_record_id"):
        reconciliation_snapshot(state)
    clear_self_hosting_context(state)
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

    clear_self_hosting_context(state)
    state["last_result"] = "HUMAN_CONFIRMED"
    state["block_reason"] = None
    state["current_step"] = int(state["current_step"]) + 1
    state["status"] = "APPROVED"
    save_state(state)
    plan_control_event(
        state,
        "human_gate_resolution",
        f"human gate resolved {expected_gate}",
        step=int(step.get("id") or 0),
        gate_id=expected_gate,
    )
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


def cmd_models(args: argparse.Namespace) -> int:
    catalog = query_codex_models()
    if getattr(args, "json", False):
        print(json.dumps(catalog, indent=2, sort_keys=True))
    else:
        selected = catalog.get("selected") or catalog.get("configured_default") or "codex-default"
        print(f"selected={selected}")
        for item in catalog.get("models") or []:
            marker = "*" if str(item.get("id")) == str(selected) else " "
            print(f"{marker} {item.get('id')} — {item.get('display_name')}")
    return 0


def _model_supported_efforts(catalog: dict, model_name: str | None) -> list[str]:
    if not model_name:
        return []
    for item in catalog.get("models") or []:
        if str(item.get("id") or "") == str(model_name):
            return [str(value).strip().lower() for value in item.get("reasoning_efforts") or [] if str(value).strip()]
    return []


def cmd_model_policy(args: argparse.Namespace) -> int:
    operation = str(getattr(args, "model_action", "show") or "show")
    if operation == "show":
        policy = model_policy.load_policy(ROOT)
    elif operation == "set":
        requested = str(getattr(args, "model", "") or "").strip()
        if not requested:
            raise RuntimeError("model-policy set requires --model")
        catalog = query_codex_models()
        available = {str(item.get("id") or "") for item in catalog.get("models") or []}
        if requested not in available:
            raise RuntimeError(f"model {requested!r} is not in the current authenticated Codex model catalog")
        current = model_policy.load_policy(ROOT)
        current_effort = str(current.get("reasoning_effort") or "").strip().lower() or None
        supported = _model_supported_efforts(catalog, requested)
        if current_effort and current_effort not in supported:
            policy = model_policy.save_policy(ROOT, requested, reasoning_effort=None)
            live_write(
                f"model policy updated revision={policy['revision']} model={requested}; "
                f"effort override {current_effort} cleared because the model does not support it",
                "MODEL",
            )
        else:
            policy = model_policy.save_policy(ROOT, requested)
            live_write(f"model policy updated revision={policy['revision']} model={requested}", "MODEL")
    elif operation == "reset":
        policy = model_policy.save_policy(ROOT, None)
        live_write(f"model policy reset to Codex configured default revision={policy['revision']}", "MODEL")
    elif operation == "set-effort":
        requested_effort = str(getattr(args, "effort", "") or "").strip().lower()
        if not requested_effort:
            raise RuntimeError("model-policy set-effort requires --effort")
        catalog = query_codex_models()
        effective_model = selected_codex_model()
        if not effective_model:
            raise RuntimeError("cannot set reasoning effort because no effective Codex model is available")
        supported = _model_supported_efforts(catalog, effective_model)
        if not supported:
            raise RuntimeError(
                f"model {effective_model!r} advertises no selectable reasoning efforts in the authenticated Codex catalog"
            )
        if requested_effort not in supported:
            raise RuntimeError(
                f"effort {requested_effort!r} is not supported by model {effective_model!r}; "
                f"supported={','.join(supported)}"
            )
        policy = model_policy.save_policy(ROOT, reasoning_effort=requested_effort)
        live_write(
            f"model effort policy updated revision={policy['revision']} effort={requested_effort}",
            "MODEL",
        )
    elif operation == "reset-effort":
        policy = model_policy.save_policy(ROOT, reasoning_effort=None)
        live_write(
            f"model effort policy reset to Codex configured default revision={policy['revision']}",
            "MODEL",
        )
    else:
        raise RuntimeError(f"unsupported model-policy action {operation}")
    effective = policy.get("model") or configured_codex_model()
    effective_effort = policy.get("reasoning_effort") or configured_codex_effort()
    payload = {**policy, "effective_model": effective, "effective_reasoning_effort": effective_effort}
    if getattr(args, "json", False):
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(
            f"model={policy.get('model') or 'codex-default'} effective={effective or '-'} "
            f"effort={policy.get('reasoning_effort') or 'codex-default'} "
            f"effective_effort={effective_effort or '-'} revision={policy['revision']}"
        )
    return 0


def cmd_redeem_reset(args: argparse.Namespace) -> int:
    if str(getattr(args, "confirm", "") or "") != "REDEEM":
        raise RuntimeError("redeem-reset requires --confirm REDEEM")
    credit_id = str(getattr(args, "credit_id", "") or "").strip() or None
    result = consume_codex_reset_credit(credit_id)
    outcome = str(result.get("outcome") or "unknown")
    live_write(f"banked reset redemption outcome={outcome}", "USAGE")
    if getattr(args, "json", False):
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"BANKED_RESET outcome={outcome}")
    return 0 if outcome in {"reset", "alreadyRedeemed", "nothingToReset", "noCredit"} else 2


def cmd_usage_reset_stats(args: argparse.Namespace) -> int:
    if str(getattr(args, "confirm", "") or "") != "RESET":
        raise RuntimeError("usage-reset-stats requires --confirm RESET")
    marker = reset_usage_statistics()
    live_write(f"local token statistics baseline reset at {marker['reset_at']}; provider quota untouched", "USAGE")
    if getattr(args, "json", False):
        print(json.dumps(marker, indent=2, sort_keys=True))
    else:
        print(f"USAGE_STATS_RESET at={marker['reset_at']} provider_quota=UNCHANGED")
    return 0


def cmd_status(_: argparse.Namespace) -> int:
    init_files()
    state = load_state()
    policy = efficiency_policy.load_policy(ROOT)
    total = len((state.get("plan") or {}).get("steps") or [])
    efficiency = state.get("last_efficiency") if isinstance(state.get("last_efficiency"), dict) else {}
    usage = state.get("codex_usage") if isinstance(state.get("codex_usage"), dict) else {}
    guard, _ = codex_usage_guard(usage, reserve_percent=float(policy["reserve_percent"]), admitted=usage_admission_valid(state)) if usage else ("-", [])
    windows = usage.get("windows") if isinstance(usage.get("windows"), list) else []
    remaining = min((float(w.get("remaining_percent", 100.0)) for w in windows), default=None)
    quota = f"{guard}:{remaining:.1f}%min" if remaining is not None else guard
    gate = gate_id_for_state(state) if state.get("status") == "BLOCKED_HUMAN" else "-"
    print(f"status={state.get('status')} plan={state.get('plan_hash') or '-'} step={state.get('current_step')}/{total or '-'} loops={state.get('loop_count')} gate={gate} block={state.get('block_reason') or '-'} efficiency={efficiency.get('status') or '-'} mode={policy['mode']} reserve={float(policy['reserve_percent']):.1f}% quota={quota}")
    return 0


def _policy_arg_updates(args: argparse.Namespace) -> dict:
    updates = {}
    mapping = {
        "mode": "mode",
        "reserve_percent": "reserve_percent",
        "strict_prompt_command_budget": "strict_prompt_command_budget",
        "strict_max_commands": "strict_max_commands",
        "strict_max_reported_files": "strict_max_reported_files",
        "strict_max_cumulative_input": "strict_max_cumulative_input",
        "strict_max_noncached_input": "strict_max_noncached_input",
        "normal_prompt_command_budget": "normal_prompt_command_budget",
        "normal_max_commands": "normal_max_commands",
        "normal_max_reported_files": "normal_max_reported_files",
        "normal_max_cumulative_input": "normal_max_cumulative_input",
        "normal_max_noncached_input": "normal_max_noncached_input",
        "relaxed_prompt_command_budget": "relaxed_prompt_command_budget",
        "relaxed_max_commands": "relaxed_max_commands",
        "relaxed_max_reported_files": "relaxed_max_reported_files",
        "relaxed_max_cumulative_input": "relaxed_max_cumulative_input",
        "relaxed_max_noncached_input": "relaxed_max_noncached_input",
        "runaway_max_commands": "runaway_max_commands",
        "runaway_max_reported_files": "runaway_max_reported_files",
        "runaway_max_cumulative_input": "runaway_max_cumulative_input",
        "runaway_max_noncached_input": "runaway_max_noncached_input",
    }
    for attr, key in mapping.items():
        value = getattr(args, attr, None)
        if value is not None:
            updates[key] = value
    return updates


def cmd_efficiency_policy(args: argparse.Namespace) -> int:
    init_files()
    operation = str(getattr(args, "policy_action", "show") or "show")
    if operation == "show":
        policy = efficiency_policy.load_policy(ROOT)
    elif operation == "set":
        updates = _policy_arg_updates(args)
        if not updates:
            raise RuntimeError("efficiency-policy set requires at least one setting")
        policy = efficiency_policy.save_policy(ROOT, updates)
        live_write(f"efficiency policy updated revision={policy['revision']} mode={policy['mode']} reserve={float(policy['reserve_percent']):.1f}%", "EFFICIENCY")
    elif operation == "reset":
        policy = efficiency_policy.save_policy(ROOT, {}, replace=True)
        live_write(f"efficiency policy restored to defaults revision={policy['revision']}", "EFFICIENCY")
    elif operation == "reset-mode":
        policy = efficiency_policy.save_policy(ROOT, {"mode": "NORMAL"})
        live_write(f"efficiency mode reset to NORMAL revision={policy['revision']}", "EFFICIENCY")
    else:
        raise RuntimeError(f"unsupported efficiency-policy action {operation}")
    if getattr(args, "json", False):
        print(json.dumps(policy, indent=2, sort_keys=True))
    else:
        print(f"mode={policy['mode']} reserve={float(policy['reserve_percent']):.1f}% revision={policy['revision']} updated={policy.get('updated_at') or '-'}")
    return 0


def _write_terminal_completion_report(state: dict, gates: list[str]) -> dict | None:
    """Best-effort report emission after terminal qualification has persisted state."""
    try:
        return build_completion_report(state, gates)
    except Exception as exc:
        qualification = state.get("final_qualification") if isinstance(state.get("final_qualification"), dict) else {}
        qualification["report_error"] = str(exc)[:2000]
        state["final_qualification"] = qualification
        save_state(state)
        live_write(f"completion report generation failed after terminal state was persisted: {exc}", "FAIL")
        return None


def _block_terminal_qualification(
    state: dict,
    *,
    stage: str,
    error: str,
    gates: Iterable[str] = (),
    durations: dict[str, float] | None = None,
    output: str = "",
) -> int:
    """Persist an exact terminal qualification refusal instead of escaping N+1/N."""
    gate_list = list(gates)
    detail = " ".join(str(error or "terminal qualification refused").split())[:6000]
    state["final_qualification"] = {
        "state": "BLOCKED",
        "stage": stage,
        "error": detail,
        "gates": gate_list,
        "durations": dict(durations or {}),
        "output": str(output or "")[-6000:],
        "completed_at": utc_now(),
        "delta_fingerprint": None,
    }
    state["status"] = "BLOCKED_HUMAN"
    state["block_reason"] = f"final qualification {stage} blocked after all approved steps completed: {detail}"
    save_state(state)
    report = _write_terminal_completion_report(state, gate_list)
    report_note = f"; report={report['markdown_path']}" if report else ""
    append_journal(
        int(state.get("loop_count") or 0),
        len((state.get("plan") or {}).get("steps") or []),
        "final-qualification",
        "BLOCKED",
        summary=state["block_reason"],
        gates=gate_list,
        next_action="correct the exact provenance/qualification block, then resume terminal finalization",
    )
    live_write(state["block_reason"] + report_note, "FAIL")
    print(state["block_reason"])
    if report:
        print(f"Report: {report['markdown_path']}")
    return 2


def finalize_completed_plan(state: dict) -> int:
    """Run terminal qualification once all approved steps have been consumed."""
    try:
        passed, final_gates, final_durations, final_output = run_final_qualification(state)
    except RuntimeError as exc:
        return _block_terminal_qualification(state, stage="qualification-guard", error=str(exc))

    provenance = None
    fingerprint = None
    plan = state.get("plan") if isinstance(state.get("plan"), dict) else {}
    repository_authority = str(plan.get(REPOSITORY_AUTHORITY_FIELD) or "")
    if passed:
        try:
            if repository_authority == "read-only":
                provenance = verified_read_only_completion(
                    state, "READ_ONLY_COMPLETE admission",
                )
            else:
                provenance = strict_native_provenance(
                    state, "READY_TO_COMMIT admission", require_current_delta=True, require_write=True,
                )
            fingerprint = str(provenance["current_sha256"])
        except RuntimeError as exc:
            return _block_terminal_qualification(
                state,
                stage="delta-binding",
                error=str(exc),
                gates=final_gates,
                durations=final_durations,
                output=final_output,
            )

    state["final_qualification"] = {
        "state": "PASS" if passed else "FAIL",
        "gates": final_gates,
        "durations": final_durations,
        "output": final_output[-6000:],
        "completed_at": utc_now(),
        "delta_fingerprint": fingerprint,
        "native_provenance_sha256": provenance.get("binding_sha256") if provenance else None,
        "completion_summary": {
            "delta_fingerprint": fingerprint,
            "native_provenance_sha256": provenance.get("binding_sha256"),
            "recorded_plan_paths": list(provenance.get("new_plan_paths") or []),
        } if provenance else None,
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
        report = _write_terminal_completion_report(state, final_gates)
        append_journal(
            state["loop_count"], len(state["plan"]["steps"]), "final-qualification", "FAIL",
            summary=state["block_reason"], gates=final_gates,
            next_action="human review final qualification output",
        )
        live_write(
            state["block_reason"] + (f"; report={report['markdown_path']}" if report else ""),
            "FAIL",
        )
        if final_output:
            print(final_output[-6000:])
        if report:
            print(f"Report: {report['markdown_path']}")
        return 2

    final_paths = list(provenance.get("new_plan_paths") or [])
    final_entries = change_entries(final_paths)
    state["completion_changes"] = {
        "entries": final_entries,
        "files": len(final_entries),
        "added": sum(int(item.get("added") or 0) for item in final_entries),
        "removed": sum(int(item.get("removed") or 0) for item in final_entries),
    }
    if repository_authority == "read-only":
        state["status"] = "READ_ONLY_COMPLETE"
        save_state(state)
        report = build_completion_report(state, final_gates)
        with JOURNAL.open("a", encoding="utf-8") as handle:
            handle.write(
                f"## Read-only plan complete — {utc_now()}\n\n"
                f"- Plan: `{state['plan_hash']}`\n"
                f"- Loops: {state['loop_count']}\n"
                f"- Steps: {len(state['plan']['steps'])}\n"
                "- Final qualification: PASS\n"
                "- Status: READ_ONLY_COMPLETE\n"
                "- Repository delta: zero\n"
                "- Operation attribution: zero\n"
                "- Plan ownership: zero\n"
                f"- Completion report: `{report['markdown_path']}`\n"
                f"- Recovery checkpoint: `{state.get('recovery_checkpoint')}`\n"
                f"- Native provenance: `{provenance['binding_sha256']}`\n"
                "- Next action: none; commit/push/reconciliation are prohibited\n\n"
            )
        live_write(
            f"read-only plan complete · final qualification PASS · provenance={provenance['binding_sha256'][:12]} "
            f"· report={report['markdown_path']} · READ_ONLY_COMPLETE",
            "COMPLETE",
        )
        print(tui.completion_card(report))
        print("READ_ONLY_COMPLETE: no commit or push action is required or permitted.")
        return 0

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
            f"- Native provenance: `{provenance['binding_sha256']}`\n"
            f"- Next action: python3 scripts/ralph.py finalize {state['plan_hash']}\n\n"
        )
    live_write(
        f"plan complete · final qualification PASS · provenance={provenance['binding_sha256'][:12]} "
        f"· report={report['markdown_path']} · READY_TO_COMMIT",
        "READY",
    )
    print(tui.completion_card(report))
    print(f"Next: python3 scripts/ralph.py finalize {state['plan_hash']}")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    tui.configure(getattr(args, "color", "auto"))
    init_files()
    state = load_state()
    requested_mode = getattr(args, "efficiency_mode", None)
    if requested_mode is not None:
        policy = efficiency_policy.save_policy(ROOT, {"mode": _efficiency_mode(requested_mode)})
    else:
        policy = efficiency_policy.load_policy(ROOT)
    state["efficiency_mode"] = str(policy["mode"])
    save_state(state)
    if state.get("status") not in {"APPROVED", "RUNNING", "PAUSED_USAGE_LIMIT"}:
        raise RuntimeError(f"run requires APPROVED/RUNNING/PAUSED_USAGE_LIMIT status, found {state.get('status')}")
    try:
        validate_complete_plan(state["plan"], state.get("plan_hash"))
        sandbox = sandbox_for_approved_plan(state["plan"], state.get("plan_hash"))
    except (TypeError, ValueError) as exc:
        block(state, f"approved plan repository authority is invalid: {exc}")
        raise RuntimeError("approved plan repository authority is invalid; blocked for human review") from exc
    try:
        verify_approval_execution_evidence(state)
    except RuntimeError as exc:
        block(state, str(exc))
        raise RuntimeError(f"{exc}; blocked for human review") from exc
    if state.get("retirement_record_id") and not refresh_replacement_dirty_inventory(state):
        block(state, "replacement dirty-path inventory changed after approval; refreshed dispositions require human review")
        raise RuntimeError("replacement dirty-path inventory changed after approval; execution refused")
    unresolved = unresolved_replacement_dispositions(state) if state.get("retirement_record_id") else []
    if unresolved:
        block(state, "replacement dirty-path inventory has unresolved dispositions: " + ", ".join(unresolved))
        raise RuntimeError("replacement dirty-path inventory requires explicit dispositions before execution")
    loops_this_run = 0
    while state["current_step"] <= len(state["plan"]["steps"]):
        policy = efficiency_policy.load_policy(ROOT)
        if state.get("efficiency_mode") != policy["mode"]:
            state["efficiency_mode"] = str(policy["mode"])
            save_state(state)
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
            changed_files=len(validated_plan_paths(state)),
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
            result = run_codex(step_prompt(state, step, active_fp, repair_no), RESULT_SCHEMA, sandbox, context=f"LOOP {loop_no:04d} STEP {step['id']} {'REPAIR' if active_fp else 'IMPLEMENT'}")
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
                # The restoration guard is not a substitute for the required
                # checkpoint comparison; record it even on this refusal path.
                verification = record_post_turn_repository_verification(
                    state, step, sandbox, files, loop=loop_no,
                )
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
                if verification["state"] == "REFUSED":
                    reason += f"; post-turn checkpoint verification: {verification['error']}"
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
            verification = record_post_turn_repository_verification(
                state, step, sandbox, files, loop=loop_no,
            )
            reason = "policy violation: " + "; ".join(filter(None, [f"protected paths {protected}" if protected else "", f"test paths {test_violations}" if test_violations else ""]))
            if verification["state"] == "REFUSED":
                reason += f"; post-turn checkpoint verification: {verification['error']}"
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

        # A fresh checkpoint comparison is required before *every* result
        # disposition.  It is intentionally after immediate restore guards so
        # their existing protective behavior remains intact, and before
        # continuation, controller gates, acceptance, progression, or terminal
        # readiness can consume the model result.
        verification = record_post_turn_repository_verification(
            state, step, sandbox, files, loop=loop_no,
        )
        if verification["state"] == "REFUSED":
            reason = str(verification["error"])
            append_journal(
                loop_no, step["id"], "post-turn-verification", "BLOCKED",
                summary=reason, files=files, repair=repair_no, ideas=result.get("ideas", []),
                next_action="human review checkpoint-relative repository mismatch",
                change_class=change_class, stats=loop_stats(loop_started, result, repair=repair_no),
            )
            live_write(f"loop={loop_no:04d} checkpoint verification refused: {reason}", "VERIFY")
            block(state, reason)
            return 2
        _remember_pending_step_paths(
            state, int(step["id"]),
            set(files) & set(verification.get("new_project_delta") or []),
        )
        try:
            attribution = verified_attribution_result(
                state, step, verification, files, loop=loop_no, phase=phase,
            )
        except RuntimeError as exc:
            reason = str(exc)
            append_journal(
                loop_no, step["id"], "verified-attribution", "BLOCKED",
                summary=reason, files=files, repair=repair_no, ideas=result.get("ideas", []),
                next_action="human review verified operation attribution",
                change_class=change_class, stats=loop_stats(loop_started, result, repair=repair_no),
            )
            block(state, reason)
            return 2
        # From this point onward, no acceptance-facing control may consume the
        # raw before/after path list.  It is evidence only; attribution is the
        # controller's verified and checkpoint-bound authority boundary.
        files = list(attribution["paths"])
        change_class = classify_changes(files)
        save_state(state)
        live_write(
            f"loop={loop_no:04d} checkpoint verification=PASS sandbox={sandbox} "
            f"delta={len(verification['new_project_delta'])}",
            "VERIFY",
        )

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
            policy = efficiency_policy.load_policy(ROOT)
            mode = _efficiency_mode(str(policy.get("mode") or "NORMAL"))
            state["efficiency_mode"] = mode
            runaway = runaway_findings(stats, policy=policy)
            efficiency = efficiency_findings(stats, mode=mode, policy=policy)
            next_action = "pause for runaway review" if runaway else ("pause for efficiency-policy review" if efficiency else "next approved step")
            live_write(f"loop={loop_no:04d} step={step['id']} PASS · class={change_class}", "PASS")
            append_journal(loop_no, step["id"], phase, "PASS", summary=result.get("summary", ""), files=files, gates=gates, repair=repair_no, ideas=result.get("ideas", []), next_action=next_action, change_class=change_class, stats=stats)
            state["last_result"] = "PASS"
            state["last_failure"] = None
            state["active_failure"] = None
            state["last_efficiency"] = {
                "status": "RUNAWAY" if runaway else ("WARN" if efficiency else "PASS"),
                "mode": mode,
                "findings": runaway or efficiency,
            }
            record_accepted_operations(state, attribution)
            remember_plan_files(state, files)
            update_context_after_pass(state, step, result, files)
            record_step_result(
                state, step, "PASS", summary=result.get("summary", ""), files=files,
                gates=gates, stats=stats, attribution=attribution,
            )
            _clear_pending_step_paths(state)
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
            clear_self_hosting_context(state)
            state["current_step"] += 1
            state["status"] = "APPROVED"
            save_state(state)
            if runaway:
                detail = "; ".join(runaway)
                live_write(f"qualified step completed but emergency runaway ceiling exceeded: {detail}; pausing before next model turn", "EFFICIENCY")
                print(f"PAUSED_RUNAWAY plan={state['plan_hash']} step={state['current_step']} loops={state['loop_count']} findings={detail}")
                return 0
            if efficiency:
                detail = "; ".join(efficiency)
                live_write(f"qualified step completed but {mode} efficiency policy exceeded: {detail}; pausing before next model turn", "EFFICIENCY")
                print(f"PAUSED_EFFICIENCY_POLICY mode={mode} plan={state['plan_hash']} step={state['current_step']} loops={state['loop_count']} findings={detail}")
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

    return finalize_completed_plan(state)



def cmd_recover_self_upgrade(args: argparse.Namespace) -> int:
    """Recover one active native plan after its controller attribution schema changed in-process.

    This is deliberately an explicit operator repair, not a compatibility path in
    normal execution. It reconstructs only evidence that can be proven from the
    active plan/checkpoint, accepted step results, exact self-hosting grants and
    current checkpoint-relative repository evidence.
    """
    init_files()
    state = load_state()
    expected = str(state.get("plan_hash") or "")
    if not expected or not secrets.compare_digest(str(args.plan_hash or ""), expected):
        raise RuntimeError("recover-self-upgrade hash does not match the active plan")
    if str(args.confirm or "") != "RECOVER":
        raise RuntimeError("recover-self-upgrade requires --confirm RECOVER")
    if state.get("status") not in {"APPROVED", "RUNNING", "BLOCKED_HUMAN"}:
        raise RuntimeError(f"recover-self-upgrade requires active approved/running/blocked plan, found {state.get('status')}")
    checkpoint_id = str(state.get("recovery_checkpoint") or "")
    if not checkpoint_id or str(args.checkpoint or "") != checkpoint_id:
        raise RuntimeError("recover-self-upgrade requires the exact active recovery checkpoint")
    validate_complete_plan(state["plan"], expected)
    verify_approval_execution_evidence(state)

    current_step = int(state.get("current_step") or 0)
    steps = list(((state.get("plan") or {}).get("steps") or []))
    if not (1 <= current_step <= len(steps)):
        raise RuntimeError("recover-self-upgrade cannot resolve current approved step")
    current_step_def = steps[current_step - 1]
    accepted = _accepted_step_results_by_id(state)
    if not accepted or max(accepted) >= current_step:
        raise RuntimeError("recover-self-upgrade requires completed accepted steps strictly before the current step")

    pending = sorted({
        _normalize_repo_path(str(path))
        for path in list(args.pending_path or [])
        if _normalize_repo_path(str(path))
    })
    repository = recompute_repository_against_approval_checkpoint(state)
    if repository.get("changed_approval_residue"):
        raise RuntimeError(f"recover-self-upgrade refuses changed approval residue: {repository['changed_approval_residue']}")
    current_delta = {
        _normalize_repo_path(str(path))
        for path in repository.get("new_project_delta") or []
        if _normalize_repo_path(str(path))
    }
    if not set(pending).issubset(current_delta):
        raise RuntimeError("recover-self-upgrade pending paths must be current checkpoint-relative delta")
    for path in pending:
        if is_protected_path(path) or _is_runtime_authority_path(path) or path in approval_baseline_residue_paths(state):
            raise RuntimeError(f"recover-self-upgrade refuses pending protected/runtime/residue path: {path}")
        if path == "tests" or path.startswith("tests/"):
            policy = str(current_step_def.get("test_change_policy") or "none")
            baseline = plan_baseline_path_kind(state, path)
            if policy == "none" or (policy == "add-only" and baseline != "absent"):
                raise RuntimeError(f"recover-self-upgrade pending test path violates current step policy {policy}: {path}")
    pending_tooling = [path for path in pending if is_tooling_path(path)]
    if pending_tooling:
        allowed, reason = self_hosting_grant_allows(state, current_step, pending_tooling)
        if not allowed:
            raise RuntimeError(f"recover-self-upgrade pending tooling lacks current exact authority: {reason}")

    source_records = state.get("operation_attributions")
    if not isinstance(source_records, list):
        raise RuntimeError("recover-self-upgrade requires an operation attribution list")
    repaired: list[dict] = []
    foreign_removed = 0
    converted = 0
    for raw in source_records:
        if not isinstance(raw, dict):
            raise RuntimeError("recover-self-upgrade found malformed operation attribution")
        if raw.get("plan_hash") != expected:
            foreign_removed += 1
            continue
        schema = raw.get("schema")
        if schema == OPERATION_ATTRIBUTION_SCHEMA:
            repaired.append(_json_copy(raw))
            continue
        if schema != "zen_ralph_operation_attribution_v1":
            raise RuntimeError(f"recover-self-upgrade refuses unsupported attribution schema: {schema}")
        if raw.get("checkpoint") != checkpoint_id:
            raise RuntimeError("recover-self-upgrade refuses current-plan v1 attribution from another checkpoint")
        origin = _legacy_v1_origin_step(state, raw)
        if int(origin["id"]) not in accepted:
            raise RuntimeError("recover-self-upgrade refuses v1 attribution from an unaccepted step")
        path = _normalize_repo_path(str(raw.get("path") or ""))
        fingerprint = raw.get("current_fingerprint")
        if not path or not isinstance(fingerprint, dict):
            raise RuntimeError("recover-self-upgrade found incomplete v1 attribution")
        native = _native_recovery_record(
            state, origin, path, fingerprint, loop=int(raw.get("loop") or 0),
            source="accepted-v1-operation",
        )
        if native["baseline_kind"] != raw.get("baseline_kind") or native["operation"] != raw.get("operation"):
            raise RuntimeError(f"recover-self-upgrade v1 operation no longer matches checkpoint semantics: {path}")
        repaired.append(native)
        converted += 1

    prospective = dict(state)
    prospective["operation_attributions"] = repaired
    # Validate every retained/converted record before using it as recovery evidence.
    _validated_operation_records(prospective)
    latest = _latest_operation_records_by_path(prospective)
    synthetic = 0
    recovery_loop = int(state.get("loop_count") or 0)
    for path in sorted(current_delta - set(pending)):
        fingerprint = retirement_path_fingerprint(path)
        existing = latest.get(path)
        if existing is not None and existing.get("current_fingerprint") == fingerprint:
            continue
        origin, accepted_loop = _accepted_origin_for_recovery(state, path, accepted)
        record = _native_recovery_record(
            state, origin, path, fingerprint, loop=recovery_loop,
            source=f"accepted-step-current-delta:accepted-loop={accepted_loop}",
        )
        repaired.append(record)
        prospective["operation_attributions"] = repaired
        _validated_operation_records(prospective)
        latest = _latest_operation_records_by_path(prospective)
        synthetic += 1

    state["operation_attributions"] = repaired
    validated = _validated_operation_records(state)
    state["plan_changed_files"] = sorted({str(item["path"]) for item in validated})
    state["plan_owned_files"] = sorted({str(item["path"]) for item in validated if item["baseline_kind"] == "absent"})
    if pending:
        state["pending_step_delta_paths"] = {"step": current_step, "paths": pending, "updated_at": utc_now()}
    else:
        _clear_pending_step_paths(state)
    state["status"] = "APPROVED"
    state["block_reason"] = None
    state["self_upgrade_recovery"] = {
        "schema": "zen_ralph_self_upgrade_recovery_v1",
        "plan_hash": expected,
        "checkpoint": checkpoint_id,
        "step": current_step,
        "foreign_records_removed": foreign_removed,
        "v1_records_converted": converted,
        "current_records_synthesized": synthetic,
        "pending_current_step_paths": pending,
        "recovered_at": utc_now(),
    }
    save_state(state)
    plan_control_event(
        state, "self_upgrade_recovery",
        f"controller self-upgrade attribution recovered at step {current_step}",
        step=current_step, foreign_removed=foreign_removed, converted=converted, synthetic=synthetic,
        pending=len(pending),
    )
    append_journal(
        int(state.get("loop_count") or 0), current_step, "operator-self-upgrade-recovery", "RECOVERED",
        summary=(
            f"Recovered active native attribution after controller schema transition; "
            f"removed_foreign={foreign_removed} converted_v1={converted} synthesized={synthetic} "
            f"pending_current_step={pending}"
        ),
        files=sorted(current_delta),
        next_action="resume the same approved step under the current controller",
    )
    print(
        f"SELF_UPGRADE_RECOVERED plan={expected} checkpoint={checkpoint_id} step={current_step} "
        f"removed_foreign={foreign_removed} converted_v1={converted} synthesized={synthetic} "
        f"pending={','.join(pending) if pending else '-'} status=APPROVED"
    )
    return 0


def cmd_recover_validation_block(args: argparse.Namespace) -> int:
    """Human-triggered controller qualification for a validation-only historical block."""
    init_files()
    state = load_state()
    if state.get("status") != "BLOCKED_HUMAN":
        raise RuntimeError("recover-validation-block requires BLOCKED_HUMAN status")
    if args.plan_hash != state.get("plan_hash"):
        raise RuntimeError("recovery hash does not match the approved plan")
    if state.get("retirement_record_id"):
        reconciliation_snapshot(state)
    if not is_recoverable_validation_block(state.get("block_reason") or ""):
        raise RuntimeError("current block is not classified as a recoverable validation-only block")
    try:
        validate_complete_plan(state["plan"], state.get("plan_hash"))
        verify_approval_execution_evidence(state)
    except (TypeError, ValueError, RuntimeError) as exc:
        block(state, str(exc))
        raise RuntimeError(f"{exc}; recovery blocked for human review") from exc

    step = state["plan"]["steps"][state["current_step"] - 1]
    files = git_changed_paths()
    if not files:
        raise RuntimeError("no working-tree changes found to qualify")
    validate_recovery_paths(files, step)
    verification = record_post_turn_repository_verification(
        state, step, "workspace-write", files, loop=int(state.get("loop_count") or 0),
    )
    if verification["state"] == "REFUSED":
        reason = str(verification["error"])
        block(state, reason)
        raise RuntimeError(f"recovery qualification refused: {reason}")
    attribution = verified_attribution_result(
        state, step, verification, files,
        loop=int(state.get("loop_count") or 0), phase="human-qualification",
    )
    files = list(attribution["paths"])
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
        record_accepted_operations(state, attribution)
        update_context_after_pass(state, step, result, files)
        record_step_result(
            state, step, "PASS", summary=result["summary"], files=files, gates=gates,
            stats=stats, attribution=attribution,
        )
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
    propose.add_argument("--goal")
    propose.add_argument("--from-retirement", metavar="RT_ID")
    # Runtime admission in ``cmd_propose`` owns this requirement.  Keeping the
    # parser permissive lets callers inspect proposal-only options (such as
    # planning bounds) without implying that a proposal can be admitted
    # unbound.
    propose.add_argument("--repository-authority", choices=sorted(REPOSITORY_AUTHORITIES))
    propose.add_argument("--min-steps", type=int, default=PLAN_MIN_STEPS_DEFAULT)
    propose.add_argument("--max-steps", type=int, default=PLAN_MAX_STEPS_DEFAULT)
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
    disposition = retire.add_mutually_exclusive_group(required=True)
    disposition.add_argument("--rollback", action="store_true")
    disposition.add_argument("--carry-forward", action="store_true")
    retire.add_argument("--confirm", default=None, help="must be ROLLBACK to execute a rollback")
    retire.add_argument(
        "--reconcile-restored",
        action="store_true",
        help="permit no-op rollback only when every recorded plan path already matches its approval checkpoint",
    )
    retire.set_defaults(func=cmd_retire_plan)
    inspect_carry = sub.add_parser("inspect-carry-forward", help="inspect durable carry-forward reconciliation dispositions")
    inspect_carry.add_argument("plan_hash")
    inspect_carry.set_defaults(func=cmd_inspect_carry_forward)
    adopt_carry = sub.add_parser("adopt-carry-forward", help="adopt unchanged retirement content into the approved plan")
    adopt_carry.add_argument("plan_hash")
    adopt_carry.add_argument("--path", required=True)
    adopt_carry.add_argument("--step", required=True, type=int)
    adopt_carry.add_argument("--ownership-basis", required=True)
    adopt_carry.add_argument("--confirm", required=True)
    adopt_carry.set_defaults(func=cmd_adopt_carry_forward)
    leave_carry = sub.add_parser("leave-carry-forward-outside", help="leave a carry-forward candidate outside plan scope")
    leave_carry.add_argument("plan_hash")
    leave_carry.add_argument("--path", required=True)
    leave_carry.add_argument("--step", required=True, type=int, help="current approved step claiming this disposition")
    leave_carry.add_argument("--reason", required=True)
    leave_carry.set_defaults(func=cmd_leave_carry_forward_outside)
    reject_carry = sub.add_parser("reject-carry-forward", help="reject a candidate pending external reconciliation")
    reject_carry.add_argument("plan_hash")
    reject_carry.add_argument("--path", required=True)
    reject_carry.add_argument("--step", required=True, type=int, help="current approved step claiming this disposition")
    reject_carry.add_argument("--reason", required=True)
    reject_carry.set_defaults(func=cmd_reject_carry_forward)
    run = sub.add_parser("run")
    run.add_argument("--max-loops", type=int, default=DEFAULT_MAX_LOOPS)
    run.add_argument("--efficiency-mode", choices=tuple(mode.lower() for mode in EFFICIENCY_MODES), default=None, help="efficiency governor for this plan: strict, normal, relaxed, or off; persisted for resumed runs")
    run.add_argument("--wait-for-limits", action=argparse.BooleanOptionalAction, default=True, help="wait and automatically resume after Codex usage limits recover")
    run.add_argument("--usage-poll-seconds", type=int, default=USAGE_POLL_SECONDS, help="maximum zero-model usage recheck interval while paused")
    run.add_argument("--color", choices=("auto", "always", "never"), default="auto", help="terminal colour mode")
    run.set_defaults(func=cmd_run)

    efficiency = sub.add_parser("efficiency-policy", help="show or update the live RALPH efficiency/resource policy")
    efficiency_sub = efficiency.add_subparsers(dest="policy_action", required=True)
    efficiency_show = efficiency_sub.add_parser("show", help="show the effective live policy")
    efficiency_show.add_argument("--json", action="store_true")
    efficiency_show.set_defaults(func=cmd_efficiency_policy)
    efficiency_set = efficiency_sub.add_parser("set", help="atomically update live efficiency settings")
    efficiency_set.add_argument("--mode", choices=tuple(mode.lower() for mode in EFFICIENCY_MODES))
    efficiency_set.add_argument("--reserve-percent", type=float)
    for prefix in ("strict", "normal", "relaxed"):
        efficiency_set.add_argument(f"--{prefix}-prompt-command-budget", type=int)
        efficiency_set.add_argument(f"--{prefix}-max-commands", type=int)
        efficiency_set.add_argument(f"--{prefix}-max-reported-files", type=int)
        efficiency_set.add_argument(f"--{prefix}-max-cumulative-input", type=int)
        efficiency_set.add_argument(f"--{prefix}-max-noncached-input", type=int)
    efficiency_set.add_argument("--runaway-max-commands", type=int)
    efficiency_set.add_argument("--runaway-max-reported-files", type=int)
    efficiency_set.add_argument("--runaway-max-cumulative-input", type=int)
    efficiency_set.add_argument("--runaway-max-noncached-input", type=int)
    efficiency_set.add_argument("--json", action="store_true")
    efficiency_set.set_defaults(func=cmd_efficiency_policy)
    efficiency_reset = efficiency_sub.add_parser("reset", help="restore every efficiency/resource setting to defaults")
    efficiency_reset.add_argument("--json", action="store_true")
    efficiency_reset.set_defaults(func=cmd_efficiency_policy)
    efficiency_reset_mode = efficiency_sub.add_parser("reset-mode", help="reset only the efficiency mode to NORMAL")
    efficiency_reset_mode.add_argument("--json", action="store_true")
    efficiency_reset_mode.set_defaults(func=cmd_efficiency_policy)
    model = sub.add_parser("model-policy", help="show or update RALPH's project-local Codex model selection")
    model_sub = model.add_subparsers(dest="model_action", required=True)
    model_show = model_sub.add_parser("show", help="show the selected/effective model")
    model_show.add_argument("--json", action="store_true")
    model_show.set_defaults(func=cmd_model_policy)
    model_set = model_sub.add_parser("set", help="select one model from the current authenticated Codex catalog")
    model_set.add_argument("--model", required=True)
    model_set.add_argument("--json", action="store_true")
    model_set.set_defaults(func=cmd_model_policy)
    model_reset = model_sub.add_parser("reset", help="return to the user's configured Codex default model")
    model_reset.add_argument("--json", action="store_true")
    model_reset.set_defaults(func=cmd_model_policy)
    effort_set = model_sub.add_parser("set-effort", help="set project-local reasoning effort for subsequent Codex turns")
    effort_set.add_argument("--effort", required=True)
    effort_set.add_argument("--json", action="store_true")
    effort_set.set_defaults(func=cmd_model_policy)
    effort_reset = model_sub.add_parser("reset-effort", help="return to the user's configured Codex reasoning effort")
    effort_reset.add_argument("--json", action="store_true")
    effort_reset.set_defaults(func=cmd_model_policy)
    models = sub.add_parser("models", help="show the current authenticated Codex model catalog")
    models.add_argument("--json", action="store_true")
    models.set_defaults(func=cmd_models)
    redeem = sub.add_parser("redeem-reset", help="redeem one explicitly confirmed banked Codex reset")
    redeem.add_argument("--credit-id", default=None, help="opaque credit ID from the live app-server snapshot; omit to let Codex select")
    redeem.add_argument("--confirm", required=True, help="must be REDEEM")
    redeem.add_argument("--json", action="store_true")
    redeem.set_defaults(func=cmd_redeem_reset)
    usage_reset = sub.add_parser("usage-reset-stats", help="reset RALPH local token-stat display baseline only")
    usage_reset.add_argument("--confirm", required=True, help="must be RESET")
    usage_reset.add_argument("--json", action="store_true")
    usage_reset.set_defaults(func=cmd_usage_reset_stats)
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
    self_upgrade_recover = sub.add_parser(
        "recover-self-upgrade",
        help="operator-confirmed repair for an active plan stranded by a controller attribution-schema self-upgrade",
    )
    self_upgrade_recover.add_argument("plan_hash")
    self_upgrade_recover.add_argument("--checkpoint", required=True, help="exact active recovery checkpoint ID")
    self_upgrade_recover.add_argument(
        "--pending-path", action="append", default=[], metavar="PATH",
        help="exact current-step operator bootstrap path to leave pending rather than retroactively accepting; repeat as needed",
    )
    self_upgrade_recover.add_argument("--confirm", required=True, help="must be RECOVER")
    self_upgrade_recover.set_defaults(func=cmd_recover_self_upgrade)
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
    requalify = sub.add_parser("requalify", help="re-run final qualification and bind it to the exact current plan delta")
    requalify.add_argument("plan_hash")
    requalify.set_defaults(func=cmd_requalify)
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
    adopt_test = sub.add_parser("adopt-test-reconciliation", help="adopt only the controller-validated late test delta and require requalification")
    adopt_test.add_argument("plan_hash")
    adopt_test.add_argument("--path", required=True, help="must be the exact controller-approved test path")
    adopt_test.add_argument("--confirm", required=True, help="must be ADOPT")
    adopt_test.add_argument("--reason", required=True, help="operator reason retained in the immutable-style adoption record")
    adopt_test.set_defaults(func=cmd_adopt_test_reconciliation)
    usage = sub.add_parser("usage", help="show RALPH context/token usage and live Codex remaining limits")
    usage.add_argument("--details", action="store_true", help="include per-loop token usage")
    usage.add_argument("--json", action="store_true", help="emit machine-readable report")
    usage.add_argument("--no-save", action="store_true", help=argparse.SUPPRESS)
    usage.add_argument("--include-reset-details", action="store_true", help=argparse.SUPPRESS)
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


def _fail_closed_unhandled_run_exception(args: argparse.Namespace, exc: Exception) -> None:
    """Never leave durable RUNNING state behind after the run process exits."""
    if getattr(args, "command", None) != "run":
        return
    try:
        state = load_state()
    except Exception:
        return
    if state.get("status") != "RUNNING":
        return
    reason = f"controller runtime exception: {exc}"
    state["status"] = "BLOCKED_HUMAN"
    state["block_reason"] = reason[:2000]
    save_state(state)
    try:
        plan_control_event(
            state, "controller_exception",
            "run process failed closed instead of leaving stale RUNNING state",
            step=int(state.get("current_step") or 0),
        )
    except Exception:
        pass


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
        _fail_closed_unhandled_run_exception(args, exc)
        print(f"RALPH-Lite: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
