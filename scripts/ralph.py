#!/usr/bin/env python3
"""RALPH-Lite: a tiny, deterministic Codex development-loop supervisor.

Human approves a 5-10 step plan. Codex may then implement one step per loop.
The controller, not Codex, owns approval state, qualification gates, failure
budgets, loop journaling, and the ideas bucket.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
RALPH = ROOT / ".ralph"
STATE = RALPH / "state.json"
PLAN = RALPH / "plan.md"
IDEAS = RALPH / "ideas.md"
JOURNAL = RALPH / "journal.md"
POLICY = RALPH / "policy.md"
LIVE = RALPH / "live.log"

MAX_REPAIRS_PER_FAILURE = 3
DEFAULT_MAX_LOOPS = 40
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
    "tests/test_ralph_lite.py",
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
    },
    "required": ["summary", "ideas", "blockers", "needs_human"],
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


def init_files() -> None:
    RALPH.mkdir(parents=True, exist_ok=True)
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
    if not POLICY.exists():
        raise RuntimeError("missing tracked authority file .ralph/policy.md")


def append_journal(loop_no: int, step_no: int, phase: str, result: str, *, summary: str = "", files: Iterable[str] = (), gates: Iterable[str] = (), fingerprint: str | None = None, repair: int = 0, ideas: Iterable[str] = (), next_action: str = "", change_class: str = "control-event") -> None:
    lines = [
        f"## Loop {loop_no:04d} — {utc_now()}", "",
        f"- Plan step: {step_no}", f"- Phase: {phase}", f"- Result: {result}", f"- Change class: {change_class}", f"- Repair attempt: {repair}",
        f"- Failure fingerprint: `{fingerprint or '-'}`", f"- Files changed: {', '.join(files) if files else '-'}",
        f"- Gates: {'; '.join(gates) if gates else '-'}", f"- Summary: {summary or '-'}",
        f"- Ideas captured: {len(list(ideas))}", f"- Next action: {next_action or '-'}", "",
    ]
    with JOURNAL.open("a", encoding="utf-8") as handle:
        handle.write("\n".join(lines))


def live_write(message: str, category: str = "RALPH") -> None:
    """Write a concise operator-visible event to terminal and the local live trace."""
    RALPH.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().astimezone().strftime("%H:%M:%S")
    clean = " ".join(str(message).split())
    line = f"[{stamp}] {category:<8} {clean}"
    print(line, flush=True)
    with LIVE.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


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
        messages.append(("RUN", _clip(item.get("command", ""))))
    elif event_type == "item.completed":
        if item_type == "reasoning":
            messages.append(("THINK", _clip(item.get("text", ""), 800)))
        elif item_type == "command_execution":
            status = str(item.get("status") or "completed").upper()
            code = item.get("exit_code")
            suffix = f" exit={code}" if code is not None else ""
            messages.append(("CMD", f"{status}{suffix} · {_clip(item.get('command', ''))}"))
            if status == "FAILED" and item.get("aggregated_output"):
                messages.append(("OUTPUT", _clip(str(item["aggregated_output"])[-1200:], 800)))
        elif item_type == "file_change":
            changes = item.get("changes") if isinstance(item.get("changes"), list) else []
            rendered = []
            for change in changes:
                if isinstance(change, dict):
                    rendered.append(f"{change.get('kind', 'update')}:{change.get('path', '?')}")
            messages.append(("FILES", ", ".join(rendered) if rendered else "file change completed"))
        elif item_type == "error":
            messages.append(("WARN", _clip(item.get("message", "Codex item error"), 800)))
    elif event_type == "turn.completed":
        usage = event.get("usage") if isinstance(event.get("usage"), dict) else {}
        messages.append((
            "USAGE",
            "input={input} cached={cached} output={output} reasoning={reasoning}".format(
                input=usage.get("input_tokens", 0),
                cached=usage.get("cached_input_tokens", 0),
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
    paths = (
        STATE, PLAN, IDEAS, JOURNAL, POLICY,
        ROOT / ".gitignore", ROOT / "scripts" / "ralph.py",
        ROOT / "tests" / "test_ralph_lite.py", ROOT / "docs" / "RALPH-LITE.md",
    )
    return {path: path.read_bytes() if path.exists() else None for path in paths}


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


def test_policy_violation(before: dict[str, str], after: dict[str, str], policy: str) -> list[str]:
    changed = [p for p in changed_paths(before, after) if p == "tests" or p.startswith("tests/")]
    if policy == "modify":
        return []
    if policy == "none":
        return changed
    return [p for p in changed if p in before]  # add-only: existing tests may not change or disappear


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


def stream_codex_process(args: list[str]) -> tuple[int, str]:
    """Run Codex while rendering its JSONL event stream for the operator."""
    proc = subprocess.Popen(
        args, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1,
    )
    captured: list[str] = []
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
            for category, message in codex_event_messages(event):
                if message:
                    live_write(message, category)
    return proc.wait(), "".join(captured)


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


def run_codex(prompt: str, schema: dict, sandbox: str, *, context: str = "Codex") -> dict:
    if shutil.which("codex") is None:
        raise RuntimeError("codex CLI is not installed or not on PATH")
    with tempfile.TemporaryDirectory(prefix="ralph-lite-") as temp_dir:
        schema_path = Path(temp_dir) / "schema.json"
        output_path = Path(temp_dir) / "result.json"
        schema_path.write_text(json.dumps(schema), encoding="utf-8")
        command = [
            "codex", "exec", "--ephemeral", "--json", "--sandbox", sandbox,
            "--output-schema", str(schema_path), "-o", str(output_path), prompt,
        ]
        live_write(f"{context} · sandbox={sandbox}", "CODEX")
        returncode, output = stream_codex_process(command)
        if returncode != 0 and is_bwrap_bootstrap_failure(output):
            live_write("bubblewrap bootstrap blocked; retrying this invocation with legacy Landlock", "SANDBOX")
            fallback = [
                "codex", "--enable", "use_legacy_landlock", "exec",
                "--ephemeral", "--json", "--sandbox", sandbox,
                "--output-schema", str(schema_path), "-o", str(output_path), prompt,
            ]
            returncode, output = stream_codex_process(fallback)
        if returncode != 0:
            raise RuntimeError(f"codex exec failed ({returncode}):\n{output[-6000:]}")
        try:
            result = json.loads(output_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"codex returned invalid structured output: {exc}") from exc
        if isinstance(result, dict) and result.get("summary"):
            live_write(_clip(result["summary"], 800), "SUMMARY")
        return result


def qualification_gates() -> list[tuple[str, list[str]]]:
    py_files = sorted(str(p.relative_to(ROOT)) for base in (ROOT / "app", ROOT / "scripts") if base.exists() for p in base.glob("*.py"))
    return [
        ("python-compile", [sys.executable, "-m", "py_compile", *py_files]),
        ("unit-tests", [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"]),
        ("ux-validator", [sys.executable, "scripts/ux_validate.py"]),
    ]


def run_gates() -> tuple[bool, list[str], str | None, str]:
    gate_log: list[str] = []
    for name, command in qualification_gates():
        live_write(f"running {name}", "GATE")
        proc = run_process(command)
        outcome = "PASS" if proc.returncode == 0 else "FAIL"
        gate_log.append(f"{name}={outcome}")
        live_write(f"{name}={outcome}", "GATE")
        if proc.returncode != 0:
            fp = failure_fingerprint(name, proc.stdout, proc.returncode)
            live_write(f"{name} failure fingerprint={fp}", "FAIL")
            return False, gate_log, fp, proc.stdout[-12000:]
    return True, gate_log, None, ""


def plan_prompt(goal: str) -> str:
    return f"""You are planning work for ZEN Control under RALPH-Lite. Inspect the repository read-only.
Goal: {goal}
Return exactly 5-10 ordered, concrete implementation steps. Keep steps small enough to implement and qualify independently.
For each step choose test_change_policy: none, add-only, or modify. Prefer add-only; use modify only when modifying existing tests is genuinely required.
Do not execute or edit anything. Respect .ralph/policy.md. Put discovered nice-to-have work into later plan steps only if it directly serves the goal; otherwise it belongs in the ideas bucket during execution.
"""


def step_prompt(state: dict, step: dict, repair_fp: str | None, repair_no: int) -> str:
    repair_text = ""
    if repair_fp:
        repair_text = f"\nThis is repair attempt {repair_no} for failure fingerprint {repair_fp}. Fix the failure without weakening qualification."
    return f"""Execute exactly ONE approved RALPH-Lite plan step in ZEN Control.
Approved plan hash: {state['plan_hash']}
Step {step['id']}: {step['title']}
Objective: {step['objective']}
Acceptance: {json.dumps(step['acceptance'])}
Test-change policy: {step['test_change_policy']}
{repair_text}
Read .ralph/policy.md and obey it. Do not edit any file under .ralph. Do not interact with live RouterOS, secrets, credentials, or external production systems. Stay inside the repository. Do not disable, skip, delete, or weaken qualification to obtain a pass. Make only changes necessary for this step. You may run focused local tests while working, but the external controller will run authoritative gates afterwards.
If you discover useful out-of-scope work, return it in ideas and continue the approved step rather than implementing it.
If safe completion requires breaking policy or human judgement, make no speculative workaround: return needs_human=true with blockers.
"""


def block(state: dict, reason: str) -> None:
    state["status"] = "BLOCKED_HUMAN"
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
    if state.get("status") not in {"IDLE", "PLAN_COMPLETE"}:
        raise RuntimeError(f"cannot propose while status={state.get('status')}; finish or resolve the current plan first")
    plan = run_codex(plan_prompt(args.goal), PLAN_SCHEMA, "read-only", context="PLAN PROPOSAL")
    validate_plan(plan)
    digest = plan_hash(plan)
    state.update({"status": "AWAITING_APPROVAL", "plan_hash": digest, "plan": plan, "current_step": 1, "failure_attempts": {}, "active_failure": None, "last_failure": None, "last_result": None, "block_reason": None})
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
    state["status"] = "APPROVED"
    save_state(state)
    print(f"Approved plan {expected}; {len(state['plan']['steps'])} steps ready.")
    return 0


def cmd_resume(args: argparse.Namespace) -> int:
    init_files()
    state = load_state()
    if state.get("status") != "BLOCKED_HUMAN":
        raise RuntimeError("resume is only valid from BLOCKED_HUMAN")
    if args.plan_hash != state.get("plan_hash"):
        raise RuntimeError("resume hash does not match the approved plan")
    state["status"] = "APPROVED"
    state["block_reason"] = None
    save_state(state)
    append_journal(state["loop_count"], state["current_step"], "human-resume", "RESUMED", summary=args.reason, next_action="continue approved plan")
    print("Human resume accepted; approved plan may continue.")
    return 0


def cmd_status(_: argparse.Namespace) -> int:
    init_files()
    state = load_state()
    total = len((state.get("plan") or {}).get("steps") or [])
    print(f"status={state.get('status')} plan={state.get('plan_hash') or '-'} step={state.get('current_step')}/{total or '-'} loops={state.get('loop_count')} block={state.get('block_reason') or '-'}")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    init_files()
    state = load_state()
    if state.get("status") not in {"APPROVED", "RUNNING"}:
        raise RuntimeError(f"run requires APPROVED/RUNNING status, found {state.get('status')}")
    if PLAN.read_text(encoding="utf-8") != render_plan(state["plan"]):
        block(state, "approved plan file changed")
        raise RuntimeError("approved plan file changed; blocked for human review")

    loops_this_run = 0
    while state["current_step"] <= len(state["plan"]["steps"]):
        if loops_this_run >= args.max_loops:
            state["status"] = "APPROVED"
            save_state(state)
            live_write(f"loop budget reached ({args.max_loops}); paused cleanly with plan still approved", "PAUSE")
            print(f"PAUSED plan={state['plan_hash']} step={state['current_step']} loops={state['loop_count']}")
            return 0
        loops_this_run += 1
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
        live_write(
            f"loop={loop_no:04d} step={step['id']}/{len(state['plan']['steps'])} phase={phase} repair={repair_no} title={step['title']}",
            "RALPH",
        )

        before_repo = repo_snapshot()
        authority = authority_snapshot()
        protected_before = protected_snapshot()
        try:
            result = run_codex(step_prompt(state, step, active_fp, repair_no), RESULT_SCHEMA, "workspace-write", context=f"LOOP {loop_no:04d} STEP {step['id']} {'REPAIR' if active_fp else 'IMPLEMENT'}")
        except Exception as exc:
            append_journal(loop_no, step["id"], "repair" if active_fp else "implement", "BLOCKED", summary=str(exc), repair=repair_no, next_action="human review")
            block(state, str(exc))
            return 2

        after_repo = repo_snapshot()
        files = changed_paths(before_repo, after_repo)
        change_class = classify_changes(files)
        tooling_changed = [path for path in files if is_tooling_path(path)]

        if authority_changed(authority):
            restore_authority(authority)
            state = load_state()
            detail = f"tooling paths {tooling_changed}" if tooling_changed else "RALPH runtime authority"
            reason = f"Codex changed {detail}; original contents restored"
            live_write(reason, "POLICY")
            append_journal(loop_no, step["id"], "policy", "BLOCKED", summary=reason, files=files, repair=repair_no, next_action="human review", change_class=change_class)
            block(state, "Codex attempted to change RALPH controller/tooling authority")
            return 2

        protected = [p for p in files if is_protected_path(p)]
        test_violations = test_policy_violation(before_repo, after_repo, step["test_change_policy"])
        if protected or test_violations:
            if protected:
                restore_protected(protected_before, protected)
            reason = "policy violation: " + "; ".join(filter(None, [f"protected paths {protected}" if protected else "", f"test paths {test_violations}" if test_violations else ""]))
            append_journal(loop_no, step["id"], "policy", "BLOCKED", summary=reason, files=files, repair=repair_no, ideas=result.get("ideas", []), next_action="human review", change_class=change_class)
            append_ideas(loop_no, result.get("ideas", []))
            block(state, reason)
            return 2

        append_ideas(loop_no, result.get("ideas", []))
        if result.get("needs_human") or result.get("blockers"):
            reason = "; ".join(result.get("blockers") or ["Codex requested human review"])
            append_journal(loop_no, step["id"], "repair" if active_fp else "implement", "BLOCKED", summary=reason, files=files, repair=repair_no, ideas=result.get("ideas", []), next_action="human review", change_class=change_class)
            block(state, reason)
            return 2

        passed, gates, fp, gate_output = run_gates()
        if passed:
            live_write(f"loop={loop_no:04d} step={step['id']} PASS · class={change_class}", "PASS")
            append_journal(loop_no, step["id"], "repair" if active_fp else "implement", "PASS", summary=result.get("summary", ""), files=files, gates=gates, repair=repair_no, ideas=result.get("ideas", []), next_action="next approved step", change_class=change_class)
            state["last_result"] = "PASS"
            state["last_failure"] = None
            state["active_failure"] = None
            state["current_step"] += 1
            save_state(state)
            continue

        live_write(f"loop={loop_no:04d} step={step['id']} FAIL fingerprint={fp}", "FAIL")
        if active_fp:
            attempts = state.setdefault("failure_attempts", {})
            attempts[active_fp] = int(attempts.get(active_fp, 0)) + 1
        state["last_result"] = "FAIL"
        state["last_failure"] = {"fingerprint": fp, "output": gate_output[-6000:], "gates": gates}
        state["active_failure"] = fp
        append_journal(loop_no, step["id"], "repair" if active_fp else "implement", "FAIL", summary=result.get("summary", ""), files=files, gates=gates, fingerprint=fp, repair=repair_no, ideas=result.get("ideas", []), next_action="repair same approved step", change_class=change_class)
        save_state(state)

        same_attempts = int(state.get("failure_attempts", {}).get(fp, 0))
        if active_fp == fp and same_attempts >= MAX_REPAIRS_PER_FAILURE:
            block(state, f"failure {fp} persisted through {MAX_REPAIRS_PER_FAILURE} repair attempts")
            return 2

    state["status"] = "PLAN_COMPLETE"
    state["block_reason"] = None
    save_state(state)
    with JOURNAL.open("a", encoding="utf-8") as handle:
        handle.write(f"## Plan complete — {utc_now()}\n\n- Plan: `{state['plan_hash']}`\n- Loops: {state['loop_count']}\n- Steps: {len(state['plan']['steps'])}\n- Status: PLAN_COMPLETE\n- Next action: human review and approve a new 5-10 step plan\n\n")
    live_write(f"plan complete · plan={state['plan_hash']} loops={state['loop_count']} steps={len(state['plan']['steps'])}", "COMPLETE")
    print(f"PLAN_COMPLETE plan={state['plan_hash']} loops={state['loop_count']} steps={len(state['plan']['steps'])}")
    return 0


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
    run = sub.add_parser("run")
    run.add_argument("--max-loops", type=int, default=DEFAULT_MAX_LOOPS)
    run.set_defaults(func=cmd_run)
    resume = sub.add_parser("resume")
    resume.add_argument("plan_hash")
    resume.add_argument("--reason", required=True)
    resume.set_defaults(func=cmd_resume)
    sub.add_parser("status").set_defaults(func=cmd_status)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if getattr(args, "max_loops", 1) < 1:
        raise SystemExit("--max-loops must be >= 1")
    try:
        return args.func(args)
    except (RuntimeError, ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"RALPH-Lite: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
