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
import time
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
CONTEXT = RALPH / "context.json"

MAX_REPAIRS_PER_FAILURE = 3
DEFAULT_MAX_LOOPS = 40
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
    "required": ["summary", "ideas", "blockers", "needs_human", "context"],
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
            f"- Tokens: input={input_tokens} cached={cached_tokens} non-cached={noncached} output={int(stats.get('output_tokens') or 0)} reasoning={int(stats.get('reasoning_output_tokens') or 0)} cache={cache_ratio:.1f}%",
            f"- Gate durations: {'; '.join(f'{name}={seconds:.1f}s' for name, seconds in gate_times.items()) if gate_times else '-'}",
            f"- First pass: {'yes' if result == 'PASS' and repair == 0 else 'no'}",
        ]
    lines.append("")
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
        STATE, PLAN, IDEAS, JOURNAL, POLICY, CONTEXT,
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


def empty_codex_metrics() -> dict:
    return {
        "commands_executed": 0,
        "input_tokens": 0,
        "cached_input_tokens": 0,
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
        for key in ("input_tokens", "cached_input_tokens", "output_tokens", "reasoning_output_tokens"):
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

        if is_bwrap_bootstrap_failure(output):
            raise EnvironmentBlocked(
                "Codex default sandbox failed inside the model turn; automatic legacy fallback is disabled: "
                + normalize_failure(output)[-1200:],
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
        repair_text = f"\nThis is repair attempt {repair_no} for failure fingerprint {repair_fp}. Fix the failure without weakening qualification."
    prior = context_handoff(state)
    return f"""Execute exactly ONE approved RALPH-Lite plan step in ZEN Control.
Approved plan hash: {state['plan_hash']}
Step {step['id']}: {step['title']}
Objective: {step['objective']}
Acceptance: {json.dumps(step['acceptance'])}
Test-change policy: {step['test_change_policy']}
{repair_text}

Compact handoff from the previous successful loop:
{json.dumps(prior, separators=(',', ':'))}

CONTEXT-EFFICIENCY RULES:
- Start from the handoff's relevant_files and accepted_findings; do not rediscover accepted facts unless this step directly invalidates them.
- Prefer rg -n plus narrow sed/range reads or targeted symbols. Do not repeatedly read whole large files.
- Normally inspect no more than 6-8 relevant files before implementation. If more are genuinely required, explain why in the final summary.
- Do not broadly scan docs/, README.md, CHANGELOG.md, or Git history unless directly necessary for this step.
- Stop discovery once there is enough evidence to implement safely.
- Return context.relevant_files (max 8), context.accepted_findings (max 8), and context.files_inspected (max 16) for the next loop.

Read .ralph/policy.md and obey it. Do not edit any file under .ralph. Do not interact with live RouterOS, secrets, credentials, or external production systems. Stay inside the repository. Do not disable, skip, delete, or weaken qualification to obtain a pass. Make only changes necessary for this step. You may run focused local tests while working, but the external controller will run authoritative gates afterwards.
If you discover useful out-of-scope work, return it in ideas and continue the approved step rather than implementing it.
If safe completion requires breaking policy or human judgement, make no speculative workaround: return needs_human=true with blockers.
"""


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
    if state.get("status") not in {"BLOCKED_HUMAN", "BLOCKED_ENVIRONMENT"}:
        raise RuntimeError("resume is only valid from BLOCKED_HUMAN/BLOCKED_ENVIRONMENT")
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
        live_write(
            f"loop={loop_no:04d} step={step['id']}/{len(state['plan']['steps'])} phase={phase} repair={repair_no} title={step['title']}",
            "RALPH",
        )

        before_repo = repo_snapshot()
        authority = authority_snapshot()
        protected_before = protected_snapshot()
        try:
            result = run_codex(step_prompt(state, step, active_fp, repair_no), RESULT_SCHEMA, "workspace-write", context=f"LOOP {loop_no:04d} STEP {step['id']} {'REPAIR' if active_fp else 'IMPLEMENT'}")
        except EnvironmentBlocked as exc:
            reason = str(exc)
            live_write(reason, "ENV")
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

        if authority_changed(authority):
            restore_authority(authority)
            state = load_state()
            detail = f"tooling paths {tooling_changed}" if tooling_changed else "RALPH runtime authority"
            reason = f"Codex changed {detail}; original contents restored"
            live_write(reason, "POLICY")
            append_journal(loop_no, step["id"], "policy", "BLOCKED", summary=reason, files=files, repair=repair_no, next_action="human review", change_class=change_class, stats=loop_stats(loop_started, result, repair=repair_no))
            block(state, "Codex attempted to change RALPH controller/tooling authority")
            return 2

        protected = [p for p in files if is_protected_path(p)]
        test_violations = test_policy_violation(before_repo, after_repo, step["test_change_policy"])
        if protected or test_violations:
            if protected:
                restore_protected(protected_before, protected)
            reason = "policy violation: " + "; ".join(filter(None, [f"protected paths {protected}" if protected else "", f"test paths {test_violations}" if test_violations else ""]))
            append_journal(loop_no, step["id"], "policy", "BLOCKED", summary=reason, files=files, repair=repair_no, ideas=result.get("ideas", []), next_action="human review", change_class=change_class, stats=loop_stats(loop_started, result, repair=repair_no))
            append_ideas(loop_no, result.get("ideas", []))
            block(state, reason)
            return 2

        append_ideas(loop_no, result.get("ideas", []))
        if result.get("needs_human") or result.get("blockers"):
            reason = "; ".join(result.get("blockers") or ["Codex requested human review"])
            append_journal(loop_no, step["id"], phase, "BLOCKED", summary=reason, files=files, repair=repair_no, ideas=result.get("ideas", []), next_action="human review", change_class=change_class, stats=loop_stats(loop_started, result, repair=repair_no))
            block(state, reason)
            return 2

        passed, gates, fp, gate_output, gate_durations = run_gates()
        stats = loop_stats(loop_started, result, gate_durations=gate_durations, repair=repair_no)
        if passed:
            live_write(f"loop={loop_no:04d} step={step['id']} PASS · class={change_class}", "PASS")
            append_journal(loop_no, step["id"], phase, "PASS", summary=result.get("summary", ""), files=files, gates=gates, repair=repair_no, ideas=result.get("ideas", []), next_action="next approved step", change_class=change_class, stats=stats)
            state["last_result"] = "PASS"
            state["last_failure"] = None
            state["active_failure"] = None
            update_context_after_pass(state, step, result, files)
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
        append_journal(loop_no, step["id"], phase, "FAIL", summary=result.get("summary", ""), files=files, gates=gates, fingerprint=fp, repair=repair_no, ideas=result.get("ideas", []), next_action="repair same approved step", change_class=change_class, stats=stats)
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
