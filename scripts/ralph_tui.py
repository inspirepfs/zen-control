#!/usr/bin/env python3
"""Zero-dependency terminal rendering for RALPH-Lite.

The controller owns semantics.  This module only renders bounded operator output
and writes structured events that a future UI can consume.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import sys
from pathlib import Path
from typing import Iterable

VERSION = "0.3.0"
_COLOR_MODE = "auto"

ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "white": "\033[37m",
}

CATEGORY_STYLE = {
    "READ": ("blue", "READ"),
    "EDIT": ("yellow", "EDIT"),
    "CREATE": ("green", "CREATE"),
    "DELETE": ("red", "DELETE"),
    "MOVE": ("magenta", "MOVE"),
    "RUN": ("cyan", "RUN"),
    "CMD": ("cyan", "CMD"),
    "COMMAND": ("cyan", "COMMAND"),
    "THINK": ("dim", "THINK"),
    "SUMMARY": ("white", "SUMMARY"),
    "GATE": ("cyan", "TEST"),
    "VALIDATE": ("cyan", "VALIDATE"),
    "PASS": ("green", "PASS"),
    "COMPLETE": ("green", "COMPLETE"),
    "READY": ("green", "READY"),
    "WARN": ("yellow", "WARN"),
    "POLICY": ("yellow", "POLICY"),
    "STEER": ("magenta", "STEER"),
    "PAUSE": ("yellow", "PAUSE"),
    "EFFICIENCY": ("yellow", "EFFICIENCY"),
    "FAIL": ("red", "FAIL"),
    "ERROR": ("red", "ERROR"),
    "ENV": ("red", "ENV"),
    "BLOCKED": ("magenta", "BLOCKED"),
    "GATE-HUMAN": ("magenta", "HUMAN"),
    "RETIRED": ("magenta", "RETIRED"),
    "USAGE": ("dim", "USAGE"),
    "SANDBOX": ("dim", "SANDBOX"),
    "CHECKPOINT": ("cyan", "CHECKPOINT"),
    "CODEX": ("dim", "CODEX"),
    "RALPH": ("white", "RALPH"),
    "OUTPUT": ("dim", "OUTPUT"),
}


def configure(mode: str = "auto") -> None:
    global _COLOR_MODE
    if mode not in {"auto", "always", "never"}:
        raise ValueError(f"invalid color mode: {mode}")
    _COLOR_MODE = mode


def color_enabled(stream=None) -> bool:
    if os.getenv("NO_COLOR") is not None:
        return False
    if _COLOR_MODE == "always":
        return True
    if _COLOR_MODE == "never":
        return False
    stream = stream or sys.stdout
    return bool(getattr(stream, "isatty", lambda: False)())


def style(text: str, name: str, *, stream=None) -> str:
    if not color_enabled(stream):
        return text
    code = ANSI.get(name)
    return f"{code}{text}{ANSI['reset']}" if code else text


def clip(text: object, limit: int = 160) -> str:
    compact = " ".join(str(text or "").split())
    return compact if len(compact) <= limit else compact[: limit - 3] + "..."


def event_line(category: str, message: str, *, stamp: str | None = None, stream=None) -> str:
    stamp = stamp or dt.datetime.now().astimezone().strftime("%H:%M:%S")
    color, label = CATEGORY_STYLE.get(category, ("white", category[:10]))
    label_text = style(f"{label:<10}", color, stream=stream)
    return f"{style(f'[{stamp}]', 'dim', stream=stream)} {label_text} {message}"


def write_event(path: Path, category: str, message: str, **data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    event = {
        "timestamp": dt.datetime.now(dt.timezone.utc).astimezone().isoformat(timespec="seconds"),
        "category": category,
        "message": " ".join(str(message).split()),
        **data,
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")


def _visible_len(text: str) -> int:
    return len(re.sub(r"\x1b\[[0-9;]*m", "", text))


def box(title: str, rows: Iterable[str] = (), *, width: int = 74, tone: str = "cyan", stream=None) -> str:
    width = max(48, min(100, width))
    inner = width - 2
    top = "╔" + "═" * inner + "╗"
    divider = "╠" + "═" * inner + "╣"
    bottom = "╚" + "═" * inner + "╝"

    def row(text: str) -> str:
        text = clip(text, inner - 3)
        pad = max(0, inner - 1 - _visible_len(text))
        return f"║ {text}{' ' * pad}║"

    rendered = [style(top, tone, stream=stream), row(style(title, "bold", stream=stream)), style(divider, tone, stream=stream)]
    rendered.extend(row(str(item)) for item in rows)
    rendered.append(style(bottom, tone, stream=stream))
    return "\n".join(rendered)


def step_banner(
    *,
    loop_no: int,
    step_no: int,
    step_count: int,
    title: str,
    phase: str,
    plan_hash: str,
    repair: int,
    quota: str = "",
    status: str = "RUNNING",
    efficiency: str = "PASS",
    recovery: str = "-",
    changed_files: int = 0,
    test_policy: str = "none",
    progress: Iterable[str] = (),
    acceptance: Iterable[str] = (),
) -> str:
    rows = [
        f"{style('CURRENT OBJECTIVE', 'bold')}  {title}",
        f"Plan {style(plan_hash[:12] + '…', 'magenta')}   Phase {phase.upper()}   Repair {repair}",
        f"State {style(status, 'cyan')}   Efficiency {style(efficiency, 'green' if efficiency == 'PASS' else 'yellow')}   Plan files {changed_files}",
        f"Recovery {recovery}",
        f"Authority tests={test_policy} · existing tests protected · RALPH tooling protected",
    ]
    if quota:
        rows.append(f"Quota {quota}")
    accepted = list(acceptance)
    if accepted:
        rows.append("Acceptance: " + clip(accepted[0], 120))
    progress_rows = list(progress)
    if progress_rows:
        rows.append("Plan progress:")
        rows.extend(f"  {clip(item, 105)}" for item in progress_rows[:10])
    return box(f"RALPH-Lite v{VERSION} · LOOP {loop_no:04d} · STEP {step_no}/{step_count}", rows, width=88, tone="cyan")

def change_card(entries: list[dict]) -> str:
    if not entries:
        return ""
    rows: list[str] = []
    totals_add = totals_del = 0
    for item in entries[:20]:
        action = str(item.get("action") or "EDIT").upper()
        path = str(item.get("path") or "?")
        added = int(item.get("added") or 0)
        removed = int(item.get("removed") or 0)
        totals_add += added
        totals_del += removed
        tone = {"CREATE": "green", "EDIT": "yellow", "DELETE": "red", "MOVE": "magenta"}.get(action, "white")
        rows.append(f"{style(f'{action:<7}', tone)} {style(path, 'blue')}   +{added}/-{removed}")
        symbols = [str(s) for s in item.get("symbols") or []][:5]
        if symbols:
            rows.append("          ↳ " + " · ".join(symbols))
    rows.append(f"TOTAL   {len(entries)} files · +{totals_add}/-{totals_del}")
    return box("CHANGE SUMMARY", rows, tone="yellow")


def behavior_summary(summary: str) -> str:
    text = clip(summary, 900)
    if not text:
        return ""
    chunks = [chunk.strip() for chunk in re.split(r"(?<=[.!?])\s+", text) if chunk.strip()]
    rows = [f"• {chunk}" for chunk in chunks[:5]] or [text]
    return box("IMPLEMENTATION SUMMARY", rows, tone="white")


def diff_preview(diff_text: str, *, max_lines: int = 36) -> str:
    rows: list[str] = []
    for raw in str(diff_text or "").splitlines():
        if raw.startswith("diff --git"):
            parts = raw.split()
            path = parts[-1][2:] if len(parts) >= 4 and parts[-1].startswith("b/") else raw
            rows.append(style(f"FILE {path}", "bold"))
            continue
        if raw.startswith(("index ", "--- ", "+++ ")):
            continue
        if raw.startswith("@@"):
            rows.append(style(clip(raw, 92), "cyan"))
        elif raw.startswith("+") and not raw.startswith("+++"):
            rows.append(style(clip(raw, 92), "green"))
        elif raw.startswith("-") and not raw.startswith("---"):
            rows.append(style(clip(raw, 92), "red"))
        elif raw.strip():
            rows.append(style(clip(raw, 92), "dim"))
        if len(rows) >= max_lines:
            rows.append(style("… diff preview bounded …", "dim"))
            break
    return box("DIFF PREVIEW", rows, tone="cyan") if rows else ""


def policy_gate_card(
    *,
    gate_id: str,
    step_no: int,
    step_count: int,
    title: str,
    test_policy: str,
    paths: list[str],
    origins: dict[str, str],
    acceptance: list[str],
    protected: list[str],
) -> str:
    rows = [
        f"Gate {style(gate_id, 'magenta')} · Step {step_no}/{step_count} · {title}",
        f"Policy tests={test_policy}",
        "",
        "REQUESTED CHANGE / FILE ORIGIN",
    ]
    for path in paths[:8]:
        origin = origins.get(path, "unknown")
        rows.append(f"TEST    {style(path, 'blue')} · origin={origin}")
    for path in protected[:8]:
        rows.append(f"PROTECT {style(path, 'red')}")
    if acceptance:
        rows.append("")
        rows.append("APPROVED STEP")
        rows.extend(f"  • {clip(item, 120)}" for item in acceptance[:4])
    origin_values = set(origins.values())
    if paths and origin_values <= {"absent", "plan-owned"} and test_policy == "add-only":
        recommendation = "STEER/RETRY within existing approved add-only authority"
    elif protected:
        recommendation = "REPLAN or remove the protected-path change; do not override protection"
    else:
        recommendation = "REVIEW DIFF, then STEER bounded direction or RETIRE/REPLAN"
    rows.extend([
        "",
        f"RECOMMENDED ACTION  {recommendation}",
        "ACTIONS  steer bounded direction · view diff · resume retry · retire/replan",
        f'STEER   python3 scripts/ralph.py steer <plan-hash> --gate {gate_id} --direction "<direction>"',
    ])
    return box("HUMAN POLICY REVIEW", rows, width=92, tone="magenta")

def steer_card(*, gate_id: str, step_no: int, step_count: int, title: str, direction: str, allowed_new_tests: list[str]) -> str:
    rows = [
        f"Gate {gate_id} · Step {step_no}/{step_count} · {title}",
        f"Direction {clip(direction, 500)}",
        "Authority Protected/security/tooling boundaries remain enforced",
    ]
    if allowed_new_tests:
        rows.append("New-test grants:")
        rows.extend(f"  • {path}" for path in allowed_new_tests[:10])
    rows.append("Next: rerun the same approved step")
    return box("HUMAN DIRECTION RECORDED", rows, tone="magenta")


def result_card(*, result: str, step_no: int, step_count: int, files: int, added: int, removed: int, tests: Iterable[str], tokens: dict | None = None) -> str:
    tokens = dict(tokens or {})
    rows = [
        f"Step {step_no}/{step_count} {result}",
        f"Files {files} · +{added}/-{removed}",
        "Gates " + (" · ".join(tests) if tests else "-"),
    ]
    if tokens:
        rows.append(
            "Tokens input={input} cached={cached} output={output}".format(
                input=int(tokens.get("input_tokens") or 0),
                cached=int(tokens.get("cached_input_tokens") or 0),
                output=int(tokens.get("output_tokens") or 0),
            )
        )
    return box("LOOP RESULT", rows, tone="green" if result == "PASS" else "red")


def completion_card(report: dict) -> str:
    counts = report.get("counts") or {}
    change = report.get("changes") or {}
    qualification = report.get("qualification") or {}
    authority = report.get("authority") or {}
    accepted = counts.get("steps_accepted", counts.get("steps_passed", 0))
    rows = [
        f"Plan {str(report.get('plan_hash') or '')[:16]}…",
        f"Implementation {accepted}/{counts.get('steps_total', 0)} ACCEPTED · loops {counts.get('loops', 0)}",
        f"  PASS {counts.get('steps_passed', 0)} · HUMAN_CONFIRMED {counts.get('steps_human_confirmed', 0)} · recovered {counts.get('steps_recovered', 0)} · failed {counts.get('steps_failed', 0)}",
        f"Human gates {counts.get('human_gates', 0)} · steering decisions {counts.get('human_steers', 0)}",
        f"Final qualification {qualification.get('state', 'UNKNOWN')}",
        f"Files {change.get('files', 0)} · +{change.get('added', 0)}/-{change.get('removed', 0)}",
        f"Protected paths {'UNCHANGED' if not authority.get('protected_paths_changed') else 'CHANGED'} · RALPH tooling {'UNCHANGED' if not authority.get('ralph_tooling_changed') else 'CHANGED'}",
        f"Recovery {report.get('recovery_checkpoint') or '-'}",
        f"Report {report.get('markdown_path') or '-'}",
        f"Suggested commit {clip(report.get('suggested_commit') or '-', 70)}",
        "READY TO COMMIT" if report.get("status") == "READY_TO_COMMIT" else f"State {report.get('status')}",
        f"Next: python3 scripts/ralph.py finalize {report.get('plan_hash')} --commit",
    ]
    return box(f"RALPH-Lite v{VERSION} · PLAN COMPLETE", rows, width=92, tone="green")


def commit_overlap_card(
    *,
    plan_hash: str,
    checkpoint: str,
    baseline_head: str,
    branch: str,
    upstream: str,
    overlaps: list[str],
    plan_files: int,
) -> str:
    rows = [
        f"Plan {plan_hash[:16]}… · recovery {checkpoint}",
        f"Baseline HEAD {baseline_head[:12]} · branch {branch} · upstream {upstream}",
        f"Plan files {plan_files} · overlapping dirty-at-approval files {len(overlaps)}",
        "",
        "OVERLAPPING FILES",
        *[f"  • {style(path, 'yellow')}" for path in overlaps[:15]],
        "",
        "WHY RALPH STOPPED",
        "  Ralph cannot safely separate pre-existing edits from this plan's edits.",
        "RECOMMENDED ACTION",
        "  Review/commit the qualified product delta manually, then use reconcile-commit.",
        "NOT SAFE  git add -A · force commit · force push",
    ]
    return box("COMMIT REVIEW REQUIRED", rows, width=92, tone="yellow")


def reconcile_card(*, title: str, plan_hash: str, commit: str, upstream: str, detail: str) -> str:
    rows = [
        f"Plan {plan_hash[:16]}…",
        f"Commit {commit[:12]}",
        f"Upstream {upstream}",
        detail,
    ]
    return box(title, rows, width=84, tone="green")

