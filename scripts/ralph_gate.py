#!/usr/bin/env python3
"""RALPH-Lite v0.2.1 human-gate review surface.

Read-only companion for a blocked RALPH-Lite controller.  It intentionally
owns no execution authority: it never edits controller state, never resumes a
plan and never calls Codex.  Its job is to turn the existing fail-closed state
into a concise operator-facing gate card.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

VERSION = "0.2.1"
SCHEMA = "ralph_human_gate_v1"
MAX_TEXT = 480

ROOT = Path(__file__).resolve().parents[1]
RALPH_DIR = ROOT / ".ralph"
STATE = RALPH_DIR / "state.json"
JOURNAL = RALPH_DIR / "journal.md"
LIVE = RALPH_DIR / "live.log"

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
}


def _color_enabled(mode: str = "auto", *, is_tty: bool | None = None) -> bool:
    if mode == "never" or "NO_COLOR" in os.environ:
        return False
    if mode == "always":
        return True
    return sys.stdout.isatty() if is_tty is None else bool(is_tty)


def _paint(text: str, *styles: str, enabled: bool = False) -> str:
    if not enabled:
        return text
    prefix = "".join(ANSI[name] for name in styles if name in ANSI)
    return f"{prefix}{text}{ANSI['reset']}" if prefix else text


def _gate_owner(gate_class: str) -> str:
    return {
        "runtime_evidence": "Operator + Release Manager",
        "validation_evidence": "Developer/Operator + Release Manager",
        "credentials_or_access": "Operator / Access Owner",
        "security_approval": "Security Approver + Release Manager",
        "production_action": "Operator + Release Manager",
        "scope_conflict": "Maintainer / Technical Lead",
        "external_dependency": "Service Owner + Release Manager",
        "policy_review": "Maintainer / Technical Lead",
    }.get(gate_class, "Human Approver / Release Manager")


def _text(value: Any, limit: int = MAX_TEXT) -> str:
    """Return bounded single-line operator text."""
    if value is None:
        return ""
    value = re.sub(r"\s+", " ", str(value)).strip()
    if len(value) <= limit:
        return value
    return value[: max(0, limit - 1)].rstrip() + "…"


def _load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimeError(f"RALPH state not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"RALPH state is not valid JSON: {path}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("RALPH state root must be an object")
    return payload


def _step(state: dict[str, Any]) -> tuple[int, int, dict[str, Any]]:
    plan = state.get("plan") if isinstance(state.get("plan"), dict) else {}
    steps = plan.get("steps") if isinstance(plan.get("steps"), list) else []
    current = int(state.get("current_step") or 1)
    total = len(steps)
    item: dict[str, Any] = {}
    if 1 <= current <= total and isinstance(steps[current - 1], dict):
        item = steps[current - 1]
    return current, total, item


def _reason(state: dict[str, Any]) -> str:
    candidates: list[Any] = [state.get("block_reason")]
    result = state.get("last_result")
    if isinstance(result, dict):
        candidates.extend(
            result.get(key)
            for key in ("summary", "blocker", "block_reason", "reason", "detail")
        )
    for candidate in candidates:
        text = _text(candidate)
        if text:
            return text
    return "RALPH stopped for a human-owned decision or evidence requirement."


def _gate_class(reason: str, step_title: str = "") -> str:
    # The explicit blocker reason outranks the approved step title.  A resumed
    # step can move from one human-owned condition to another, and the gate
    # reviewer must describe the current blocker rather than stale title words.
    reason_text = reason.lower()
    title_text = step_title.lower()
    if "policy violation" in reason_text or "protected path" in reason_text or "controller/tooling authority" in reason_text:
        return "policy_review"
    rules = (
        ("validation_evidence", ("performance", "sample", "acceptance evidence", "snapshot", "validation")),
        ("runtime_evidence", ("incident", "runtime", "diagnostic", "worker", "active durable")),
        ("credentials_or_access", ("credential", "login", "permission", "access token", "authentication")),
        ("security_approval", ("security approval", "security sign-off", "authority approval")),
        ("production_action", ("routeros", "production", "live write", "live action")),
        ("scope_conflict", ("scope conflict", "overlap", "claimed work", "out of scope")),
        ("external_dependency", ("external dependency", "third-party", "upstream", "service unavailable")),
    )
    for name, needles in rules:
        if any(needle in reason_text for needle in needles):
            return name
    for name, needles in rules:
        if any(needle in title_text for needle in needles):
            return name
    return "human_decision"


def _guidance(gate_class: str, reason: str) -> dict[str, list[str]]:
    lower = reason.lower()
    if gate_class == "policy_review":
        return {
            "actions": [
                "Compare the requested path/action with the approved step and its test-change policy.",
                "Use steer for bounded human direction when the objective is still correct; use --allow-new-test only for an exact test path absent at plan approval.",
                "Retire/re-plan if the approved objective genuinely needs broader existing-file authority.",
            ],
            "success": [
                "The requested change is demonstrably inside the approved step or is explicitly bounded by a human steering record.",
                "Existing protected/tooling paths and pre-existing tests remain unchanged unless the approved plan already permits them.",
            ],
            "forbidden": [
                "Do not use steering to bypass protected paths, RALPH tooling authority, secrets or existing-test protection.",
                "Do not broaden the whole step merely to clear one blocked path.",
            ],
        }
    if gate_class == "runtime_evidence" and "incident" in lower:
        return {
            "actions": [
                "Review the currently active ZEN incidents and identify the underlying condition.",
                "Correct the underlying operational condition where appropriate; do not clear evidence merely for release acceptance.",
                "Run a fresh Incident Monitor scan after the underlying condition has cleared.",
                "Capture fresh operational diagnostics and verify the Incident Monitor is healthy with zero active incidents.",
            ],
            "success": [
                "Incident Monitor diagnostic state is healthy.",
                "Active durable incident count is 0.",
                "Fresh evidence is produced by the normal monitor/diagnostic path.",
            ],
            "forbidden": [
                "Do not disable Incident Monitor to obtain PASS.",
                "Do not edit/delete the incident database to obtain PASS.",
                "Do not manufacture or manually rewrite release evidence.",
            ],
        }
    if gate_class == "validation_evidence" and "performance" in lower:
        return {
            "actions": [
                "Exercise the real workload required by the existing performance contract.",
                "Capture a fresh operator-owned performance snapshot outside the repository.",
                "Validate it with python3 scripts/perf_acceptance.py ../zen-performance.json.",
            ],
            "success": [
                "All configured request-class sample minima and latency budgets pass.",
                "Prepared-view effectiveness and mutation-lane evidence pass without threshold relaxation.",
            ],
            "forbidden": [
                "Do not lower sample minima, latency budgets or acceptance thresholds.",
                "Do not inject synthetic PASS evidence.",
            ],
        }
    return {
        "actions": [
            "Review the blocker summary and the approved step acceptance criteria.",
            "Perform only the human-owned action or provide only the genuine evidence required by the approved plan.",
            "Resume the same approved plan when the stated condition is genuinely satisfied.",
        ],
        "success": ["The approved step's stated human-owned condition is genuinely satisfied."],
        "forbidden": [
            "Do not weaken gates or edit evidence merely to continue execution.",
            "Do not expand scope beyond the approved plan.",
        ],
    }


def _last_loop_gate(state: dict[str, Any]) -> tuple[int, int]:
    loop_no = int(state.get("loop_count") or 0)
    step_no, _, _ = _step(state)
    return loop_no, step_no


def _accepted_findings(state: dict[str, Any]) -> list[str]:
    result = state.get("last_result")
    values: list[str] = []
    if isinstance(result, dict):
        for key in ("tests", "validation", "evidence", "findings", "proved"):
            raw = result.get(key)
            if isinstance(raw, str) and raw.strip():
                values.append(_text(raw, 220))
            elif isinstance(raw, list):
                values.extend(_text(item, 220) for item in raw if _text(item, 220))
    # Keep the card bounded.  The full trace remains in live.log/journal.md.
    return values[:8]


def _display_summary(gate_class: str, reason: str) -> str:
    if gate_class == "runtime_evidence" and "incident" in reason.lower():
        return (
            "Incident Monitor state is runtime-owned. No verified source/configuration defect "
            "was found; operator action/evidence is required before this approved step can advance."
        )
    return _text(reason)


def _resolution_allowed(item: dict[str, Any], gate_class: str) -> bool:
    if gate_class != "runtime_evidence":
        return False
    approval_text = " ".join([
        str(item.get("objective") or ""),
        *(str(value) for value in (item.get("acceptance") or [])),
    ]).lower()
    return (
        "blocked_human" in approval_text
        and any(marker in approval_text for marker in ("runtime", "operator", "human-owned", "human owned"))
    )


def _policy_paths(reason: str) -> list[str]:
    match = re.search(r"test paths \[(.*?)\]", reason)
    if not match:
        return []
    return re.findall(r"['\"]([^'\"]+)['\"]", match.group(1))[:12]


def _checkpoint(state: dict[str, Any]) -> dict[str, Any]:
    checkpoint_id = str(state.get("recovery_checkpoint") or "")
    if not checkpoint_id:
        return {}
    path = RALPH_DIR / "recovery" / checkpoint_id / "manifest.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _path_origin(state: dict[str, Any], path: str) -> str:
    if path in set(state.get("plan_owned_files") or []):
        return "plan-owned"
    checkpoint = _checkpoint(state)
    if path in set(checkpoint.get("baseline_untracked_paths") or []):
        return "pre-existing untracked"
    head = str(checkpoint.get("head") or "")
    if head:
        proc = subprocess.run(
            ["git", "cat-file", "-e", f"{head}:{path}"],
            cwd=ROOT, text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if proc.returncode == 0:
            return "pre-existing tracked"
    current = subprocess.run(
        ["git", "status", "--porcelain=v1", "--", path], cwd=ROOT, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    ).stdout
    if current.startswith("??"):
        return "new/untracked since approval"
    return "absent at approval"


def build_gate(state: dict[str, Any]) -> dict[str, Any]:
    loop_no, step_no = _last_loop_gate(state)
    current, total, item = _step(state)
    title = _text(item.get("title") or item.get("name") or f"Step {current}", 180)
    reason = _reason(state)
    gate_class = _gate_class(reason, title)
    guidance = _guidance(gate_class, reason)
    status = str(state.get("status") or "UNKNOWN")
    open_gate = status in {"BLOCKED_HUMAN", "BLOCKED", "PAUSED"} or bool(state.get("block_reason"))
    plan_hash = _text(state.get("plan_hash"), 96)
    gate_id = f"HG-{loop_no:04d}-{step_no:02d}"
    resolution_allowed = open_gate and _resolution_allowed(item, gate_class)
    policy_paths = _policy_paths(reason) if gate_class == "policy_review" else []
    policy_detail = {
        "test_change_policy": str(item.get("test_change_policy") or ""),
        "paths": [{"path": path, "origin": _path_origin(state, path)} for path in policy_paths],
    } if gate_class == "policy_review" else {}
    return {
        "schema": SCHEMA,
        "version": VERSION,
        "gate_id": gate_id,
        "open": open_gate,
        "controller_status": status,
        "plan_hash": plan_hash,
        "loop": loop_no,
        "step": current,
        "step_count": total,
        "step_title": title,
        "approved_acceptance": [
            _text(value, 300) for value in (item.get("acceptance") or []) if _text(value, 300)
        ],
        "class": gate_class,
        "severity": "release_blocker" if "release" in reason.lower() or open_gate else "human_gate",
        "owner": _gate_owner(gate_class),
        "release_impact": (
            "Release/plan progression is blocked until this human gate is satisfied."
            if open_gate else "No open human gate currently blocks progression."
        ),
        "decision": (
            "Review the blocked delta and use bounded steer/resume/re-plan; policy gates are never silently overridden."
            if gate_class == "policy_review" else
            "Resolve the gate after the success criteria are independently satisfied."
            if resolution_allowed else
            "Supply genuine new evidence/input, then retry the same approved step."
        ),
        "summary": _display_summary(gate_class, reason),
        "blocker_detail": reason,
        "proved": _accepted_findings(state),
        "human_actions": guidance["actions"],
        "success_criteria": guidance["success"],
        "forbidden_shortcuts": guidance["forbidden"],
        "resolution_allowed": resolution_allowed,
        "policy": policy_detail,
        "steer": (
            f"python3 scripts/ralph.py steer {plan_hash} --gate {gate_id} --direction \"<bounded human direction>\""
            if plan_hash and gate_class == "policy_review" else ""
        ),
        "resolve": (
            f"python3 scripts/ralph.py resolve-gate {plan_hash} --gate {gate_id} --reason \"<evidence / action satisfying this gate>\""
            if plan_hash and resolution_allowed else ""
        ),
        "resume": (
            f"python3 scripts/ralph.py resume {plan_hash} --reason \"<new input requiring Ralph to retry this same step>\""
            if plan_hash else "python3 scripts/ralph.py resume <plan-hash> --reason \"<reason>\""
        ),
        "sources": {
            "state": str(STATE.relative_to(ROOT)),
            "journal": str(JOURNAL.relative_to(ROOT)),
            "live": str(LIVE.relative_to(ROOT)),
        },
    }


def _wrap_lines(items: list[str], indent: str = "  ") -> list[str]:
    lines: list[str] = []
    for index, item in enumerate(items, start=1):
        wrapped = textwrap.wrap(item, width=72, subsequent_indent="      ") or [""]
        lines.append(f"{indent}{index}. {wrapped[0]}")
        lines.extend(f"{indent}   {line}" for line in wrapped[1:])
    return lines


def _rule(title: str) -> list[str]:
    return [title, "─" * 70]


def _command_lines(gate: dict[str, Any]) -> list[str]:
    commands: list[str] = []
    if gate.get("class") == "policy_review" and gate.get("steer"):
        commands.extend([gate["steer"], gate["resume"]])
    elif gate.get("resolution_allowed") and gate.get("resolve"):
        commands.extend([gate["resolve"], "python3 scripts/ralph.py run"])
    else:
        commands.extend([gate["resume"], "python3 scripts/ralph.py run"])
    return commands


def render_gate(
    gate: dict[str, Any],
    *,
    details: bool = False,
    view: str = "review",
    color: bool = False,
) -> str:
    border = "═" * 78
    blocked = bool(gate.get("open"))
    status_word = "BLOCKED" if blocked else "CLEAR"
    status_color = "red" if blocked else "green"
    lines = [
        f"╔{border}╗",
        f"║ RALPH-Lite v{VERSION} · HUMAN GATE REVIEW".ljust(79) + "║",
        f"╠{border}╣",
        "║ " + _paint(f"STATUS {status_word}", "bold", status_color, enabled=color)
        + "   " + _paint(f"GATE {gate['gate_id']}", "bold", "magenta", enabled=color)
        + "   " + _paint(f"STEP {gate['step']}/{gate['step_count'] or '?'}", "bold", "cyan", enabled=color),
        f"╚{border}╝",
        "",
        f"Controller     {_paint(gate['controller_status'], 'bold', status_color, enabled=color)}",
        f"Gate type      {_paint(gate['class'], 'cyan', enabled=color)}",
        f"Owner          {gate.get('owner') or '-'}",
        f"Plan           {_paint(gate['plan_hash'] or '-', 'dim', enabled=color)}",
        f"Step title     {gate['step_title']}",
    ]

    if view in {"review", "release"}:
        lines.extend(["", *_rule("RELEASE MANAGER VIEW")])
        lines.append(f"  Decision       {_paint(gate.get('decision') or '-', 'bold', 'yellow', enabled=color)}")
        lines.append(f"  Impact         {gate.get('release_impact') or '-'}")
        lines.append(f"  Gate severity  {_paint(gate.get('severity') or '-', 'bold', 'red' if blocked else 'green', enabled=color)}")
        lines.extend(["", *_rule("SUCCESS / GO CRITERIA")])
        for item in gate["success_criteria"]:
            lines.append("  " + _paint("✓", "green", enabled=color) + f" {item}")
        lines.extend(["", *_rule("NO-GO / FORBIDDEN SHORTCUTS")])
        for item in gate["forbidden_shortcuts"]:
            lines.append("  " + _paint("✗", "red", enabled=color) + f" {item}")

    if view in {"review", "developer"}:
        lines.extend(["", *_rule("DEVELOPER VIEW")])
        lines.append("  Technical diagnosis")
        lines.extend(_wrap_lines([gate["summary"]], indent="    "))
        if gate.get("proved"):
            lines.append("  Evidence already recorded")
            for finding in gate["proved"]:
                lines.append("    " + _paint("✓", "green", enabled=color) + f" {finding}")
        policy = gate.get("policy") or {}
        if policy:
            lines.append("  Policy review")
            lines.append(f"    test-change policy: {_paint(policy.get('test_change_policy') or '-', 'yellow', enabled=color)}")
            for item in policy.get("paths") or []:
                lines.append(f"    {_paint(item.get('path') or '-', 'blue', enabled=color)} · origin={item.get('origin') or 'unknown'}")
        acceptance = gate.get("approved_acceptance") or []
        if acceptance:
            lines.append("  Approved acceptance")
            lines.extend(_wrap_lines([_text(v, 300) for v in acceptance], indent="    "))
        if details and gate.get("blocker_detail") and gate.get("blocker_detail") != gate.get("summary"):
            lines.append("  Raw blocker evidence")
            lines.extend(_wrap_lines([_text(gate["blocker_detail"], MAX_TEXT)], indent="    "))

    if view in {"review", "operator"}:
        lines.extend(["", *_rule("OPERATOR ACTION")])
        lines.extend(_wrap_lines(gate["human_actions"]))

    lines.extend(["", *_rule("NEXT COMMANDS")])
    for command in _command_lines(gate):
        lines.append("  " + _paint("$ " + command, "cyan", enabled=color))
    if gate.get("resolution_allowed"):
        lines.append("  " + _paint("Use resume only when Ralph must re-evaluate genuinely new input.", "dim", enabled=color))

    if details:
        lines.extend(["", *_rule("EVIDENCE PROVENANCE")])
        for name, path in gate["sources"].items():
            lines.append(f"  {name:<8} {_paint(path, 'blue', enabled=color)}")
        lines.append(f"  current step index: {gate['step']}")

    lines.extend([
        "",
        _paint("Views:", "bold", enabled=color)
        + " --view operator | developer | release | review",
        "Shareable:    python3 scripts/ralph_gate.py --markdown --view review",
        "Machine JSON: python3 scripts/ralph_gate.py --json",
        "History:      python3 scripts/ralph_gate.py --history",
    ])
    return "\n".join(lines)


def render_markdown(gate: dict[str, Any], *, details: bool = False, view: str = "review") -> str:
    status = "BLOCKED" if gate.get("open") else "CLEAR"
    lines = [
        f"# RALPH-Lite v{VERSION} — Human Gate Review",
        "",
        f"**Status:** {status}  ",
        f"**Gate:** `{gate['gate_id']}`  ",
        f"**Step:** {gate['step']}/{gate['step_count'] or '?'} — {gate['step_title']}  ",
        f"**Type:** `{gate['class']}`  ",
        f"**Owner:** {gate.get('owner') or '-'}  ",
        f"**Plan:** `{gate['plan_hash'] or '-'}`",
    ]
    if view in {"review", "release"}:
        lines += [
            "", "## Release manager view",
            f"**Decision:** {gate.get('decision') or '-'}",
            f"**Impact:** {gate.get('release_impact') or '-'}",
            "", "### Success / go criteria",
            *[f"- [ ] {item}" for item in gate["success_criteria"]],
            "", "### No-go conditions",
            *[f"- {item}" for item in gate["forbidden_shortcuts"]],
        ]
    if view in {"review", "developer"}:
        lines += ["", "## Developer view", f"**Technical diagnosis:** {gate['summary']}"]
        if gate.get("proved"):
            lines += ["", "### Evidence already recorded", *[f"- {item}" for item in gate["proved"]]]
        policy = gate.get("policy") or {}
        if policy:
            lines += ["", "### Policy review", f"- Test-change policy: `{policy.get('test_change_policy') or '-'}`"]
            lines += [f"- `{item.get('path')}` — {item.get('origin')}" for item in policy.get("paths") or []]
        acceptance = gate.get("approved_acceptance") or []
        if acceptance:
            lines += ["", "### Approved acceptance", *[f"- {item}" for item in acceptance]]
        if details and gate.get("blocker_detail") and gate.get("blocker_detail") != gate.get("summary"):
            lines += ["", "### Raw blocker evidence", gate["blocker_detail"]]
    if view in {"review", "operator"}:
        lines += ["", "## Operator action", *[f"{i}. {item}" for i, item in enumerate(gate["human_actions"], 1)]]
    lines += ["", "## Next commands"]
    for command in _command_lines(gate):
        lines += ["```bash", command, "```"]
    if details:
        lines += ["", "## Evidence provenance"]
        lines += [f"- **{name}:** `{path}`" for name, path in gate["sources"].items()]
    return "\n".join(lines)


def gate_history(path: Path = LIVE) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    current: dict[str, Any] = {}
    history: list[dict[str, Any]] = []
    start_re = re.compile(
        r"\[(?P<time>[^]]+)\]\s+RALPH\s+loop=(?P<loop>\d+)\s+step=(?P<step>\d+)/(?:\d+)\s+.*?title=(?P<title>.+)$"
    )
    block_re = re.compile(r"\[(?P<time>[^]]+)\]\s+SUMMARY\s+BLOCKED_HUMAN:\s*(?P<reason>.+)$")
    resolved_re = re.compile(r"\[(?P<time>[^]]+)\]\s+GATE\s+gate=(?P<gate>HG-\d{4}-\d{2})\s+resolved\s+HUMAN_CONFIRMED")
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = start_re.search(line)
        if match:
            current = {
                "loop": int(match.group("loop")),
                "step": int(match.group("step")),
                "title": _text(match.group("title"), 180),
                "started_at": match.group("time"),
            }
            continue
        match = block_re.search(line)
        if match:
            loop_no = int(current.get("loop") or 0)
            step_no = int(current.get("step") or 0)
            history.append(
                {
                    "gate_id": f"HG-{loop_no:04d}-{step_no:02d}",
                    "loop": loop_no,
                    "step": step_no,
                    "title": current.get("title") or "unknown",
                    "blocked_at": match.group("time"),
                    "summary": _text(match.group("reason"), 300),
                    "status": "OPEN",
                    "resolved_at": None,
                }
            )
            continue
        match = resolved_re.search(line)
        if match:
            for item in reversed(history):
                if item.get("gate_id") == match.group("gate"):
                    item["status"] = "RESOLVED"
                    item["resolved_at"] = match.group("time")
                    break
    return history


def render_history(history: list[dict[str, Any]]) -> str:
    if not history:
        return "RALPH-Lite Human Gate History\nNo BLOCKED_HUMAN events found."
    lines = ["RALPH-Lite Human Gate History", "", "Gate          Step   Status      Blocked      Summary"]
    for item in history:
        stamp = str(item.get("blocked_at") or "-")[:8]
        summary = _text(item.get("summary"), 62)
        lines.append(f"{item['gate_id']:<13} {item['step']:<6} {item.get('status','OPEN'):<11} {stamp:<12} {summary}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="RALPH-Lite v0.2.1 human-gate review surface"
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--json", action="store_true", help="emit the current gate as JSON")
    mode.add_argument("--markdown", action="store_true", help="emit a shareable Markdown review")
    mode.add_argument("--history", action="store_true", help="show prior BLOCKED_HUMAN events from live.log")
    parser.add_argument("--details", action="store_true", help="include raw blocker detail and evidence provenance")
    parser.add_argument("--view", choices=("operator", "developer", "release", "review"), default="review", help="select the audience-oriented review view")
    parser.add_argument("--color", choices=("auto", "always", "never"), default="auto", help="terminal colour mode; NO_COLOR always disables colour")
    parser.add_argument("--state", type=Path, default=STATE, help=argparse.SUPPRESS)
    parser.add_argument("--live", type=Path, default=LIVE, help=argparse.SUPPRESS)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.history:
        print(render_history(gate_history(args.live)))
        return 0
    state = _load_json(args.state)
    gate = build_gate(state)
    if args.json:
        print(json.dumps(gate, indent=2, sort_keys=True))
        return 0 if gate["open"] else 2
    if args.markdown:
        print(render_markdown(gate, details=args.details, view=args.view))
        return 0 if gate["open"] else 2
    color = _color_enabled(args.color)
    print(render_gate(gate, details=args.details, view=args.view, color=color))
    if not gate["open"]:
        print("\nNOTE: controller state does not currently indicate an open human gate.")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
