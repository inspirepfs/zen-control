#!/usr/bin/env python3
"""Local zero-dependency web console for RALPH-Lite.

The web console is an operator surface only. It never owns controller semantics:
all state transitions are performed by the existing scripts/ralph.py CLI. The
server binds to loopback by default; explicit private-LAN mode uses username/password login, an HttpOnly session cookie, and CSRF for every write.
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import html
import ipaddress
import json
import os
import secrets
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[1]
RALPH = ROOT / ".ralph"
STATE = RALPH / "state.json"
EVENTS = RALPH / "events.jsonl"
LIVE = RALPH / "live.log"
REPORTS = RALPH / "reports"
WEB_JOB = RALPH / "web-job.json"
WEB_LOG = RALPH / "web-run.log"
RALPH_CLI = ROOT / "scripts" / "ralph.py"
VERSION = "0.3.2"
MAX_EVENTS = 240
MAX_LOG_LINES = 160
MAX_BODY = 64 * 1024
DEFAULT_USAGE_REFRESH_SECONDS = 60
DEFAULT_SESSION_HOURS = 12.0
SESSION_COOKIE = "ralph_session"


class WebConsoleError(RuntimeError):
    pass


def _read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _read_lines(path: Path, limit: int) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    return lines[-max(1, int(limit)) :]


def _git(args: list[str], *, timeout: int = 8) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args], cwd=ROOT, text=True, capture_output=True,
        timeout=timeout, check=False,
    )


def git_snapshot() -> dict[str, Any]:
    branch = _git(["branch", "--show-current"]).stdout.strip() or "DETACHED"
    upstream = _git(["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"]).stdout.strip()
    status_lines = [line for line in _git(["status", "--short"]).stdout.splitlines() if line.strip()]
    head = _git(["rev-parse", "HEAD"]).stdout.strip()
    return {
        "branch": branch,
        "upstream": upstream or None,
        "head": head or None,
        "dirty": bool(status_lines),
        "dirty_count": len(status_lines),
        "status": status_lines[:80],
    }


def event_tail(limit: int = MAX_EVENTS) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw in _read_lines(EVENTS, min(MAX_EVENTS, max(1, int(limit)))):
        try:
            item = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            rows.append(item)
    return rows


def _process_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def web_job_status() -> dict[str, Any]:
    job = _read_json(WEB_JOB, {})
    if not isinstance(job, dict) or not job:
        return {"active": False}
    pid = int(job.get("pid") or 0)
    active = _process_alive(pid)
    if job.get("active") and not active:
        job["active"] = False
        job["finished_at"] = job.get("finished_at") or time.strftime("%Y-%m-%dT%H:%M:%S%z")
        try:
            WEB_JOB.write_text(json.dumps(job, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        except OSError:
            pass
    return {**job, "active": active}


def plan_progress(state: dict[str, Any]) -> list[dict[str, Any]]:
    plan = state.get("plan") if isinstance(state.get("plan"), dict) else {}
    steps = plan.get("steps") if isinstance(plan.get("steps"), list) else []
    results = state.get("step_results") if isinstance(state.get("step_results"), list) else []
    by_step: dict[int, dict[str, Any]] = {}
    for row in results:
        if isinstance(row, dict):
            try:
                by_step[int(row.get("step") or row.get("step_id") or 0)] = row
            except (TypeError, ValueError):
                continue
    current = int(state.get("current_step") or 0)
    output: list[dict[str, Any]] = []
    for step in steps:
        sid = int(step.get("id") or 0)
        result = by_step.get(sid) or {}
        if result:
            state_name = str(result.get("result") or result.get("status") or "PASS")
        elif sid < current:
            state_name = "ACCEPTED"
        elif sid == current:
            state_name = "CURRENT"
        else:
            state_name = "PENDING"
        output.append({
            "id": sid,
            "title": str(step.get("title") or f"Step {sid}"),
            "objective": str(step.get("objective") or ""),
            "test_change_policy": str(step.get("test_change_policy") or "none"),
            "acceptance": [str(x) for x in step.get("acceptance") or []],
            "state": state_name,
        })
    return output


def _gate_snapshot(state: dict[str, Any]) -> dict[str, Any] | None:
    if state.get("status") != "BLOCKED_HUMAN":
        return None
    loop_no = int(state.get("loop_count") or 0)
    step_no = int(state.get("current_step") or 0)
    progress = plan_progress(state)
    step = next((x for x in progress if x["id"] == step_no), None)
    block = str(state.get("block_reason") or "")
    policy = "policy violation" in block.lower() or "protected" in block.lower()
    recommendation = (
        "Review the authority mismatch. Steer only within the already-approved plan, "
        "or retire/replan if new authority is genuinely required."
        if policy else
        "Review the evidence below, then provide bounded direction and resume, or resolve "
        "the delegated human gate when its acceptance evidence is satisfied."
    )
    return {
        "id": f"HG-{loop_no:04d}-{step_no:02d}",
        "step": step_no,
        "title": (step or {}).get("title") or "Human review",
        "block_reason": block,
        "policy_review": policy,
        "test_change_policy": (step or {}).get("test_change_policy") or "none",
        "acceptance": (step or {}).get("acceptance") or [],
        "recommendation": recommendation,
    }


def _latest_report(state: dict[str, Any]) -> dict[str, Any] | None:
    digest = str(state.get("plan_hash") or "")
    if not digest:
        return None
    path = REPORTS / f"{digest[:16]}-summary.md"
    if not path.exists():
        # Older versions may use a short plan hash.
        matches = sorted(REPORTS.glob(f"{digest[:16]}*-summary.md")) if REPORTS.exists() else []
        path = matches[-1] if matches else path
    if not path.exists():
        return None
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    return {"path": str(path.relative_to(ROOT)), "preview": "\n".join(text.splitlines()[:100])}


def snapshot(usage_report: dict[str, Any] | None = None) -> dict[str, Any]:
    state = _read_json(STATE, {})
    if not isinstance(state, dict):
        state = {}
    cached_usage = state.get("codex_usage") if isinstance(state.get("codex_usage"), dict) else {}
    live_report = usage_report if isinstance(usage_report, dict) else {}
    usage = live_report.get("codex_limits") if isinstance(live_report.get("codex_limits"), dict) else cached_usage
    windows = usage.get("windows") if isinstance(usage.get("windows"), list) else []
    remaining = min((float(row.get("remaining_percent", 100.0)) for row in windows), default=None)
    ledger = live_report.get("ledger") if isinstance(live_report.get("ledger"), dict) else {}
    efficiency = state.get("last_efficiency") if isinstance(state.get("last_efficiency"), dict) else {}
    plan = state.get("plan") if isinstance(state.get("plan"), dict) else {}
    steering = state.get("human_steering") if isinstance(state.get("human_steering"), list) else []
    return {
        "schema": "zen_ralph_web_snapshot_v1",
        "version": VERSION,
        "controller": {
            "status": str(state.get("status") or "IDLE"),
            "plan_hash": state.get("plan_hash"),
            "current_step": int(state.get("current_step") or 0),
            "step_count": len(plan.get("steps") or []),
            "loop_count": int(state.get("loop_count") or 0),
            "block_reason": state.get("block_reason"),
            "efficiency": str(efficiency.get("status") or "-"),
            "quota_remaining_percent": remaining,
            "recovery_checkpoint": state.get("recovery_checkpoint"),
            "plan_changed_files": [str(x) for x in state.get("plan_changed_files") or []][:120],
            "plan_owned_files": [str(x) for x in state.get("plan_owned_files") or []][:120],
            "commit_sha": state.get("commit_sha"),
            "push_upstream": state.get("push_upstream"),
            "steering_count": len(steering),
        },
        "plan": {
            "goal": str(plan.get("goal") or ""),
            "steps": plan_progress(state),
        },
        "gate": _gate_snapshot(state),
        "usage": {
            "model": usage.get("model"),
            "plan_type": usage.get("plan_type"),
            "captured_at": usage.get("captured_at"),
            "guard": live_report.get("guard") or ("UNKNOWN" if not windows else "-"),
            "refresh_error": live_report.get("live_limit_error"),
            "current_plan": ledger.get("current_plan") or {},
            "current_plan_source": ledger.get("current_plan_source") or "ledger",
            "windows": ledger.get("windows") or windows,
            "plans": ledger.get("plans") or [],
            "ledger_rows": int(ledger.get("ledger_rows") or 0),
            "last_event_at": ledger.get("last_event_at"),
        },
        "git": git_snapshot(),
        "job": web_job_status(),
        "report": _latest_report(state),
        "events": event_tail(),
        "live_log": _read_lines(WEB_LOG if WEB_LOG.exists() else LIVE, MAX_LOG_LINES),
    }


def _host_from_header(value: str | None) -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    if raw.startswith("["):
        end = raw.find("]")
        return raw[1:end] if end > 0 else raw
    return raw.split(":", 1)[0]


def host_header_allowed(value: str | None, allowed_hosts: set[str] | None = None) -> bool:
    """Reject DNS-rebinding Host headers; LAN mode permits only the exact bind IP."""
    host = _host_from_header(value)
    if not host:
        return False
    if allowed_hosts is not None:
        return host in {str(item).strip().lower() for item in allowed_hosts if str(item).strip()}
    if host in {"localhost", "localhost."}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def validate_bind(host: str, *, allow_lan: bool = False) -> str:
    raw = str(host or "").strip()
    if raw.lower() == "localhost":
        return "127.0.0.1"
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError as exc:
        raise WebConsoleError("web console host must be a literal IP address or localhost") from exc
    if ip.is_loopback:
        return raw
    if not allow_lan:
        raise WebConsoleError("web console refuses non-loopback bind unless --allow-lan is explicit")
    if ip.is_unspecified:
        raise WebConsoleError("LAN mode refuses wildcard binds such as 0.0.0.0 or ::; bind one private LAN IP")
    if ip.is_link_local or not ip.is_private:
        raise WebConsoleError("LAN mode permits only a private RFC1918/ULA address")
    return raw


def validate_loopback(host: str) -> str:
    """Compatibility helper retained for callers/tests requiring loopback-only validation."""
    return validate_bind(host, allow_lan=False)


class SessionAuth:
    """In-memory authenticated browser sessions for explicit private-LAN mode."""

    def __init__(self, username: str, password: str, *, session_hours: float = DEFAULT_SESSION_HOURS):
        username = str(username or "").strip()
        if not username:
            raise WebConsoleError("LAN username must not be empty")
        if len(password) < 10:
            raise WebConsoleError("LAN password must contain at least 10 characters")
        self.username = username
        self.salt = secrets.token_bytes(16)
        self.digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), self.salt, 240_000)
        self.session_seconds = max(300, int(float(session_hours) * 3600))
        self.sessions: dict[str, float] = {}
        self.lock = threading.Lock()

    def verify_password(self, username: str, password: str) -> bool:
        candidate = hashlib.pbkdf2_hmac("sha256", str(password).encode("utf-8"), self.salt, 240_000)
        return secrets.compare_digest(str(username), self.username) and secrets.compare_digest(candidate, self.digest)

    def login(self, username: str, password: str) -> str | None:
        if not self.verify_password(username, password):
            return None
        token = secrets.token_urlsafe(32)
        with self.lock:
            self._prune_locked()
            self.sessions[token] = time.time() + self.session_seconds
        return token

    def valid(self, token: str | None) -> bool:
        if not token:
            return False
        with self.lock:
            self._prune_locked()
            expires = self.sessions.get(str(token))
            return bool(expires and expires > time.time())

    def logout(self, token: str | None) -> None:
        if not token:
            return
        with self.lock:
            self.sessions.pop(str(token), None)

    def _prune_locked(self) -> None:
        now = time.time()
        for token, expires in list(self.sessions.items()):
            if expires <= now:
                self.sessions.pop(token, None)


class UsageMonitor:
    """Refresh Codex limit authority without writing controller state."""

    def __init__(self, refresh_seconds: int = DEFAULT_USAGE_REFRESH_SECONDS):
        self.refresh_seconds = max(15, int(refresh_seconds))
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._report: dict[str, Any] = {}
        self._refreshed_epoch: float | None = None
        self._error: str | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._loop, name="ralph-usage-monitor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            report = dict(self._report)
            if self._error:
                report.setdefault("live_limit_error", self._error)
            report["web_refreshed_epoch"] = self._refreshed_epoch
            report["web_refresh_seconds"] = self.refresh_seconds
            return report

    def refresh(self) -> dict[str, Any]:
        command = [sys.executable, str(RALPH_CLI), "usage", "--json", "--no-save"]
        try:
            result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=25, check=False)
            report = json.loads(result.stdout) if result.stdout.strip() else {}
            if not isinstance(report, dict):
                raise ValueError("usage command returned a non-object")
            error = str(report.get("live_limit_error") or "").strip() or None
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError, ValueError) as exc:
            report = {}
            error = str(exc)
        with self._lock:
            if report:
                self._report = report
            self._refreshed_epoch = time.time()
            self._error = error
            return dict(self._report)

    def _loop(self) -> None:
        while not self._stop.is_set():
            self.refresh()
            self._stop.wait(self.refresh_seconds)


def _password_from_file(path: str) -> str:
    value = Path(path).expanduser()
    try:
        mode = value.stat().st_mode & 0o777
    except OSError as exc:
        raise WebConsoleError(f"cannot read password file: {exc}") from exc
    if mode & 0o077:
        raise WebConsoleError("password file must not be group/world accessible; use chmod 600")
    try:
        password = value.read_text(encoding="utf-8").splitlines()[0]
    except (OSError, IndexError) as exc:
        raise WebConsoleError("password file is empty or unreadable") from exc
    return password


def resolve_lan_credentials(*, username: str | None = None, password_file: str | None = None) -> tuple[str, str]:
    user = str(username or os.environ.get("RALPH_WEB_USERNAME") or "ralph").strip()
    if password_file:
        password = _password_from_file(password_file)
    elif os.environ.get("RALPH_WEB_PASSWORD"):
        password = str(os.environ["RALPH_WEB_PASSWORD"])
    elif sys.stdin.isatty():
        password = getpass.getpass(f"RALPH web password for {user}: ")
    else:
        raise WebConsoleError("LAN mode needs RALPH_WEB_PASSWORD, --password-file, or an interactive password prompt")
    if len(password) < 10:
        raise WebConsoleError("LAN password must contain at least 10 characters")
    return user, password


@dataclass(frozen=True)
class CommandRequest:
    argv: list[str]
    background: bool = False
    confirm: str | None = None


def command_for_action(payload: dict[str, Any], state: dict[str, Any]) -> CommandRequest:
    action = str(payload.get("action") or "").strip()
    plan_hash = str(payload.get("plan_hash") or state.get("plan_hash") or "").strip()
    status = str(state.get("status") or "IDLE")

    def reason() -> str:
        value = " ".join(str(payload.get("reason") or "").split())
        if not value:
            raise WebConsoleError("reason is required")
        return value

    if action == "propose":
        goal = str(payload.get("goal") or "").strip()
        if status not in {"IDLE", "PLAN_COMPLETE", "PUSHED"}:
            raise WebConsoleError(f"cannot propose while status={status}")
        if len(goal) < 20:
            raise WebConsoleError("proposal goal must be at least 20 characters")
        return CommandRequest(["propose", "--goal", goal], background=True)
    if not plan_hash:
        raise WebConsoleError("active plan hash is required")
    if action == "approve":
        return CommandRequest(["approve", plan_hash])
    if action == "reject":
        return CommandRequest(["reject", plan_hash, "--reason", reason()])
    if action == "run":
        max_loops = int(payload.get("max_loops") or 40)
        max_loops = max(1, min(max_loops, 40))
        return CommandRequest(["run", "--color", "never", "--max-loops", str(max_loops)], background=True)
    if action == "steer":
        gate = str(payload.get("gate") or "").strip()
        direction = " ".join(str(payload.get("direction") or "").split())
        if not gate or not direction:
            raise WebConsoleError("gate and direction are required for steer")
        argv = ["steer", plan_hash, "--gate", gate, "--direction", direction]
        for item in payload.get("allow_new_test") or []:
            item = str(item).strip()
            if item:
                argv += ["--allow-new-test", item]
        return CommandRequest(argv)
    if action == "resume":
        return CommandRequest(["resume", plan_hash, "--reason", reason()])
    if action == "resolve_gate":
        gate = str(payload.get("gate") or "").strip()
        if not gate:
            raise WebConsoleError("gate is required")
        return CommandRequest(["resolve-gate", plan_hash, "--gate", gate, "--reason", reason()])
    if action == "retire":
        if str(payload.get("confirm") or "") != "RETIRE":
            raise WebConsoleError("retire requires confirm=RETIRE")
        return CommandRequest(["retire-plan", plan_hash, "--reason", reason()], confirm="RETIRE")
    if action == "report":
        return CommandRequest(["report", plan_hash])
    if action == "finalize_review":
        return CommandRequest(["finalize", plan_hash])
    if action == "finalize_commit":
        if str(payload.get("confirm") or "") != "COMMIT":
            raise WebConsoleError("commit requires confirm=COMMIT")
        argv = ["finalize", plan_hash, "--commit"]
        message = " ".join(str(payload.get("message") or "").split())
        if message:
            argv += ["--message", message]
        return CommandRequest(argv, confirm="COMMIT")
    if action == "finalize_push":
        if str(payload.get("confirm") or "") != "PUSH":
            raise WebConsoleError("push requires confirm=PUSH")
        return CommandRequest(["finalize", plan_hash, "--push"], confirm="PUSH")
    if action == "reconcile_commit":
        if str(payload.get("confirm") or "") != "ADOPT":
            raise WebConsoleError("reconcile-commit requires confirm=ADOPT")
        commit = str(payload.get("commit") or "").strip()
        if not commit:
            raise WebConsoleError("commit SHA is required")
        return CommandRequest(["reconcile-commit", plan_hash, "--commit", commit, "--reason", reason()], confirm="ADOPT")
    if action == "reconcile_push":
        if str(payload.get("confirm") or "") != "PUSHED":
            raise WebConsoleError("reconcile-push requires confirm=PUSHED")
        return CommandRequest(["reconcile-push", plan_hash], confirm="PUSHED")
    raise WebConsoleError(f"unsupported action: {action or '-'}")


def run_command(request: CommandRequest) -> dict[str, Any]:
    command = [sys.executable, str(RALPH_CLI), *request.argv]
    if request.background:
        job = web_job_status()
        if job.get("active"):
            raise WebConsoleError(f"background Ralph job already active (pid={job.get('pid')})")
        RALPH.mkdir(parents=True, exist_ok=True)
        log_handle = WEB_LOG.open("a", encoding="utf-8")
        started = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        log_handle.write(f"\n=== WEB JOB {started} :: {' '.join(request.argv[:3])} ===\n")
        log_handle.flush()
        proc = subprocess.Popen(
            command, cwd=ROOT, stdout=log_handle, stderr=subprocess.STDOUT,
            text=True, start_new_session=True,
        )
        job = {
            "active": True,
            "pid": proc.pid,
            "argv": request.argv,
            "started_at": started,
        }
        WEB_JOB.write_text(json.dumps(job, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        log_handle.close()
        return {"ok": True, "background": True, "pid": proc.pid, "argv": request.argv}
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=60, check=False)
    return {
        "ok": result.returncode == 0,
        "background": False,
        "returncode": result.returncode,
        "stdout": result.stdout[-12000:],
        "stderr": result.stderr[-8000:],
        "argv": request.argv,
    }


PAGE = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>RALPH-Lite</title>
<style>
:root{color-scheme:dark;--bg:#081018;--panel:#101b26;--panel2:#0c151e;--text:#dce7f2;--muted:#8495a7;--green:#5ee19a;--yellow:#f4ca64;--red:#ff6b73;--blue:#6ab7ff;--cyan:#61d7e6;--magenta:#c98aff;--line:#263647;--shadow:0 10px 28px rgba(0,0,0,.28)}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace}.wrap{width:min(100%,2400px);max-width:2400px;margin:auto;padding:14px 22px}.top{display:grid;grid-template-columns:1fr auto;gap:14px;align-items:center;margin-bottom:12px}.brand{font-size:22px;font-weight:800}.sub{color:var(--muted)}.badge{display:inline-block;padding:4px 8px;border:1px solid var(--line);border-radius:999px;margin:2px}.ok{color:var(--green)}.warn{color:var(--yellow)}.bad{color:var(--red)}.info{color:var(--cyan)}.grid{display:grid;grid-template-columns:repeat(12,minmax(0,1fr));gap:10px}.card{background:linear-gradient(180deg,var(--panel),var(--panel2));border:1px solid var(--line);border-radius:12px;padding:12px;box-shadow:var(--shadow);min-width:0}.span3{grid-column:span 3}.span4{grid-column:span 4}.span5{grid-column:span 5}.span6{grid-column:span 6}.span7{grid-column:span 7}.span8{grid-column:span 8}.span9{grid-column:span 9}.span12{grid-column:span 12}h2{font-size:13px;letter-spacing:.08em;text-transform:uppercase;color:var(--cyan);margin:0 0 9px}h3{font-size:14px;margin:8px 0 5px}.metric{font-size:27px;font-weight:800}.kv{display:grid;grid-template-columns:max-content 1fr;gap:4px 12px}.kv>div:nth-child(odd){color:var(--muted)}.usage-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:9px}.usage-box{background:#08131d;border:1px solid var(--line);border-radius:9px;padding:10px;min-width:0}.usage-value{font-size:22px;font-weight:800}.usage-windows,.plan-usage{display:grid;gap:5px;margin-top:9px}.usage-row{display:grid;grid-template-columns:120px 1fr 1fr 1fr;gap:8px;padding:6px 8px;background:#08131d;border-radius:6px}.usage-row>span:first-child{font-weight:700}.steps{display:grid;gap:6px}.step{border-left:3px solid var(--line);padding:7px 9px;background:#0a131c}.step.PASS,.step.ACCEPTED,.step.HUMAN_CONFIRMED{border-color:var(--green)}.step.CURRENT{border-color:var(--cyan)}.step.PENDING{border-color:#39495a}.step-title{font-weight:700}.small{font-size:12px;color:var(--muted)}pre{white-space:pre-wrap;word-break:break-word;background:#071019;border:1px solid var(--line);border-radius:8px;padding:9px;max-height:460px;overflow:auto;margin:0}.events{height:600px;overflow:auto;border:1px solid var(--line);border-radius:8px;background:#071019}.event{padding:5px 9px;border-bottom:1px solid #132131}.READ{color:var(--blue)}.EDIT,.WARN,.POLICY{color:var(--yellow)}.CREATE,.PASS,.COMPLETE,.READY{color:var(--green)}.DELETE,.FAIL,.ERROR,.ENV{color:var(--red)}.BLOCKED,.STEER,.GATE-HUMAN{color:var(--magenta)}.RUN,.CMD,.COMMAND,.GATE,.VALIDATE,.CHECKPOINT,.USAGE{color:var(--cyan)}button{font:inherit;background:#172535;color:var(--text);border:1px solid #395069;border-radius:7px;padding:8px 11px;cursor:pointer;min-height:38px}button:hover{border-color:var(--cyan)}button.danger{border-color:#7a3138;color:#ff9ba1}button.good{border-color:#2d7350;color:#8bf0b7}input,textarea{width:100%;font:inherit;background:#071019;color:var(--text);border:1px solid var(--line);border-radius:7px;padding:8px}textarea{min-height:90px}.actions{display:flex;gap:7px;flex-wrap:wrap;margin-top:8px}.form{display:grid;gap:7px}.notice{padding:9px;border-left:3px solid var(--cyan);background:#09141e;margin:8px 0}.gate{border-left-color:var(--magenta)}.errorbox{border-left-color:var(--red)}.file{color:var(--blue)}.criteria{margin:6px 0 0 20px;padding:0}.criteria li{margin:3px 0}.action-result{margin-top:10px;padding:9px;background:#08131d;border:1px solid var(--line);border-radius:8px}.action-result:empty{display:none}.action-result .action-title{font-weight:800;color:var(--green);margin-bottom:5px}.pretty-object{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:3px 10px}.pretty-object>div:nth-child(odd){color:var(--muted)}.footer{margin:12px 0;color:var(--muted);font-size:12px}
@media(max-width:1150px){.span3{grid-column:span 6}.span4,.span5,.span6,.span7,.span8,.span9{grid-column:span 12}.usage-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.usage-row{grid-template-columns:100px 1fr 1fr}}
@media(max-width:720px){body{font-size:13px}.wrap{padding:8px}.top{grid-template-columns:1fr;gap:7px}.top>div:last-child{text-align:left}.brand{font-size:20px}.grid{gap:8px}.card,.span3,.span4,.span5,.span6,.span7,.span8,.span9,.span12{grid-column:span 12;padding:10px}.usage-grid{grid-template-columns:1fr}.usage-row{grid-template-columns:1fr 1fr;gap:4px}.usage-row>span:first-child{grid-column:1/-1}.events{height:340px}pre{max-height:300px}button{min-height:44px;flex:1 1 auto}input,textarea{font-size:16px}.metric{font-size:23px}.kv{grid-template-columns:110px minmax(0,1fr)}.footer{padding-bottom:max(8px,env(safe-area-inset-bottom))}}
</style></head><body><div class="wrap">
<div class="top"><div><div class="brand">RALPH-Lite <span id="version" class="info"></span></div><div class="sub">Operator console · CLI/TUI remains authoritative</div></div><div><span id="refresh" class="badge">connecting</span><span id="job" class="badge">job -</span><button onclick="logout()">Logout</button></div></div>
<div id="error"></div><div class="grid">
<section class="card span3"><h2>Controller</h2><div id="status" class="metric">-</div><div id="controller" class="kv"></div></section>
<section class="card span3"><h2>Plan</h2><div id="planMetric" class="metric">-</div><div id="planMeta" class="kv"></div></section>
<section class="card span3"><h2>Quota / Efficiency</h2><div id="quota" class="metric">-</div><div id="eff" class="kv"></div></section>
<section class="card span3"><h2>Git</h2><div id="branch" class="metric">-</div><div id="git" class="kv"></div></section>
<section class="card span12"><h2>Usage / Token Economy</h2><div id="usageSummary" class="usage-grid"></div><div id="usageWindows" class="usage-windows"></div><h3>Consumption by plan</h3><div id="planUsage" class="plan-usage"></div></section>
<section class="card span8"><h2>Plan Progress</h2><div id="goal" class="notice"></div><div id="steps" class="steps"></div></section>
<section class="card span4"><h2>Human Control</h2><div id="gate"></div><div id="controls"></div><div id="actionResult" class="action-result"></div></section>
<section class="card span9"><h2>Live Activity</h2><div id="events" class="events"></div></section>
<section class="card span3"><h2>Plan Files</h2><div id="files"></div></section>
<section class="card span6"><h2>Completion Report</h2><pre id="report">No completion report yet.</pre></section>
<section class="card span6"><h2>Controller Output</h2><pre id="log">No output yet.</pre></section>
</div><div class="footer">Private-LAN mode uses username/password + HttpOnly session + CSRF + exact Host validation · no force-push or policy bypass is exposed</div></div>
<script>
const CSRF='__CSRF__';
function esc(s){return String(s??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));}
function kv(obj){return Object.entries(obj).map(([k,v])=>`<div>${esc(k)}</div><div>${esc(v??'-')}</div>`).join('');}
function num(v){return Number(v||0).toLocaleString();}
function when(epoch){if(!epoch)return 'unknown';return new Date(Number(epoch)*1000).toLocaleString();}
function stripAnsi(s){return String(s||'').replace(/\x1b\[[0-9;]*m/g,'');}
const renderedValues=new WeakMap(),pendingTargetUpdates=new Map();let renderedControlsIdentity=null,latestSnapshot=null,refreshGeneration=0;
function selectionIntersectsTarget(target){const selection=window.getSelection();if(!target||!selection||selection.isCollapsed||!selection.rangeCount)return false;for(let i=0;i<selection.rangeCount;i++){try{if(selection.getRangeAt(i).intersectsNode(target))return true;}catch(_e){}}return false;}
function valuesFor(target){let values=renderedValues.get(target);if(!values){values=new Map();renderedValues.set(target,values);}return values;}
function pendingFor(target){let updates=pendingTargetUpdates.get(target);if(!updates){updates=new Map();pendingTargetUpdates.set(target,updates);}return updates;}
function renderValue(target,kind,value,write){if(!target)return false;const next=String(value??''),values=valuesFor(target),pending=pendingTargetUpdates.get(target);if(values.get(kind)===next){if(pending){pending.delete(kind);if(!pending.size)pendingTargetUpdates.delete(target);}return false;}if(selectionIntersectsTarget(target)){pendingFor(target).set(kind,{value:next,write});return false;}write(target,next);values.set(kind,next);if(pending){pending.delete(kind);if(!pending.size)pendingTargetUpdates.delete(target);}return true;}
function flushPendingTargetUpdates(){for(const [target,updates] of pendingTargetUpdates){if(!selectionIntersectsTarget(target))for(const [kind,update] of updates)renderValue(target,kind,update.value,update.write);}}
function renderText(id,value){return renderValue(document.getElementById(id),'text',value,(target,next)=>{target.textContent=next;});}
function renderHTML(id,value){return renderValue(document.getElementById(id),'html',value,(target,next)=>{target.innerHTML=next;});}
function renderClass(id,value){return renderValue(document.getElementById(id),'class',value,(target,next)=>{target.className=next;});}
document.addEventListener('selectionchange',flushPendingTargetUpdates);
function prettyObject(value){if(Array.isArray(value))return `<ul class="criteria">${value.map(v=>`<li>${prettyObject(v)}</li>`).join('')}</ul>`;if(value&&typeof value==='object')return `<div class="pretty-object">${Object.entries(value).map(([k,v])=>`<div>${esc(k)}</div><div>${prettyObject(v)}</div>`).join('')}</div>`;return esc(value??'-');}
function prettyOutput(text){const clean=stripAnsi(text).trim();if(!clean)return '';try{return prettyObject(JSON.parse(clean));}catch(_e){}const lines=clean.split(/\r?\n/).map(x=>x.replace(/^[║]\s?/,'').replace(/\s?[║]$/,'').trim()).filter(x=>x&&!/^[╔╠╚═─]+$/.test(x));return lines.map(x=>`<div>${esc(x)}</div>`).join('');}
function actionLabel(action){return ({approve:'Plan approved',reject:'Plan rejected',resume:'Plan resumed',resolve_gate:'Human gate resolved',steer:'Direction submitted',finalize_review:'Finalization review',finalize_commit:'Qualified delta committed',finalize_push:'Commit pushed',retire:'Plan retired'})[action]||'Operator action complete';}
function renderActionResult(action,j){const body=[prettyOutput(j.stdout),prettyOutput(j.stderr)].filter(Boolean).join('');renderHTML('actionResult',`<div class="action-title">${esc(actionLabel(action))}</div>${body||'<div class="small">Controller accepted the action. Current state is shown above.</div>'}`);}
async function post(payload){const r=await fetch('/api/action',{method:'POST',headers:{'Content-Type':'application/json','X-RALPH-CSRF':CSRF},body:JSON.stringify(payload)});const j=await r.json();if(!r.ok||!j.ok)throw new Error(j.error||j.stderr||'action failed');return j;}
function controlButton(label,action,extra={},cls=''){return `<button class="${cls}" onclick='act(${JSON.stringify(action)},${JSON.stringify(extra)})'>${esc(label)}</button>`;}
async function act(action,extra={}){try{let p={action,...extra};if(['reject','resume','resolve_gate','retire'].includes(action)){const reason=prompt('Reason / evidence:');if(!reason)return;p.reason=reason;}if(action==='retire'){if(prompt('Type RETIRE to confirm')!=='RETIRE')return;p.confirm='RETIRE';}if(action==='finalize_commit'){if(prompt('Type COMMIT to confirm')!=='COMMIT')return;p.confirm='COMMIT';}if(action==='finalize_push'){if(prompt('Type PUSH to confirm')!=='PUSH')return;p.confirm='PUSH';}const j=await post(p);renderActionResult(action,j);await refresh();}catch(e){showError(e.message);}}
async function submitGoal(){const goal=document.getElementById('goalInput').value.trim();if(!goal)return;try{await post({action:'propose',goal});await refresh();}catch(e){showError(e.message);}}
async function submitSteer(){const direction=document.getElementById('steerInput').value.trim();const gate=document.getElementById('gateId').textContent.trim();if(!direction)return;try{await post({action:'steer',gate,direction});await refresh();}catch(e){showError(e.message);}}
async function logout(){try{await fetch('/api/logout',{method:'POST',headers:{'X-RALPH-CSRF':CSRF}});}finally{location.reload();}}
function showError(msg){renderHTML('error',`<div class="notice errorbox">${esc(msg)}</div>`);}
function renderControls(s){const c=s.controller,g=s.gate;let out='';const st=c.status;const identity=JSON.stringify([st,st==='BLOCKED_HUMAN'?String(g?.id||''):'']);if(identity===renderedControlsIdentity)return;renderedControlsIdentity=identity;if(['IDLE','PLAN_COMPLETE','PUSHED'].includes(st)){out=`<div class="form"><textarea id="goalInput" placeholder="Describe the bounded engineering goal..."></textarea><button class="good" onclick="submitGoal()">Propose plan</button></div>`;}else if(st==='AWAITING_APPROVAL'){out=`<div class="notice"><b>Approval review</b><br><span class="small">Read every proposed step, objective, acceptance criterion and test-change policy before granting execution authority.</span></div><div class="actions">${controlButton('Approve plan','approve',{},'good')}${controlButton('Reject','reject',{},'danger')}</div>`;}else if(['APPROVED','RUNNING','PAUSED_USAGE_LIMIT'].includes(st)){out=`<div class="actions">${controlButton('Run approved plan','run',{max_loops:40},'good')}</div>`;}else if(st==='BLOCKED_HUMAN'){out=`<div class="form"><textarea id="steerInput" placeholder="Bounded human direction for this exact gate..."></textarea><button onclick="submitSteer()">Steer & retry</button><div class="actions">${controlButton('Resume retry','resume')}${controlButton('Resolve delegated gate','resolve_gate',{gate:g?.id||''},'good')}${controlButton('Retire plan','retire',{},'danger')}</div></div>`;}else if(st==='READY_TO_COMMIT'){out=`<div class="actions">${controlButton('Finalization review','finalize_review')}${controlButton('Commit qualified delta','finalize_commit',{},'good')}</div>`;}else if(st==='COMMITTED'){out=`<div class="actions">${controlButton('Push to configured upstream','finalize_push',{},'good')}</div>`;}else{out=`<div class="small">No web action for state ${esc(st)}. Use the CLI for exceptional recovery.</div>`;}const controls=document.getElementById('controls');renderedValues.delete(controls);renderHTML('controls',out);}
function renderUsage(u){const p=u.current_plan||{};const ratio=p.input_tokens?((Number(p.cached_input_tokens||0)/Number(p.input_tokens))*100):0;renderHTML('usageSummary',`<div class="usage-box"><div class="small">Plan input</div><div class="usage-value">${num(p.input_tokens)}</div><div class="small">non-cached ${num(p.noncached_input_tokens)}</div></div><div class="usage-box"><div class="small">Plan output</div><div class="usage-value">${num(p.output_tokens)}</div><div class="small">reasoning ${num(p.reasoning_output_tokens)}</div></div><div class="usage-box"><div class="small">Cached input</div><div class="usage-value">${num(p.cached_input_tokens)}</div><div class="small">cache ${ratio.toFixed(1)}%</div></div><div class="usage-box"><div class="small">Observed turns</div><div class="usage-value">${num(p.turns)}</div><div class="small">${esc(u.model||'-')} · ${esc(u.plan_type||'-')}</div></div>`);const wins=u.windows||[];renderHTML('usageWindows',wins.map(w=>{const t=w.observed_tokens||{};return `<div class="usage-row"><span>${esc(w.name||w.slot||'window')}</span><span>${Number(w.remaining_percent??0).toFixed(1)}% left</span><span>in ${num(t.input_tokens)} · out ${num(t.output_tokens)}</span><span>reset ${esc(when(w.resets_at))}</span></div>`;}).join('')||'<div class="small">Live quota windows are refreshing…</div>');renderHTML('planUsage',(u.plans||[]).slice(0,8).map(x=>`<div class="usage-row"><span>${esc((x.plan_hash||'unassigned').slice(0,8))}</span><span>${num(x.turns)} turns</span><span>in ${num(x.input_tokens)} · out ${num(x.output_tokens)}</span><span>${esc((x.goal||'').slice(0,80))}</span></div>`).join('')||'<div class="small">No v0.3.2 usage-ledger history yet.</div>');}
function render(s){const c=s.controller,p=s.plan,g=s.git,j=s.job,u=s.usage||{};renderText('version','v'+s.version);renderText('status',c.status);renderHTML('controller',kv({plan:(c.plan_hash||'-').slice(0,16),step:`${c.current_step}/${c.step_count||'-'}`,loops:c.loop_count,recovery:c.recovery_checkpoint||'-'}));renderText('planMetric',`${Math.min(c.current_step,c.step_count||0)}/${c.step_count||'-'}`);renderHTML('planMeta',kv({steering:c.steering_count,commit:(c.commit_sha||'-').slice(0,12),upstream:c.push_upstream||'-'}));renderText('quota',c.quota_remaining_percent==null?'-':c.quota_remaining_percent.toFixed(1)+'%');renderHTML('eff',kv({efficiency:c.efficiency,job:j.active?`RUNNING pid ${j.pid}`:'idle',limits:u.captured_at||'refreshing'}));renderText('branch',g.branch);renderHTML('git',kv({upstream:g.upstream||'-',dirty:g.dirty?`${g.dirty_count} files`:'clean',head:(g.head||'-').slice(0,12)}));renderUsage(u);renderText('goal',p.goal||'No active plan.');renderHTML('steps',p.steps.map(x=>`<div class="step ${esc(x.state)}"><div class="step-title">${x.id}. ${esc(x.title)} <span class="badge">${esc(x.state)}</span></div><div>${esc(x.objective)}</div><div class="small">Test changes: ${esc(x.test_change_policy)}</div>${(x.acceptance||[]).length?`<div class="small"><b>Acceptance criteria</b></div><ul class="criteria">${x.acceptance.map(a=>`<li>${esc(a)}</li>`).join('')}</ul>`:''}</div>`).join('')||'<div class="small">No plan steps.</div>');renderHTML('gate',s.gate?`<div class="notice gate"><div><b id="gateId">${esc(s.gate.id)}</b> · Step ${s.gate.step}</div><div class="step-title">${esc(s.gate.title||'Human review')}</div><div class="small">${s.gate.policy_review?'POLICY / AUTHORITY REVIEW':'OPERATOR EVIDENCE REVIEW'} · tests=${esc(s.gate.test_change_policy)}</div><h3>Why Ralph stopped</h3>${prettyOutput(s.gate.block_reason)}${(s.gate.acceptance||[]).length?`<h3>Acceptance criteria</h3><ul class="criteria">${s.gate.acceptance.map(a=>`<li>${esc(a)}</li>`).join('')}</ul>`:''}<h3>Recommended action</h3><div>${esc(s.gate.recommendation||'Review the evidence and choose a bounded operator action.')}</div></div>`:'<div class="small">No open human gate.</div>');renderControls(s);const events=s.events.map(e=>`<div class="event ${esc(e.category||'')}"><b>${esc(e.category||'EVENT')}</b> ${esc(e.message||'')}</div>`).join('');if(renderHTML('events',events))document.getElementById('events').scrollTop=document.getElementById('events').scrollHeight;renderHTML('files',(c.plan_changed_files||[]).map(x=>`<div class="file">${esc(x)}</div>`).join('')||'<div class="small">No recorded plan files yet.</div>');renderText('report',s.report?.preview||'No completion report yet.');renderText('log',(s.live_log||[]).join('\n')||'No output yet.');renderText('job',j.active?`job RUNNING ${j.pid}`:'job idle');renderClass('job','badge '+(j.active?'info':''));renderText('refresh','live');renderClass('refresh','badge ok');}
async function refresh(){const generation=++refreshGeneration;try{const r=await fetch('/api/snapshot',{cache:'no-store'});if(r.status===401){location.reload();return;}if(!r.ok)throw new Error('snapshot '+r.status);const s=await r.json();if(generation!==refreshGeneration)return;latestSnapshot=s;render(latestSnapshot);renderHTML('error','');}catch(e){if(generation!==refreshGeneration)return;renderText('refresh','offline');renderClass('refresh','badge bad');showError(e.message);}}
refresh();setInterval(refresh,1500);
</script></body></html>'''

LOGIN_PAGE = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><title>RALPH-Lite Login</title><style>:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#081018;color:#dce7f2;font:14px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace;padding:16px}.login{width:min(420px,100%);background:#101b26;border:1px solid #263647;border-radius:14px;padding:22px;box-shadow:0 15px 40px rgba(0,0,0,.35)}h1{font-size:22px;margin:0 0 4px}.muted{color:#8495a7;margin-bottom:18px}label{display:block;margin:10px 0 4px}input,button{width:100%;font:inherit;font-size:16px;border-radius:8px;padding:11px;background:#071019;color:#dce7f2;border:1px solid #395069}button{margin-top:15px;background:#173429;border-color:#2d7350;color:#8bf0b7;min-height:46px}.err{color:#ff8e95;margin-top:10px;min-height:20px}</style></head><body><form class="login" onsubmit="login(event)"><h1>RALPH-Lite <span style="color:#61d7e6">v__VERSION__</span></h1><div class="muted">Private home-lab operator console</div><label>Username</label><input id="user" autocomplete="username" autofocus required><label>Password</label><input id="pass" type="password" autocomplete="current-password" required><button>Sign in</button><div id="err" class="err"></div></form><script>const CSRF='__CSRF__';async function login(e){e.preventDefault();const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json','X-RALPH-CSRF':CSRF},body:JSON.stringify({username:document.getElementById('user').value,password:document.getElementById('pass').value})});const j=await r.json();if(r.ok&&j.ok){location.reload();return;}document.getElementById('err').textContent=j.error||'Sign in failed';}</script></body></html>'''


class ConsoleServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        handler,
        *,
        csrf_token: str,
        allowed_hosts: set[str],
        lan_mode: bool,
        auth: SessionAuth | None,
        usage_monitor: UsageMonitor,
    ):
        super().__init__(address, handler)
        self.csrf_token = csrf_token
        self.allowed_hosts = set(allowed_hosts)
        self.lan_mode = bool(lan_mode)
        self.auth = auth
        self.usage_monitor = usage_monitor


class Handler(BaseHTTPRequestHandler):
    server_version = "RALPH-Lite-Web/0.3.2"

    def _host_allowed(self) -> bool:
        return host_header_allowed(self.headers.get("Host"), getattr(self.server, "allowed_hosts", set()))

    def _session_token(self) -> str | None:
        cookie = SimpleCookie()
        try:
            cookie.load(str(self.headers.get("Cookie") or ""))
        except Exception:
            return None
        item = cookie.get(SESSION_COOKIE)
        return str(item.value) if item is not None else None

    def _auth_allowed(self) -> bool:
        if not bool(getattr(self.server, "lan_mode", False)):
            return True
        auth = getattr(self.server, "auth", None)
        return bool(auth and auth.valid(self._session_token()))

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("[ralph-web] " + (fmt % args) + "\n")

    def _send_json(self, payload: Any, status: int = 200, *, extra_headers: dict[str, str] | None = None) -> None:
        raw = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _send_html(self, body: str) -> None:
        raw = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802
        if not self._host_allowed():
            self._send_json({"ok": False, "error": "invalid Host header"}, HTTPStatus.MISDIRECTED_REQUEST)
            return
        path = urlparse(self.path).path
        if path == "/":
            token = html.escape(str(self.server.csrf_token), quote=True)  # type: ignore[attr-defined]
            if bool(getattr(self.server, "lan_mode", False)) and not self._auth_allowed():
                self._send_html(LOGIN_PAGE.replace("__CSRF__", token).replace("__VERSION__", VERSION))
            else:
                self._send_html(PAGE.replace("__CSRF__", token))
            return
        if path == "/api/health":
            self._send_json({
                "ok": True, "version": VERSION,
                "lan_mode": bool(getattr(self.server, "lan_mode", False)),
                "auth_required": bool(getattr(self.server, "lan_mode", False)),
                "auth_scheme": "session-password" if bool(getattr(self.server, "lan_mode", False)) else "none",
            })
            return
        if not self._auth_allowed():
            self._send_json({"ok": False, "error": "authentication required"}, HTTPStatus.UNAUTHORIZED)
            return
        if path == "/api/snapshot":
            monitor = getattr(self.server, "usage_monitor", None)
            report = monitor.snapshot() if monitor is not None else {}
            self._send_json(snapshot(report))
            return
        self._send_json({"ok": False, "error": "not found"}, 404)

    def do_POST(self) -> None:  # noqa: N802
        if not self._host_allowed():
            self._send_json({"ok": False, "error": "invalid Host header"}, HTTPStatus.MISDIRECTED_REQUEST)
            return
        path = urlparse(self.path).path
        if self.headers.get("X-RALPH-CSRF") != self.server.csrf_token:  # type: ignore[attr-defined]
            self._send_json({"ok": False, "error": "invalid CSRF token"}, 403)
            return
        if path == "/api/login":
            if not bool(getattr(self.server, "lan_mode", False)):
                self._send_json({"ok": True})
                return
            try:
                length = int(self.headers.get("Content-Length") or 0)
                payload = json.loads(self.rfile.read(length).decode("utf-8")) if 0 < length <= MAX_BODY else {}
            except (ValueError, json.JSONDecodeError):
                payload = {}
            auth = getattr(self.server, "auth", None)
            session = auth.login(str(payload.get("username") or ""), str(payload.get("password") or "")) if auth else None
            if not session:
                time.sleep(0.15)
                self._send_json({"ok": False, "error": "invalid username or password"}, HTTPStatus.UNAUTHORIZED)
                return
            max_age = int(auth.session_seconds)
            cookie = f"{SESSION_COOKIE}={session}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}"
            self._send_json({"ok": True, "username": auth.username}, extra_headers={"Set-Cookie": cookie})
            return
        if not self._auth_allowed():
            self._send_json({"ok": False, "error": "authentication required"}, HTTPStatus.UNAUTHORIZED)
            return
        if path == "/api/logout":
            auth = getattr(self.server, "auth", None)
            if auth:
                auth.logout(self._session_token())
            self._send_json({"ok": True}, extra_headers={"Set-Cookie": f"{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"})
            return
        if path != "/api/action":
            self._send_json({"ok": False, "error": "not found"}, 404)
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY:
            self._send_json({"ok": False, "error": "invalid request body"}, 400)
            return
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("payload must be an object")
            state = _read_json(STATE, {})
            if not isinstance(state, dict):
                state = {}
            request = command_for_action(payload, state)
            result = run_command(request)
            status = 200 if result.get("ok") else 409
            self._send_json(result, status)
        except (ValueError, WebConsoleError, subprocess.SubprocessError, OSError) as exc:
            self._send_json({"ok": False, "error": str(exc)}, 400)


def build_server(
    host: str,
    port: int,
    *,
    csrf_token: str | None = None,
    allow_lan: bool = False,
    username: str | None = None,
    password: str | None = None,
    session_hours: float = DEFAULT_SESSION_HOURS,
    usage_refresh_seconds: int = DEFAULT_USAGE_REFRESH_SECONDS,
) -> ConsoleServer:
    host = validate_bind(host, allow_lan=allow_lan)
    if not 0 <= int(port) <= 65535:
        raise WebConsoleError("port must be between 0 and 65535")
    ip = ipaddress.ip_address(host)
    lan_mode = not ip.is_loopback
    allowed_hosts = {host.lower()}
    if ip.is_loopback:
        allowed_hosts.update({"localhost", "localhost.", "127.0.0.1", "::1"})
    auth = SessionAuth(username or "ralph", password or "", session_hours=session_hours) if lan_mode else None
    return ConsoleServer(
        (host, int(port)), Handler,
        csrf_token=csrf_token or secrets.token_urlsafe(32),
        allowed_hosts=allowed_hosts, lan_mode=lan_mode, auth=auth,
        usage_monitor=UsageMonitor(usage_refresh_seconds),
    )


def _browser_host(host: str) -> str:
    return f"[{host}]" if ":" in host else host


def serve(
    host: str = "127.0.0.1",
    port: int = 8765,
    *,
    allow_lan: bool = False,
    username: str | None = None,
    password_file: str | None = None,
    session_hours: float = DEFAULT_SESSION_HOURS,
    usage_refresh_seconds: int = DEFAULT_USAGE_REFRESH_SECONDS,
) -> int:
    RALPH.mkdir(parents=True, exist_ok=True)
    validated = validate_bind(host, allow_lan=allow_lan)
    lan_mode = not ipaddress.ip_address(validated).is_loopback
    user, password = (resolve_lan_credentials(username=username, password_file=password_file) if lan_mode else (None, None))
    server = build_server(
        validated, port, allow_lan=allow_lan, username=user, password=password,
        session_hours=session_hours, usage_refresh_seconds=usage_refresh_seconds,
    )
    actual_host, actual_port = server.server_address[:2]
    print(f"RALPH-Lite v{VERSION} web console")
    base = f"http://{_browser_host(str(actual_host))}:{actual_port}/"
    print(f"URL: {base}")
    if server.lan_mode:
        print(f"Login: {server.auth.username if server.auth else '-'} / password supplied locally")
        print("Security: explicit private-LAN mode; username/password session + exact Host validation + CSRF")
        print("Note: plain HTTP is intended only for a trusted home LAN; use an HTTPS reverse proxy before broader exposure")
    else:
        print("Security: loopback-only by default")
    print(f"Usage: live Codex limits refresh every {server.usage_monitor.refresh_seconds}s; token ledger resets views with quota windows")
    print("Authority: web actions invoke the existing Ralph CLI; no second state machine")
    server.usage_monitor.start()
    try:
        server.serve_forever(poll_interval=0.4)
    except KeyboardInterrupt:
        pass
    finally:
        server.usage_monitor.stop()
        server.server_close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="RALPH-Lite local web console")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--allow-lan", action="store_true")
    parser.add_argument("--username", default=None)
    parser.add_argument("--password-file", default=None)
    parser.add_argument("--session-hours", type=float, default=DEFAULT_SESSION_HOURS)
    parser.add_argument("--usage-refresh-seconds", type=int, default=DEFAULT_USAGE_REFRESH_SECONDS)
    args = parser.parse_args(argv)
    if args.usage_refresh_seconds < 15:
        parser.error("--usage-refresh-seconds must be >= 15")
    if args.session_hours <= 0:
        parser.error("--session-hours must be > 0")
    try:
        return serve(
            args.host, args.port, allow_lan=args.allow_lan, username=args.username,
            password_file=args.password_file, session_hours=args.session_hours,
            usage_refresh_seconds=args.usage_refresh_seconds,
        )
    except (WebConsoleError, OSError) as exc:
        print(f"RALPH-Lite web: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
