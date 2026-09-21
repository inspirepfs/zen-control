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

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))
import ralph_efficiency as efficiency_policy
import ralph_model as model_policy
import ralph
from ralph_profile import PROJECT_PROFILE

ROOT = PROJECT_PROFILE.repository_root(__file__)


def _project_policy_kwargs() -> dict[str, Path]:
    return PROJECT_PROFILE.policy_storage_kwargs(ROOT)
RALPH = PROJECT_PROFILE.runtime_directory(ROOT)
STATE = PROJECT_PROFILE.artifact(ROOT, "state")
EVENTS = PROJECT_PROFILE.artifact(ROOT, "events")
LIVE = PROJECT_PROFILE.artifact(ROOT, "live")
REPORTS = PROJECT_PROFILE.artifact(ROOT, "reports")
WEB_JOB = PROJECT_PROFILE.artifact(ROOT, "web_job")
WEB_LOG = PROJECT_PROFILE.artifact(ROOT, "web_log")
RALPH_CLI = PROJECT_PROFILE.controller_cli(ROOT)
VERSION = "0.4.0"
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
        PROJECT_PROFILE.git_command(*args), cwd=PROJECT_PROFILE.git_worktree(ROOT), text=True, capture_output=True,
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
    if str(job.get("mode") or "background") == "foreground":
        return {**job, "active": bool(job.get("active"))}
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


def controller_runtime_status(state: dict[str, Any]) -> dict[str, Any]:
    """Expose controller-owned runtime identity; Web job metadata is not controller authority."""
    runtime = ralph.controller_runtime_status(state)
    return dict(runtime) if isinstance(runtime, dict) else {"active": False}


def _path_mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def controller_output_lines(job: dict[str, Any], runtime: dict[str, Any]) -> tuple[list[str], str]:
    """Select output for the active controller operation, independent of launch surface."""
    if runtime.get("active"):
        runtime_pid = int(runtime.get("pid") or 0)
        job_pid = int(job.get("pid") or 0) if job.get("active") else 0
        if job_pid and job_pid == runtime_pid and WEB_LOG.exists():
            return _read_lines(WEB_LOG, MAX_LOG_LINES), "web"
        return _read_lines(LIVE, MAX_LOG_LINES), "controller-live"
    if job.get("active") and WEB_LOG.exists():
        return _read_lines(WEB_LOG, MAX_LOG_LINES), "web"
    candidates = [path for path in (LIVE, WEB_LOG) if path.exists()]
    if not candidates:
        return [], "none"
    source = max(candidates, key=_path_mtime)
    return _read_lines(source, MAX_LOG_LINES), "controller-live" if source == LIVE else "web"


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
    gate = {
        "id": f"HG-{loop_no:04d}-{step_no:02d}",
        "step": step_no,
        "title": (step or {}).get("title") or "Human review",
        "block_reason": block,
        "policy_review": policy,
        "test_change_policy": (step or {}).get("test_change_policy") or "none",
        "acceptance": (step or {}).get("acceptance") or [],
        "recommendation": recommendation,
    }
    candidate = state.get("self_hosting_candidate")
    if (
        block == "Codex attempted to change RALPH controller/tooling authority"
        and isinstance(candidate, dict)
        and str(candidate.get("plan_hash") or "") == str(state.get("plan_hash") or "")
        and int(candidate.get("step") or 0) == step_no
        and str(candidate.get("gate_id") or "") == gate["id"]
        and isinstance(candidate.get("paths"), list)
        and candidate["paths"]
    ):
        authority_block = {
            "kind": "controller_self_hosting_authority",
            "plan_hash": str(state.get("plan_hash") or ""),
            "step": step_no,
            "gate_id": gate["id"],
            "paths": [str(path) for path in candidate["paths"]],
        }
        # This is a bounded echo of controller state, not a web-layer eligibility
        # decision or an authority grant.  Keep the candidate alias for refresh
        # identity compatibility while callers move to the explicit block name.
        gate["authority_block"] = authority_block
        gate["self_hosting_candidate"] = authority_block
    return gate


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
    return {"path": PROJECT_PROFILE.relative_path(ROOT, path), "preview": "\n".join(text.splitlines()[:100])}


def _controller_command(*argv: str) -> list[str]:
    """Build an existing controller invocation from the host-project profile."""
    return [sys.executable, str(PROJECT_PROFILE.controller_cli(ROOT)), *argv]


def _controller_test_reconciliation_candidate(state: dict[str, Any]) -> dict[str, str] | None:
    """Return the controller-derived candidate without Web eligibility filtering."""
    try:
        candidate = ralph.ready_to_commit_test_reconciliation_candidate(state)
    # A partially written or older controller state is not an adoption
    # candidate.  Fail closed at this display/dispatch boundary rather than
    # exposing an action or failing the snapshot while the controller state is
    # being refreshed.
    except (KeyError, OSError, RuntimeError, TypeError, ValueError):
        return None
    if not isinstance(candidate, dict):
        return None
    path = str(candidate.get("path") or "").strip()
    if not path:
        return None
    return {
        "path": path,
        "delta_kind": str(candidate.get("delta_kind") or "").strip(),
    }


def _test_reconciliation_snapshot(state: dict[str, Any]) -> dict[str, Any]:
    # READY_TO_COMMIT is controller state.  The controller helper below remains
    # the sole authority for whether that state has an adoption candidate.
    if str(state.get("status") or "") != "READY_TO_COMMIT":
        return {"eligible": False}
    candidate = _controller_test_reconciliation_candidate(state)
    if candidate is None:
        return {"eligible": False}
    return {"eligible": True, **candidate}


def _carry_forward_snapshot(state: dict[str, Any]) -> dict[str, Any]:
    """Expose only the controller's current reconciliation diagnosis.

    A malformed, stale, or otherwise refused state is useful operator feedback,
    but is never converted into a client-selectable reconciliation target.
    """
    if not str(state.get("retirement_record_id") or "").strip():
        return {"replacement": False}
    try:
        value = ralph.reconciliation_snapshot(state)
    except (KeyError, OSError, RuntimeError, TypeError, ValueError) as exc:
        return {"replacement": True, "controller_refusal": str(exc), "candidates": []}
    if not isinstance(value, dict):
        return {"replacement": True, "controller_refusal": "controller returned an invalid reconciliation snapshot", "candidates": []}
    return value


def _latest_retirement(state: dict[str, Any]) -> dict[str, Any] | None:
    """Return the most recent controller-retired record without accepting an ID from the client."""
    records = state.get("retired_plans")
    if not isinstance(records, list) or not records or not isinstance(records[-1], dict):
        return None
    record = records[-1]
    record_id = str(record.get("record_id") or "").strip()
    if not record_id:
        return None
    return {
        "record_id": record_id,
        "disposition": str(record.get("disposition") or ""),
        "manifest_sha256": str(record.get("manifest_sha256") or ""),
        "retired_at": str(record.get("retired_at") or ""),
    }


def _pending_carry_forward_candidate(state: dict[str, Any], requested_path: object) -> dict[str, Any]:
    """Require an exact current controller candidate; do not normalize client paths."""
    path = str(requested_path or "").strip()
    snapshot = _carry_forward_snapshot(state)
    if snapshot.get("controller_refusal"):
        raise WebConsoleError(f"controller refused reconciliation state: {snapshot['controller_refusal']}")
    for candidate in snapshot.get("candidates") or []:
        if (
            isinstance(candidate, dict)
            and candidate.get("path") == path
            and candidate.get("eligible") is True
            and candidate.get("disposition") == "PENDING_RECONCILIATION"
        ):
            return candidate
    raise WebConsoleError("selected path is not an exact pending controller reconciliation candidate")


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
    policy = efficiency_policy.load_policy(ROOT, **_project_policy_kwargs())
    model_selection = model_policy.load_policy(ROOT, **_project_policy_kwargs())
    plan = state.get("plan") if isinstance(state.get("plan"), dict) else {}
    steering = state.get("human_steering") if isinstance(state.get("human_steering"), list) else []
    job = web_job_status()
    runtime = controller_runtime_status(state)
    controller_output, controller_output_source = controller_output_lines(job, runtime)
    durable_status = str(state.get("status") or "IDLE")
    return {
        "schema": "zen_ralph_web_snapshot_v1",
        "version": VERSION,
        "project": PROJECT_PROFILE.project_metadata(ROOT),
        "controller": {
            "status": durable_status,
            "durable_status": durable_status,
            "plan_hash": state.get("plan_hash"),
            "current_step": int(state.get("current_step") or 0),
            "step_count": len(plan.get("steps") or []),
            "loop_count": int(state.get("loop_count") or 0),
            "block_reason": state.get("block_reason"),
            "efficiency": str(efficiency.get("status") or "-"),
            "efficiency_mode": str(policy.get("mode") or "NORMAL"),
            "efficiency_recommendation": state.get("efficiency_recommendation"),
            "usage_admitted": bool((state.get("usage_admission") or {}).get("admitted")) if isinstance(state.get("usage_admission"), dict) else False,
            "usage_admission_remaining": (state.get("usage_admission") or {}).get("remaining_percent_at_admission") if isinstance(state.get("usage_admission"), dict) else None,
            "quota_remaining_percent": remaining,
            "recovery_checkpoint": state.get("recovery_checkpoint"),
            "pending_current_step_paths": sorted(
                ralph._pending_step_paths(state, int(state.get("current_step") or 0))
            )[:120],
            "interrupted_run_recovery": (
                {
                    "action": str((state.get("interrupted_run_recovery") or {}).get("action") or ""),
                    "loop": (state.get("interrupted_run_recovery") or {}).get("loop"),
                    "checkpoint": (state.get("interrupted_run_recovery") or {}).get("checkpoint"),
                    "sha256": str((state.get("interrupted_run_recovery") or {}).get("sha256") or ""),
                }
                if isinstance(state.get("interrupted_run_recovery"), dict)
                else None
            ),
            "rollback_preview": (
                {
                    "sha256": str((state.get("retirement_rollback_preview") or {}).get("sha256") or ""),
                    "checkpoint": (state.get("retirement_rollback_preview") or {}).get("checkpoint"),
                    "reason": (state.get("retirement_rollback_preview") or {}).get("reason"),
                }
                if isinstance(state.get("retirement_rollback_preview"), dict)
                and str((state.get("retirement_rollback_preview") or {}).get("plan_hash") or "") == str(state.get("plan_hash") or "")
                else None
            ),
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
        "efficiency_policy": policy,
        "efficiency_defaults": efficiency_policy.defaults(),
        "model_policy": model_selection,
        "gate": _gate_snapshot(state),
        "test_reconciliation": _test_reconciliation_snapshot(state),
        "reconciliation": _carry_forward_snapshot(state),
        "latest_retirement": _latest_retirement(state),
        "usage": {
            "model": usage.get("model"),
            "plan_type": usage.get("plan_type"),
            "available_reset_credits": usage.get("available_reset_credits"),
            "reset_credits": usage.get("reset_credits") or [],
            "model_catalog": live_report.get("model_catalog") or {},
            "model_catalog_error": live_report.get("model_catalog_error"),
            "captured_at": usage.get("captured_at"),
            "guard": live_report.get("guard") or ("UNKNOWN" if not windows else "-"),
            "refresh_error": live_report.get("live_limit_error"),
            "current_plan": ledger.get("current_plan") or {},
            "current_plan_source": ledger.get("current_plan_source") or "ledger",
            "windows": ledger.get("windows") or windows,
            "plans": ledger.get("plans") or [],
            "ledger_rows": int(ledger.get("ledger_rows") or 0),
            "last_event_at": ledger.get("last_event_at"),
            "stats_reset": ledger.get("stats_reset"),
        },
        "git": git_snapshot(),
        "job": job,
        "runtime": runtime,
        "web_activity": str(job.get("activity") or "") if job.get("active") else None,
        "report": _latest_report(state),
        "events": event_tail(),
        "live_log": controller_output,
        "controller_output_source": controller_output_source,
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
        command = _controller_command("usage", "--json", "--no-save", "--include-reset-details")
        try:
            result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=25, check=False)
            report = json.loads(result.stdout) if result.stdout.strip() else {}
            if not isinstance(report, dict):
                raise ValueError("usage command returned a non-object")
            error = str(report.get("live_limit_error") or "").strip() or None
            try:
                model_result = subprocess.run(
                    _controller_command("models", "--json"), cwd=ROOT, text=True,
                    capture_output=True, timeout=20, check=False,
                )
                catalog = json.loads(model_result.stdout) if model_result.stdout.strip() else {}
                if isinstance(catalog, dict) and catalog.get("models") is not None:
                    report["model_catalog"] = catalog
                elif model_result.returncode != 0:
                    report["model_catalog_error"] = model_result.stderr.strip() or "model catalog unavailable"
            except (OSError, subprocess.SubprocessError, json.JSONDecodeError, ValueError) as model_exc:
                report["model_catalog_error"] = str(model_exc)
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
    activity: str | None = None
    allow_while_active: bool = False
    track_job: bool = True




def _proposal_bounds(payload: dict[str, Any]) -> tuple[int, int]:
    try:
        minimum = int(payload.get("min_steps", 5))
        maximum = int(payload.get("max_steps", 10))
    except (TypeError, ValueError) as exc:
        raise WebConsoleError("plan step bounds must be integers") from exc
    if minimum < 1:
        raise WebConsoleError("minimum plan steps must be at least 1")
    if maximum < minimum:
        raise WebConsoleError("maximum plan steps must be greater than or equal to minimum plan steps")
    if maximum > 20:
        raise WebConsoleError("maximum plan steps must not exceed 20")
    return minimum, maximum

def _repository_authority(payload: dict[str, Any]) -> str:
    authority = str(payload.get("repository_authority") or "").strip()
    if authority not in ralph.REPOSITORY_AUTHORITIES:
        raise WebConsoleError("repository_authority must be read-only or write")
    return authority


def command_for_action(payload: dict[str, Any], state: dict[str, Any]) -> CommandRequest:
    action = str(payload.get("action") or "").strip()
    # The active controller snapshot is authoritative; never let the client
    # select a different plan context for a command.
    plan_hash = str(state.get("plan_hash") or "").strip()
    status = str(state.get("status") or "IDLE")

    def reason() -> str:
        value = " ".join(str(payload.get("reason") or "").split())
        if not value:
            raise WebConsoleError("reason is required")
        return value

    if action == "propose":
        goal = str(payload.get("goal") or "").strip()
        if status not in {"IDLE", "PLAN_COMPLETE", "PUSHED", "READ_ONLY_COMPLETE"}:
            raise WebConsoleError(f"cannot propose while status={status}")
        if len(goal) < 20:
            raise WebConsoleError("proposal goal must be at least 20 characters")
        authority = _repository_authority(payload)
        argv = ["propose", "--goal", goal, "--repository-authority", authority]
        if "min_steps" in payload or "max_steps" in payload:
            minimum, maximum = _proposal_bounds(payload)
            argv += ["--min-steps", str(minimum), "--max-steps", str(maximum)]
        return CommandRequest(argv, background=True, activity="PLANNING")
    if action == "efficiency_update":
        settings = payload.get("settings")
        if not isinstance(settings, dict):
            raise WebConsoleError("efficiency settings object is required")
        argv = ["efficiency-policy", "set"]
        fields = [("mode", "--mode"), ("reserve_percent", "--reserve-percent")]
        for prefix in ("strict", "normal", "relaxed"):
            fields.extend([
                (f"{prefix}_prompt_command_budget", f"--{prefix}-prompt-command-budget"),
                (f"{prefix}_max_commands", f"--{prefix}-max-commands"),
                (f"{prefix}_max_reported_files", f"--{prefix}-max-reported-files"),
                (f"{prefix}_max_cumulative_input", f"--{prefix}-max-cumulative-input"),
                (f"{prefix}_max_noncached_input", f"--{prefix}-max-noncached-input"),
            ])
        fields.extend([
            ("runaway_max_commands", "--runaway-max-commands"),
            ("runaway_max_reported_files", "--runaway-max-reported-files"),
            ("runaway_max_cumulative_input", "--runaway-max-cumulative-input"),
            ("runaway_max_noncached_input", "--runaway-max-noncached-input"),
        ])
        supplied = 0
        for key, flag in fields:
            if key not in settings:
                continue
            value = settings[key]
            if value is None or str(value).strip() == "":
                continue
            argv += [flag, str(value).lower() if key == "mode" else str(value)]
            supplied += 1
        if not supplied:
            raise WebConsoleError("at least one efficiency setting is required")
        return CommandRequest(argv, activity="EFFICIENCY_UPDATE", allow_while_active=True, track_job=False)
    if action == "efficiency_reset_mode":
        return CommandRequest(["efficiency-policy", "reset-mode"], activity="EFFICIENCY_RESET", allow_while_active=True, track_job=False)
    if action == "efficiency_reset_all":
        return CommandRequest(["efficiency-policy", "reset"], activity="EFFICIENCY_RESET", allow_while_active=True, track_job=False)
    if action == "model_update":
        model = str(payload.get("model") or "").strip()
        if not model:
            raise WebConsoleError("model is required")
        return CommandRequest(["model-policy", "set", "--model", model], activity="MODEL_UPDATE", allow_while_active=True, track_job=False)
    if action == "model_reset":
        return CommandRequest(["model-policy", "reset"], activity="MODEL_UPDATE", allow_while_active=True, track_job=False)
    if action == "effort_update":
        effort = str(payload.get("effort") or "").strip().lower()
        if not effort:
            raise WebConsoleError("reasoning effort is required")
        return CommandRequest(["model-policy", "set-effort", "--effort", effort], activity="MODEL_UPDATE", allow_while_active=True, track_job=False)
    if action == "effort_reset":
        return CommandRequest(["model-policy", "reset-effort"], activity="MODEL_UPDATE", allow_while_active=True, track_job=False)
    if action == "redeem_reset":
        if str(payload.get("confirm") or "") != "REDEEM":
            raise WebConsoleError("banked reset redemption requires confirm=REDEEM")
        credit_id = str(payload.get("credit_id") or "").strip()
        argv = ["redeem-reset", "--confirm", "REDEEM", "--json"]
        if credit_id:
            argv += ["--credit-id", credit_id]
        return CommandRequest(argv, activity="REDEEMING_RESET", allow_while_active=True, track_job=False)
    if action == "usage_reset_stats":
        if str(payload.get("confirm") or "") != "RESET":
            raise WebConsoleError("token-stat reset requires confirm=RESET")
        return CommandRequest(["usage-reset-stats", "--confirm", "RESET", "--json"], activity="USAGE_STATS_RESET", allow_while_active=True, track_job=False)
    if not plan_hash and action != "propose_replacement":
        raise WebConsoleError("active plan hash is required")
    if action == "approve":
        return CommandRequest(["approve", plan_hash], activity="APPROVING")
    if action == "reject":
        return CommandRequest(["reject", plan_hash, "--reason", reason()], activity="REJECTING")
    if action == "run":
        max_loops = int(payload.get("max_loops") or 40)
        max_loops = max(1, min(max_loops, 40))
        argv = ["run", "--color", "never", "--max-loops", str(max_loops)]
        if payload.get("efficiency_mode") is not None:
            mode = str(payload.get("efficiency_mode") or "").strip().lower()
            if mode not in {"strict", "normal", "relaxed", "off"}:
                raise WebConsoleError("efficiency_mode must be strict, normal, relaxed, or off")
            argv += ["--efficiency-mode", mode]
        return CommandRequest(argv, background=True, activity="RUNNING")
    if action == "recover_interrupted_run":
        if status not in {"RUNNING", "BLOCKED_HUMAN"}:
            raise WebConsoleError("interrupted-run recovery requires RUNNING or BLOCKED_HUMAN")
        checkpoint = str(state.get("recovery_checkpoint") or "").strip()
        if not checkpoint:
            raise WebConsoleError("interrupted-run recovery requires the active recovery checkpoint")
        if str(payload.get("confirm") or "") != "RECOVER":
            raise WebConsoleError("interrupted-run recovery requires confirm=RECOVER")
        if status == "BLOCKED_HUMAN":
            block_reason = str(state.get("block_reason") or "")
            if not (block_reason.startswith("controller interrupted:") or block_reason.startswith("controller runtime exception:")):
                raise WebConsoleError("current human block is not an interrupted controller run")
        supplied = payload.get("pending_paths") or []
        if not isinstance(supplied, list):
            raise WebConsoleError("pending_paths must be a list")
        supplied_paths = [str(path).strip() for path in supplied if str(path).strip()]
        expected_paths = sorted(ralph._pending_step_paths(state, int(state.get("current_step") or 0)))
        if len(set(supplied_paths)) != len(supplied_paths) or sorted(supplied_paths) != expected_paths:
            raise WebConsoleError("interrupted-run recovery requires the exact controller pending paths")
        argv = ["recover-interrupted-run", plan_hash, "--checkpoint", checkpoint]
        for path in expected_paths:
            argv += ["--pending-path", path]
        argv += ["--confirm", "RECOVER"]
        return CommandRequest(argv, activity="RECOVERING")
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
        return CommandRequest(argv, activity="STEERING")
    if action == "resume":
        return CommandRequest(["resume", plan_hash, "--reason", reason()], activity="RESUMING")
    if action == "resolve_gate":
        gate = str(payload.get("gate") or "").strip()
        if not gate:
            raise WebConsoleError("gate is required")
        return CommandRequest(["resolve-gate", plan_hash, "--gate", gate, "--reason", reason()], activity="RESOLVING")
    if action == "authorize_self_hosting":
        # This action is bound exclusively to the state snapshot that the
        # authenticated /api/action handler just reread.  In particular, do
        # not allow a caller-supplied plan hash to select its authorization
        # context.
        controller_plan_hash = str(state.get("plan_hash") or "").strip()
        if not controller_plan_hash:
            raise WebConsoleError("active controller plan hash is required")
        if status != "BLOCKED_HUMAN":
            raise WebConsoleError("self-hosting authorization requires BLOCKED_HUMAN")
        if str(state.get("block_reason") or "") != "Codex attempted to change RALPH controller/tooling authority":
            raise WebConsoleError("current block is not a RALPH tooling authority gate")
        step_no = int(state.get("current_step") or 0)
        gate = str(payload.get("gate") or "").strip()
        expected_gate = f"HG-{int(state.get('loop_count') or 0):04d}-{step_no:02d}"
        if gate != expected_gate:
            raise WebConsoleError(f"self-hosting gate does not match current gate {expected_gate}")
        candidate = state.get("self_hosting_candidate") if isinstance(state.get("self_hosting_candidate"), dict) else {}
        candidate_paths = sorted({str(path).strip() for path in candidate.get("paths") or [] if str(path).strip()})
        if (
            str(candidate.get("plan_hash") or "") != controller_plan_hash
            or int(candidate.get("step") or 0) != step_no
            or str(candidate.get("gate_id") or "") != expected_gate
            or not candidate_paths
        ):
            raise WebConsoleError("controller self-hosting candidate is missing or stale")
        requested = sorted({str(path).strip() for path in payload.get("paths") or [] if str(path).strip()})
        if requested != candidate_paths:
            raise WebConsoleError("selected paths must exactly match the controller self-hosting candidate")
        argv = ["authorize-self-hosting", controller_plan_hash, "--gate", expected_gate]
        for path in candidate_paths:
            argv += ["--path", path]
        argv += ["--reason", reason()]
        return CommandRequest(argv, activity="AUTHORIZING")
    if action == "retire":
        mode = str(payload.get("mode") or "").strip()
        if mode not in {"rollback-preview", "rollback", "carry-forward"}:
            raise WebConsoleError("retire mode must be rollback or carry-forward")
        if mode == "rollback-preview":
            return CommandRequest(
                ["retire-plan", plan_hash, "--reason", reason(), "--rollback"],
                activity="INSPECTING_RECONCILIATION",
            )
        expected_confirm = "ROLLBACK" if mode == "rollback" else "CARRY_FORWARD"
        if str(payload.get("confirm") or "") != expected_confirm:
            raise WebConsoleError(f"retire {mode} requires confirm={expected_confirm}")
        argv = ["retire-plan", plan_hash, "--reason", reason(), f"--{mode}"]
        if mode == "rollback":
            preview = state.get("retirement_rollback_preview") if isinstance(state.get("retirement_rollback_preview"), dict) else {}
            preview_sha = str(payload.get("preview_sha") or "").strip()
            expected_preview = str(preview.get("sha256") or "").strip()
            if not expected_preview or preview_sha != expected_preview:
                raise WebConsoleError("retire rollback requires the exact current controller rollback preview SHA")
            argv += ["--preview-sha", expected_preview, "--confirm", "ROLLBACK"]
        return CommandRequest(argv, confirm=expected_confirm, activity="RETIRING")
    if action == "propose_replacement":
        if status != "IDLE":
            raise WebConsoleError("replacement proposal requires IDLE")
        retirement = _latest_retirement(state)
        requested_id = str(payload.get("retirement_record_id") or "").strip()
        if retirement is None or requested_id != retirement["record_id"]:
            raise WebConsoleError("retirement record must exactly match the latest controller retirement")
        if retirement["disposition"] != "RETIRED_WITH_CARRY_FORWARD":
            raise WebConsoleError("latest controller retirement is not eligible for a carry-forward replacement")
        goal = str(payload.get("goal") or "").strip()
        authority = _repository_authority(payload)
        argv = ["propose", "--from-retirement", retirement["record_id"], "--repository-authority", authority]
        if "min_steps" in payload or "max_steps" in payload:
            minimum, maximum = _proposal_bounds(payload)
            argv += ["--min-steps", str(minimum), "--max-steps", str(maximum)]
        if goal:
            argv += ["--goal", goal]
        return CommandRequest(argv, background=True, activity="PLANNING")
    if action == "inspect_carry_forward":
        if status != "APPROVED":
            raise WebConsoleError("inspect-carry-forward requires APPROVED")
        snapshot = _carry_forward_snapshot(state)
        if snapshot.get("controller_refusal"):
            raise WebConsoleError(f"controller refused reconciliation state: {snapshot['controller_refusal']}")
        if snapshot.get("replacement") is not True:
            raise WebConsoleError("no controller replacement reconciliation is active")
        return CommandRequest(["inspect-carry-forward", plan_hash], activity="INSPECTING_RECONCILIATION")
    if action in {"adopt_carry_forward", "leave_carry_forward_outside", "reject_carry_forward"}:
        if status != "APPROVED":
            raise WebConsoleError(f"{action} requires APPROVED")
        candidate = _pending_carry_forward_candidate(state, payload.get("path"))
        try:
            step = int(payload.get("step"))
        except (TypeError, ValueError):
            raise WebConsoleError("controller claiming step is required") from None
        if action == "adopt_carry_forward":
            if str(payload.get("confirm") or "") != "ADOPT":
                raise WebConsoleError("adopt-carry-forward requires confirm=ADOPT")
            return CommandRequest(
                ["adopt-carry-forward", plan_hash, "--path", candidate["path"], "--step", str(step),
                 "--ownership-basis", "retired-unchanged-content", "--confirm", "ADOPT"],
                confirm="ADOPT", activity="RECONCILING",
            )
        command = "leave-carry-forward-outside" if action == "leave_carry_forward_outside" else "reject-carry-forward"
        return CommandRequest(
            [command, plan_hash, "--path", candidate["path"], "--step", str(step), "--reason", reason()],
            activity="RECONCILING",
        )
    if action == "report":
        return CommandRequest(["report", plan_hash], activity="REPORTING")
    if action == "requalify":
        if status != "READY_TO_COMMIT":
            raise WebConsoleError("requalify requires READY_TO_COMMIT")
        return CommandRequest(["requalify", plan_hash], background=True, activity="QUALIFYING")
    if action == "reconcile_ready_test":
        if status != "READY_TO_COMMIT":
            raise WebConsoleError("reconcile-ready-test requires READY_TO_COMMIT")
        if str(payload.get("confirm") or "") != "ADOPT":
            raise WebConsoleError("reconcile-ready-test requires confirm=ADOPT")
        candidate = _controller_test_reconciliation_candidate(state)
        if candidate is None:
            raise WebConsoleError("no eligible controller test-reconciliation candidate")
        # The displayed path is not an API authority input.  The browser does
        # not submit it; if an older client echoes one, it can only act as a
        # stale-display check and can never replace the current controller
        # candidate used below.
        requested_path = str(payload.get("path") or "").strip()
        if requested_path and requested_path != candidate["path"]:
            raise WebConsoleError("selected path must exactly match the controller candidate")
        return CommandRequest(
            ["adopt-test-reconciliation", plan_hash, "--path", candidate["path"],
             "--confirm", "ADOPT", "--reason", reason()],
            confirm="ADOPT", activity="RECONCILING",
        )
    if action == "finalize_review":
        if status != "READY_TO_COMMIT":
            raise WebConsoleError("finalization review requires READY_TO_COMMIT")
        return CommandRequest(["finalize", plan_hash], activity="REVIEWING")
    if action == "finalize_commit":
        if status != "READY_TO_COMMIT":
            raise WebConsoleError("commit requires READY_TO_COMMIT")
        if str(payload.get("confirm") or "") != "COMMIT":
            raise WebConsoleError("commit requires confirm=COMMIT")
        argv = ["finalize", plan_hash, "--commit"]
        message = " ".join(str(payload.get("message") or "").split())
        if message:
            argv += ["--message", message]
        return CommandRequest(argv, confirm="COMMIT", activity="COMMITTING")
    if action == "finalize_push":
        if status != "COMMITTED":
            raise WebConsoleError("push requires COMMITTED")
        if str(payload.get("confirm") or "") != "PUSH":
            raise WebConsoleError("push requires confirm=PUSH")
        return CommandRequest(["finalize", plan_hash, "--push"], confirm="PUSH", activity="PUSHING")
    raise WebConsoleError(f"unsupported action: {action or '-'}")


def _write_web_job(job: dict[str, Any]) -> None:
    RALPH.mkdir(parents=True, exist_ok=True)
    WEB_JOB.write_text(json.dumps(job, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_command(request: CommandRequest) -> dict[str, Any]:
    command = _controller_command(*request.argv)
    current = web_job_status()
    state = _read_json(STATE, {})
    runtime = controller_runtime_status(state if isinstance(state, dict) else {})
    if runtime.get("active") and not request.allow_while_active:
        raise WebConsoleError(
            f"Ralph controller runtime already active ({runtime.get('command') or 'controller'} pid {runtime.get('pid')})"
        )
    if current.get("active") and not request.allow_while_active:
        raise WebConsoleError(f"Ralph action already active ({current.get('activity') or 'RUNNING'})")
    started = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    activity = str(request.activity or "WORKING")
    if request.background:
        RALPH.mkdir(parents=True, exist_ok=True)
        log_handle = WEB_LOG.open("a", encoding="utf-8")
        log_handle.write(f"\n=== WEB JOB {started} :: {' '.join(request.argv[:3])} ===\n")
        log_handle.flush()
        proc = subprocess.Popen(
            command, cwd=ROOT, stdout=log_handle, stderr=subprocess.STDOUT,
            text=True, start_new_session=True,
        )
        job = {
            "active": True,
            "mode": "background",
            "pid": proc.pid,
            "argv": request.argv,
            "activity": activity,
            "started_at": started,
        }
        _write_web_job(job)
        log_handle.close()
        return {"ok": True, "background": True, "pid": proc.pid, "argv": request.argv, "activity": activity}

    job = {
        "active": True,
        "mode": "foreground",
        "pid": os.getpid(),
        "argv": request.argv,
        "activity": activity,
        "started_at": started,
    }
    if request.track_job:
        _write_web_job(job)
    try:
        result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=60, check=False)
    finally:
        if request.track_job:
            finished = dict(job)
            finished["active"] = False
            finished["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
            _write_web_job(finished)
    return {
        "ok": result.returncode == 0,
        "background": False,
        "returncode": result.returncode,
        "stdout": result.stdout[-12000:],
        "stderr": result.stderr[-8000:],
        "argv": request.argv,
        "activity": activity,
    }


PAGE = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>__PROJECT_WEB_TITLE__</title>
<style>
:root{color-scheme:dark;--bg:#081018;--panel:#101b26;--panel2:#0c151e;--text:#dce7f2;--muted:#8495a7;--green:#5ee19a;--yellow:#f4ca64;--red:#ff6b73;--blue:#6ab7ff;--cyan:#61d7e6;--magenta:#c98aff;--line:#263647;--shadow:0 10px 28px rgba(0,0,0,.28)}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace}.wrap{width:min(100%,2400px);max-width:2400px;margin:auto;padding:14px 22px}.top{display:grid;grid-template-columns:1fr auto;gap:14px;align-items:center;margin-bottom:12px}.brand{font-size:22px;font-weight:800}.sub{color:var(--muted)}.badge{display:inline-block;padding:4px 8px;border:1px solid var(--line);border-radius:999px;margin:2px}.ok{color:var(--green)}.warn{color:var(--yellow)}.bad{color:var(--red)}.info{color:var(--cyan)}.grid{display:grid;grid-template-columns:repeat(12,minmax(0,1fr));gap:10px}.card{background:linear-gradient(180deg,var(--panel),var(--panel2));border:1px solid var(--line);border-radius:12px;padding:12px;box-shadow:var(--shadow);min-width:0}.span3{grid-column:span 3}.span4{grid-column:span 4}.span5{grid-column:span 5}.span6{grid-column:span 6}.span7{grid-column:span 7}.span8{grid-column:span 8}.span9{grid-column:span 9}.span12{grid-column:span 12}h2{font-size:13px;letter-spacing:.08em;text-transform:uppercase;color:var(--cyan);margin:0 0 9px}h3{font-size:14px;margin:8px 0 5px}.metric{font-size:27px;font-weight:800}.kv{display:grid;grid-template-columns:max-content 1fr;gap:4px 12px}.kv>div:nth-child(odd){color:var(--muted)}.usage-grid{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:6px}.usage-box{background:#08131d;border:1px solid var(--line);border-radius:8px;padding:7px 8px;min-width:0}.usage-value{font-size:18px;font-weight:800;line-height:1.15}.usage-window .usage-value{font-size:16px}.usage-windows{display:none}.plan-usage{display:grid;gap:1px;margin-top:4px}.usage-row{display:grid;grid-template-columns:110px 90px minmax(230px,280px) minmax(0,1fr);gap:6px;padding:3px 6px;background:#08131d;border-radius:4px;align-items:start}.usage-row>span:first-child{font-weight:700}.usage-tokens{white-space:nowrap;min-width:0}.plan-comment{min-width:0}.plan-comment summary{cursor:pointer;color:var(--muted);display:-webkit-box;-webkit-box-orient:vertical;-webkit-line-clamp:2;line-clamp:2;line-height:1.35;max-height:2.7em;white-space:normal;overflow:hidden;list-style:none}.plan-comment summary::-webkit-details-marker{display:none}.plan-comment summary::before{content:'▸ ';color:var(--cyan)}.plan-comment[open] summary::before{content:'▾ '}.plan-comment-body{max-height:90px;overflow:auto;margin-top:4px;padding:5px 7px;background:#071019;border:1px solid var(--line);border-radius:5px;color:var(--text)}.section-title-row{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:9px}.section-title-row h2{margin:0}.view-toggle{display:flex;gap:4px;flex-wrap:wrap}.view-toggle button{min-height:30px;padding:4px 9px;font-size:12px}.view-toggle button.active{border-color:var(--cyan);color:var(--cyan);background:#102836}.markdown-report{background:#071019;border:1px solid var(--line);border-radius:8px;padding:12px;max-height:520px;overflow:auto}.markdown-report>*:first-child{margin-top:0}.markdown-report>*:last-child{margin-bottom:0}.markdown-report h1,.markdown-report h2,.markdown-report h3,.markdown-report h4,.markdown-report h5,.markdown-report h6{letter-spacing:normal;text-transform:none;color:var(--text);margin:14px 0 6px}.markdown-report h1{font-size:22px}.markdown-report h2{font-size:18px}.markdown-report h3{font-size:16px}.markdown-report p{margin:6px 0}.markdown-report ul,.markdown-report ol{margin:6px 0 6px 22px;padding:0}.markdown-report li{margin:2px 0}.markdown-report blockquote{margin:7px 0;padding:5px 10px;border-left:3px solid var(--cyan);background:#09141e;color:var(--muted)}.markdown-report code{background:#10202e;border:1px solid #263b4d;border-radius:4px;padding:1px 4px}.markdown-report pre.md-code{max-height:320px;margin:8px 0}.markdown-report pre.md-code code{background:transparent;border:0;padding:0}.markdown-report hr{border:0;border-top:1px solid var(--line);margin:10px 0}.report-path{margin-top:6px}.steps{display:grid;gap:6px}.step{border-left:3px solid var(--line);padding:7px 9px;background:#0a131c}.step.PASS,.step.ACCEPTED,.step.HUMAN_CONFIRMED{border-color:var(--green)}.step.CURRENT{border-color:var(--cyan)}.step.PENDING{border-color:#39495a}.step-title{font-weight:700}.small{font-size:12px;color:var(--muted)}pre{white-space:pre-wrap;word-break:break-word;background:#071019;border:1px solid var(--line);border-radius:8px;padding:9px;max-height:460px;overflow:auto;margin:0}.events{height:600px;overflow:auto;border:1px solid var(--line);border-radius:8px;background:#071019}.event{padding:5px 9px;border-bottom:1px solid #132131}.READ{color:var(--blue)}.EDIT,.WARN,.POLICY{color:var(--yellow)}.CREATE,.PASS,.COMPLETE,.READY{color:var(--green)}.DELETE,.FAIL,.ERROR,.ENV{color:var(--red)}.BLOCKED,.STEER,.GATE-HUMAN{color:var(--magenta)}.RUN,.CMD,.COMMAND,.GATE,.VALIDATE,.CHECKPOINT,.USAGE{color:var(--cyan)}button{font:inherit;background:#172535;color:var(--text);border:1px solid #395069;border-radius:7px;padding:8px 11px;cursor:pointer;min-height:38px}button:hover{border-color:var(--cyan)}button.danger{border-color:#7a3138;color:#ff9ba1}button.good{border-color:#2d7350;color:#8bf0b7}input,textarea,select{width:100%;font:inherit;background:#071019;color:var(--text);border:1px solid var(--line);border-radius:7px;padding:8px}textarea{min-height:90px}.efficiency-controls{display:grid;gap:10px}.efficiency-groups{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}.eff-group{background:#08131d;border:1px solid var(--line);border-radius:8px;padding:9px}.eff-group h3{color:var(--cyan);margin-top:0}.eff-field{display:grid;grid-template-columns:minmax(0,1fr) 38px;gap:5px;align-items:end;margin:7px 0}.eff-field.no-reset{grid-template-columns:1fr}.eff-field label{display:block;color:var(--muted);font-size:12px;margin-bottom:3px}.icon-btn{width:38px;min-width:38px;min-height:36px;padding:5px;font-size:17px;line-height:1}.eff-actions{display:flex;gap:7px;align-items:center;flex-wrap:wrap}.eff-actions button{width:auto}.eff-note{padding:7px 9px;background:#09141e;border-left:3px solid var(--cyan);font-size:12px;color:var(--muted)}.compact-actions{display:flex;gap:6px;align-items:center;flex-wrap:wrap}.compact-actions select{width:auto;min-width:190px;padding:5px 7px}.compact-actions button{min-height:31px;padding:5px 9px;font-size:12px}.top-actions{display:flex;gap:8px;align-items:stretch;justify-content:flex-end;flex-wrap:nowrap}.top-actions select{width:100%;min-width:190px;max-width:280px;padding:4px 7px}.top-actions button{min-height:31px;padding:5px 9px;font-size:12px}.top-model-controls{display:grid;grid-template-columns:minmax(235px,310px);gap:4px;align-content:center}.top-choice-field{display:grid;grid-template-columns:44px minmax(0,1fr);gap:5px;align-items:center}.top-choice-field label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}.top-choice-control{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:4px;align-items:center}.top-choice-control select{min-width:0;max-width:none}.top-choice-control .inline-reset{flex:0 0 auto}.top-runtime-stack{display:grid;gap:4px;align-content:center;justify-items:stretch;min-width:88px}.top-runtime-stack .badge{margin:0;text-align:center;white-space:nowrap}.top-actions>.danger-solid,.top-actions>.top-logout{align-self:stretch;white-space:nowrap}.top-logout{margin-left:0}.sparkle{position:relative;border-color:var(--cyan)!important;color:#bff7ff!important;box-shadow:0 0 0 1px rgba(97,215,230,.2),0 0 12px rgba(201,138,255,.22);animation:sparklePulse 1.8s ease-in-out infinite}.sparkle:before{content:'✦';margin-right:5px;color:#fff}.sparkle:after{content:'';position:absolute;inset:-2px;border-radius:8px;border:1px solid transparent;background:linear-gradient(90deg,transparent,#fff,transparent) border-box;mask:linear-gradient(#000 0 0) padding-box,linear-gradient(#000 0 0);mask-composite:exclude;animation:sparkleSweep 2.4s linear infinite;pointer-events:none}@keyframes sparklePulse{50%{box-shadow:0 0 0 1px rgba(97,215,230,.5),0 0 18px rgba(201,138,255,.45)}}@keyframes sparkleSweep{0%{opacity:.15}50%{opacity:1}100%{opacity:.15}}.danger-solid{background:#42161a!important;border-color:#a13c45!important;color:#ffd6d8!important}.plan-usage{display:grid;gap:4px;margin-top:4px}.plan-usage-head,.plan-usage-summary{display:grid;grid-template-columns:96px 72px 72px 120px 82px minmax(0,1fr);gap:9px;align-items:center}.plan-usage-head{padding:2px 8px 2px 28px;color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.05em}.plan-usage details.plan-usage-detail{background:#08131d;border:1px solid #172637;border-radius:7px;overflow:hidden}.plan-usage details.plan-usage-detail[open]{border-color:var(--line)}.plan-usage-summary{position:relative;padding:6px 8px 6px 28px;cursor:pointer;list-style:none;min-height:32px}.plan-usage-summary::-webkit-details-marker{display:none}.plan-usage-summary:before{content:'▸';position:absolute;left:9px;top:50%;transform:translateY(-50%);color:var(--cyan)}.plan-usage-detail[open]>.plan-usage-summary:before{content:'▾'}.plan-usage-summary .plan-hash{font-weight:700;white-space:nowrap}.plan-usage-summary .plan-number{white-space:nowrap}.plan-usage-summary .plan-goal{min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:var(--text)}.plan-usage-meta{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:5px;padding:7px 9px 9px;border-top:1px solid #162434}.plan-mini{background:#071019;border:1px solid var(--line);border-radius:5px;padding:5px 7px;min-width:0}.plan-breakdown{grid-column:1/-1;display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:6px}.plan-breakdown table{width:100%;border-collapse:collapse;font-size:11px}.plan-breakdown td{padding:2px 4px;border-bottom:1px solid #162434}.plan-breakdown td:first-child{max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.plan-breakdown td:last-child{text-align:right;white-space:nowrap}.current-tag{color:var(--green);font-size:11px}.eff-section-head{display:grid;grid-template-columns:auto minmax(0,1fr) auto;gap:10px;align-items:center;margin-bottom:8px}.eff-section-head h2{grid-column:1/2;margin:0;white-space:nowrap}.eff-header-controls{grid-column:2/3;display:flex;align-items:center;gap:7px;flex-wrap:wrap}.eff-section-head #effPolicyState{grid-column:3/4;justify-self:end;margin:0}.eff-header-field{display:flex;align-items:center;gap:5px}.eff-header-field label{color:var(--muted);font-size:11px;white-space:nowrap}.eff-header-field select{width:116px;padding:4px 6px}.eff-header-field input{width:78px;padding:4px 6px}.eff-policy-revision{font-size:11px;color:var(--muted);white-space:nowrap}.eff-policy-meta{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-top:8px;padding:0 2px;color:var(--muted);font-size:11px}.eff-policy-meta .eff-updated{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}#effPolicyState{white-space:nowrap}.eff-toolbar{display:grid;grid-template-columns:1fr;gap:8px;align-items:end}.eff-mode-limits{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:7px}.eff-mode-panel{background:#08131d;border:1px solid var(--line);border-radius:8px;padding:8px}.eff-advanced{border:1px solid var(--line);border-radius:8px;background:#08131d;padding:7px 9px}.eff-advanced>summary{cursor:pointer;color:var(--cyan)}.field-help{cursor:help;color:var(--cyan);font-weight:700}.baseline{font-size:10px;color:#66798b}.disabled-note{padding:8px;color:var(--muted);border:1px dashed var(--line);border-radius:6px}.eff-off [data-mode-limit]{opacity:.45;pointer-events:none}.eff-off [data-mode-limit] input{cursor:not-allowed}.inline-reset{width:28px!important;min-width:28px!important;min-height:28px!important;padding:2px!important;font-size:14px!important}.dirty{color:var(--yellow)}.actions{display:flex;gap:7px;flex-wrap:wrap;margin-top:8px}.form{display:grid;gap:7px}.notice{padding:9px;border-left:3px solid var(--cyan);background:#09141e;margin:8px 0}.gate{border-left-color:var(--magenta)}.errorbox{border-left-color:var(--red)}.file{color:var(--blue)}.criteria{margin:6px 0 0 20px;padding:0}.criteria li{margin:3px 0}.action-result{margin-top:10px;padding:9px;background:#08131d;border:1px solid var(--line);border-radius:8px}.action-result:empty{display:none}.action-result .action-title{font-weight:800;color:var(--green);margin-bottom:5px}.pretty-object{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:3px 10px}.pretty-object>div:nth-child(odd){color:var(--muted)}.footer{margin:12px 0;color:var(--muted);font-size:12px}.human-section-head{display:flex;align-items:center;gap:12px;margin-bottom:7px;flex-wrap:wrap}.human-section-head h2{margin:0}.plan-bound-controls{display:flex;align-items:center;gap:9px;flex-wrap:wrap;margin:0}.plan-bound-field{display:flex;align-items:center;gap:5px;min-width:0}.plan-bound-field label{font-size:11px;color:var(--muted);white-space:nowrap;margin:0}.plan-bound-field input{width:6ch;min-width:6ch;max-width:6ch;padding:5px 4px;text-align:center}
@media(max-width:1150px){.span3{grid-column:span 6}.eff-mode-limits{grid-template-columns:repeat(3,minmax(0,1fr))}.plan-usage-meta{grid-template-columns:repeat(3,minmax(0,1fr))}.plan-breakdown{grid-template-columns:1fr}.span4,.span5,.span6,.span7,.span8,.span9{grid-column:span 12}.efficiency-groups{grid-template-columns:repeat(2,minmax(0,1fr))}.usage-grid{grid-template-columns:repeat(3,minmax(0,1fr))}.usage-row{grid-template-columns:100px 80px minmax(210px,240px) minmax(0,1fr)}.top-actions select{min-width:160px;max-width:230px}}
@media(max-width:720px){body{font-size:13px}.eff-mode-limits,.plan-usage-meta{grid-template-columns:1fr}.plan-usage-head{display:none}.plan-usage-summary{grid-template-columns:76px 62px 62px minmax(0,1fr)}.plan-usage-summary .hide-mobile{display:none}.plan-usage-summary .plan-goal{white-space:nowrap}.efficiency-groups{grid-template-columns:1fr}.wrap{padding:8px}.top{grid-template-columns:1fr;gap:10px;align-items:start}.top-actions{display:grid;grid-template-columns:auto minmax(0,1fr) auto;gap:7px;justify-items:stretch;align-items:center}.top-model-controls{grid-column:1/-1;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;width:100%;align-items:start}.top-choice-field{display:grid;grid-template-columns:1fr;gap:3px;min-width:0}.top-choice-field label{font-size:10px}.top-choice-control{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:4px}.top-model-controls select{min-width:0;max-width:none;width:100%}.top-runtime-stack{grid-column:1/2;display:flex;gap:5px;align-items:center;justify-content:flex-start;min-width:0}.top-actions>.danger-solid{grid-column:2/3;justify-self:end}.top-actions>.top-logout{grid-column:3/4;justify-self:end}.brand{font-size:20px}.grid{gap:8px}.card,.span3,.span4,.span5,.span6,.span7,.span8,.span9,.span12{grid-column:span 12;padding:10px}.usage-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.usage-row{grid-template-columns:1fr 1fr;gap:3px}.usage-row>span:first-child{grid-column:1/-1}.usage-tokens{white-space:normal}.plan-comment{grid-column:1/-1}.section-title-row{align-items:flex-start;flex-direction:column}.eff-section-head{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px;align-items:center}.eff-section-head h2{grid-column:1/2;grid-row:1;margin:0}.eff-section-head #effPolicyState{grid-column:2/3;grid-row:1;justify-self:end;margin:0}.eff-header-controls{grid-column:1/-1;grid-row:2;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;width:100%}.eff-header-field{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:5px;align-items:center;min-width:0}.eff-header-field label{grid-column:1/-1;margin:0}.eff-header-field select,.eff-header-field input{grid-column:1/2;width:100%;min-width:0}.eff-header-field .inline-reset{grid-column:2/3}.events{height:340px}pre{max-height:300px}button{min-height:44px;flex:1 1 auto}.top-actions button,.top-actions .inline-reset,.top-runtime-stack button{min-height:34px;flex:0 0 auto}input,textarea{font-size:16px}.metric{font-size:23px}.kv{grid-template-columns:110px minmax(0,1fr)}.footer{padding-bottom:max(8px,env(safe-area-inset-bottom))}}
</style></head><body><div class="wrap">
<div class="top"><div><div class="brand">__PROJECT_WEB_TITLE__ <span id="version" class="info"></span></div><div class="sub">__PROJECT_WEB_CONSOLE_SUBTITLE__</div></div><div class="top-actions"><div id="topModelControls" class="top-model-controls"></div><div class="top-runtime-stack"><span id="refresh" class="badge">connecting</span><span id="job" class="badge">pid -</span></div><button class="danger-solid" title="Reset only RALPH local token statistics" onclick="resetTokenStats()">Reset token stats</button><button class="top-logout" onclick="logout()">Logout</button></div></div>
<div id="error"></div><div class="grid">
<section class="card span3"><h2>Controller</h2><div id="status" class="metric">-</div><div id="controller" class="kv"></div></section>
<section class="card span3"><h2>Plan</h2><div id="planMetric" class="metric">-</div><div id="planMeta" class="kv"></div></section>
<section class="card span3"><h2>Quota / Efficiency</h2><div id="quota" class="metric">-</div><div id="eff" class="kv"></div></section>
<section class="card span3"><h2>Git</h2><div id="branch" class="metric">-</div><div id="git" class="kv"></div></section>
<section class="card span12"><div class="section-title-row"><h2>Usage / Token Economy</h2><div id="usageToolbar" class="compact-actions"></div></div><div id="usageSummary" class="usage-grid"></div><div id="usageWindows" class="usage-windows"></div><h3>Consumption by plan</h3><div id="planUsage" class="plan-usage"></div></section>
<section class="card span12"><div class="eff-section-head"><h2>Efficiency / Resource Controls</h2><div id="effHeaderControls" class="eff-header-controls"></div><span id="effPolicyState" class="badge">live</span></div><div id="efficiencyControls" class="efficiency-controls"></div></section>
<section class="card span12"><div class="human-section-head"><h2>Human Control</h2><div id="planBounds" class="plan-bound-controls" hidden><div class="plan-bound-field"><label for="proposalAuthority">Repository authority</label><select id="proposalAuthority"><option value="" selected>Select authority…</option><option value="read-only">Read-only</option><option value="write">Write</option></select></div><div class="plan-bound-field"><label for="planMinSteps">Min steps</label><input id="planMinSteps" type="number" min="1" max="20" value="5" inputmode="numeric"></div><div class="plan-bound-field"><label for="planMaxSteps">Max steps</label><input id="planMaxSteps" type="number" min="1" max="20" value="10" inputmode="numeric"></div></div></div><div id="gate"></div><div id="retirementReconciliation"></div><div id="controls"></div><div id="actionResult" class="action-result"></div></section>
<section class="card span12"><h2>Plan Progress</h2><div id="goal" class="notice"></div><div id="steps" class="steps"></div></section>
<section class="card span9"><h2>Live Activity</h2><div id="events" class="events"></div></section>
<section class="card span3"><h2>Plan Files</h2><div id="files"></div></section>
<section class="card span12"><div class="section-title-row"><h2>Completion Report</h2><div class="view-toggle" role="group" aria-label="Completion report view"><button id="reportRenderedButton" class="active" type="button" onclick="setReportMode('rendered')">Rendered</button><button id="reportMarkdownButton" type="button" onclick="setReportMode('markdown')">Markdown</button></div></div><div id="reportRendered" class="markdown-report">No completion report yet.</div><pre id="reportMarkdown" hidden>No completion report yet.</pre><div id="reportPath" class="small report-path"></div></section>
<section class="card span12"><h2>Controller Output</h2><pre id="log">No output yet.</pre></section>
</div><div class="footer">Private-LAN mode uses username/password + HttpOnly session + CSRF + exact Host validation · no force-push or policy bypass is exposed</div></div>
<script>
const CSRF='__CSRF__';
function esc(s){return String(s??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));}
function kv(obj){return Object.entries(obj).map(([k,v])=>`<div>${esc(k)}</div><div>${esc(v??'-')}</div>`).join('');}
function num(v){return Number(v||0).toLocaleString();}
function when(epoch){if(!epoch)return 'unknown';return new Date(Number(epoch)*1000).toLocaleString();}
function stripAnsi(s){return String(s||'').replace(/\x1b\[[0-9;]*m/g,'');}
const renderedValues=new WeakMap(),pendingTargetUpdates=new Map();let renderedControlsIdentity=null,renderedReadyTestReconciliationIdentity=null,latestSnapshot=null,refreshGeneration=0,actionFeedback=null,localActionState=null,efficiencyDirty=false;
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
let reportMode='rendered';
function markdownInline(text){let value=esc(text);value=value.replace(/`([^`]+)`/g,'<code>$1</code>');value=value.replace(/\*\*([^*]+)\*\*/g,'<strong>$1</strong>');value=value.replace(/__([^_]+)__/g,'<strong>$1</strong>');value=value.replace(/(^|[^*])\*([^*\n]+)\*/g,'$1<em>$2</em>');return value;}
function renderMarkdown(text){const lines=String(text??'').replace(/\r\n?/g,'\n').split('\n');let out=[],code=false,list='';const closeList=()=>{if(list){out.push(`</${list}>`);list='';}};for(const raw of lines){if(/^\s*```/.test(raw)){closeList();if(code){out.push('</code></pre>');code=false;}else{out.push('<pre class="md-code"><code>');code=true;}continue;}if(code){out.push(esc(raw)+'\n');continue;}const line=raw.trimEnd();if(!line.trim()){closeList();continue;}let m=line.match(/^(#{1,6})\s+(.+)$/);if(m){closeList();const level=m[1].length;out.push(`<h${level}>${markdownInline(m[2])}</h${level}>`);continue;}if(/^\s*([-*_])(?:\s*\1){2,}\s*$/.test(line)){closeList();out.push('<hr>');continue;}m=line.match(/^\s*[-*+]\s+(.+)$/);if(m){if(list!=='ul'){closeList();out.push('<ul>');list='ul';}out.push(`<li>${markdownInline(m[1])}</li>`);continue;}m=line.match(/^\s*\d+[.)]\s+(.+)$/);if(m){if(list!=='ol'){closeList();out.push('<ol>');list='ol';}out.push(`<li>${markdownInline(m[1])}</li>`);continue;}m=line.match(/^\s*>\s?(.*)$/);if(m){closeList();out.push(`<blockquote>${markdownInline(m[1])}</blockquote>`);continue;}closeList();out.push(`<p>${markdownInline(line.trim())}</p>`);}closeList();if(code)out.push('</code></pre>');return out.join('')||'<div class="small">No completion report yet.</div>';}
function setReportMode(mode){reportMode=mode==='markdown'?'markdown':'rendered';const rendered=document.getElementById('reportRendered'),raw=document.getElementById('reportMarkdown'),renderedButton=document.getElementById('reportRenderedButton'),rawButton=document.getElementById('reportMarkdownButton');if(rendered)rendered.hidden=reportMode!=='rendered';if(raw)raw.hidden=reportMode!=='markdown';if(renderedButton)renderedButton.classList.toggle('active',reportMode==='rendered');if(rawButton)rawButton.classList.toggle('active',reportMode==='markdown');}
function renderReport(report){const text=report?.preview||'No completion report yet.';renderHTML('reportRendered',renderMarkdown(text));renderText('reportMarkdown',text);renderText('reportPath',report?.path?`Source: ${report.path}`:'');setReportMode(reportMode);}
function actionLabel(action){return ({approve:'Plan approved',reject:'Plan rejected',resume:'Plan resumed',resolve_gate:'Human gate resolved',steer:'Direction submitted',requalify:'Qualified delta revalidated',reconcile_ready_test:'Late test delta adopted for requalification',finalize_review:'Finalization review',finalize_commit:'Qualified delta committed',finalize_push:'Commit pushed',retire:'Plan retirement request',propose_replacement:'Replacement plan requested',inspect_carry_forward:'Reconciliation inspected',adopt_carry_forward:'Carry-forward candidate adopted',leave_carry_forward_outside:'Candidate left outside boundary',reject_carry_forward:'Candidate marked externally required',authorize_self_hosting:'Self-hosting authority granted',recover_interrupted_run:'Interrupted run recovered',efficiency_update:'Efficiency policy updated',efficiency_reset_all:'Efficiency policy reset'})[action]||'Operator action complete';}
function renderActionFeedback(){if(!actionFeedback)return;const feedback=actionFeedback;const heading=feedback.error?`${actionLabel(feedback.action)} failed`:actionLabel(feedback.action);const output=[prettyOutput(feedback.stdout),prettyOutput(feedback.stderr)].filter(Boolean).join('');const granted=feedback.grantedPaths?.length?`<pre class="action-detail">${esc(`Granted authority over named RALPH tooling paths:\n${feedback.grantedPaths.join('\n')}`)}</pre>`:'';const detail=feedback.error?`<pre class="action-detail">${esc(feedback.error)}</pre>`:(output||'<div class="small">Controller accepted the action. Current state is shown above.</div>');renderHTML('actionResult',`<div class="action-title ${feedback.error?'bad':''}">${esc(heading)}</div>${granted}${detail}`);}
function renderActionResult(action,j,grantedPaths=[]){actionFeedback={action,stdout:j.stdout,stderr:j.stderr,grantedPaths};renderActionFeedback();}
function renderActionFailure(action,message){actionFeedback={action,error:message||'action failed'};renderActionFeedback();}
function renderSelfHostingReview(){const context=document.getElementById('selfHostingContext');if(context&&!context.dataset.reviewed){context.dataset.reviewed='true';context.insertAdjacentHTML('beforebegin','<div class="small">You are granting authority over named RALPH tooling paths. Review every displayed candidate before submission.</div>');}}
async function post(payload){const r=await fetch('/api/action',{method:'POST',headers:{'Content-Type':'application/json','X-RALPH-CSRF':CSRF},body:JSON.stringify(payload)});const j=await r.json();if(!r.ok||!j.ok)throw new Error(j.error||j.stderr||'action failed');return j;}
function controlButton(label,action,extra={},cls=''){return `<button class="${cls}" onclick='act(${JSON.stringify(action)},${JSON.stringify(extra)})'>${esc(label)}</button>`;}
function actionState(action){return ({propose:'PLANNING',approve:'APPROVING',reject:'REJECTING',run:'RUNNING',steer:'STEERING',resume:'RESUMING',resolve_gate:'RESOLVING',retire:'RETIRING',authorize_self_hosting:'AUTHORIZING',requalify:'QUALIFYING',reconcile_ready_test:'RECONCILING',finalize_review:'REVIEWING',finalize_commit:'COMMITTING',finalize_push:'PUSHING'})[action]||'WORKING';}
function showActionState(action){localActionState=actionState(action);renderClass('job','badge info');renderText('job',localActionState.toLowerCase());}
async function act(action,extra={}){try{let p={action,...extra};if(['reject','resume','resolve_gate'].includes(action)){const reason=prompt('Reason / evidence:');if(!reason)return;p.reason=reason;}if(action==='finalize_commit'){if(prompt('Type COMMIT to confirm')!=='COMMIT')return;p.confirm='COMMIT';}if(action==='finalize_push'){if(prompt('Type PUSH to confirm')!=='PUSH')return;p.confirm='PUSH';}showActionState(action);const j=await post(p);renderActionResult(action,j);await refresh();}catch(e){renderActionFailure(action,e.message);}finally{localActionState=null;}}
async function submitRetirement(mode){const reason=document.getElementById('retirementReason')?.value.trim()||'';if(!reason){renderActionFailure('retire','Operator reason is required.');return;}if(mode==='rollback-preview'){try{showActionState('retire');const j=await post({action:'retire',mode,reason});renderActionResult('retire',j);await refresh();}catch(e){renderActionFailure('retire',e.message);}finally{localActionState=null;}return;}const confirmToken=mode==='rollback'?'ROLLBACK':'CARRY_FORWARD';const previewSha=mode==='rollback'?String(latestSnapshot?.controller?.rollback_preview?.sha256||''):'';if(mode==='rollback'&&!previewSha){renderActionFailure('retire','Preview the exact rollback paths before confirming rollback.');return;}if(prompt(`Type ${confirmToken} to confirm the controller-selected retirement disposition`)!==confirmToken)return;try{showActionState('retire');const j=await post({action:'retire',mode,confirm:confirmToken,reason,preview_sha:previewSha});renderActionResult('retire',j);await refresh();}catch(e){renderActionFailure('retire',e.message);}finally{localActionState=null;}}
async function submitReplacement(recordId){if(String(latestSnapshot?.latest_retirement?.record_id||'')!==String(recordId||'')){renderActionFailure('propose_replacement','The current controller retirement record is no longer available.');return;}const repositoryAuthority=String(document.getElementById('proposalAuthority')?.value||'').trim(),minSteps=Number(document.getElementById('planMinSteps')?.value||5),maxSteps=Number(document.getElementById('planMaxSteps')?.value||10),goal=String(document.getElementById('replacementGoal')?.value||'').trim();if(!repositoryAuthority){renderActionFailure('propose_replacement','Select repository authority before proposing.');return;}try{showActionState('propose_replacement');const j=await post({action:'propose_replacement',retirement_record_id:recordId,repository_authority:repositoryAuthority,min_steps:minSteps,max_steps:maxSteps,goal});renderActionResult('propose_replacement',j);await refresh();}catch(e){renderActionFailure('propose_replacement',e.message);}finally{localActionState=null;}}
async function submitCarryForward(action,path){const reconciliation=latestSnapshot?.reconciliation;const candidate=(reconciliation?.candidates||[]).find(x=>String(x?.path||'')===String(path||'')&&x?.eligible===true&&x?.disposition==='PENDING_RECONCILIATION');if(!candidate){renderActionFailure(action,'The exact controller reconciliation candidate is no longer pending.');return;}const step=prompt('Controller claiming step number:');if(!step)return;const reason=action==='adopt_carry_forward'?'':prompt('Operator reason / evidence:');if(action==='adopt_carry_forward'&&prompt('Type ADOPT to confirm this exact controller candidate')!=='ADOPT')return;if(action!=='adopt_carry_forward'&&!reason)return;try{showActionState(action);const payload={action,path:String(candidate.path),step:Number(step)};if(action==='adopt_carry_forward')payload.confirm='ADOPT';else payload.reason=reason;const j=await post(payload);renderActionResult(action,j,[String(candidate.path)]);await refresh();}catch(e){renderActionFailure(action,e.message);}finally{localActionState=null;}}
async function submitGoal(){const goal=document.getElementById('goalInput').value.trim();if(!goal)return;const repositoryAuthority=String(document.getElementById('proposalAuthority')?.value||'').trim(),minSteps=Number(document.getElementById('planMinSteps')?.value||5),maxSteps=Number(document.getElementById('planMaxSteps')?.value||10);if(!repositoryAuthority){renderActionFailure('propose','Select repository authority before proposing.');return;}try{showActionState('propose');await post({action:'propose',goal,repository_authority:repositoryAuthority,min_steps:minSteps,max_steps:maxSteps});await refresh();}catch(e){renderActionFailure('propose',e.message);}finally{localActionState=null;}}
async function submitRun(){try{showActionState('run');const j=await post({action:'run',max_loops:40});renderActionResult('run',j);await refresh();}catch(e){renderActionFailure('run',e.message);}finally{localActionState=null;}}
function interruptedRecoveryControls(c){const paths=Array.isArray(c?.pending_current_step_paths)?c.pending_current_step_paths:[];const rows=paths.map(path=>`<label><input type="checkbox" data-interrupted-pending value="${esc(path)}" checked> <span class="file">${esc(path)}</span></label>`).join('');return `<div class="form"><div class="small">Confirm the exact controller-recorded current-step pending paths before recovery.${paths.length?'':' No pending paths are recorded.'}</div>${rows}<button class="good" onclick="submitInterruptedRecovery()">Recover interrupted run</button></div>`;}
async function submitInterruptedRecovery(){const expected=Array.isArray(latestSnapshot?.controller?.pending_current_step_paths)?latestSnapshot.controller.pending_current_step_paths.map(String):[];const allowed=new Set(expected);const paths=[...document.querySelectorAll('input[data-interrupted-pending]:checked')].map(x=>x.value).filter(path=>allowed.has(path));if(paths.length!==expected.length){renderActionFailure('recover_interrupted_run','Select every exact controller pending path before recovery.');return;}if(prompt('Type RECOVER to confirm exact interrupted-run recovery')!=='RECOVER')return;try{showActionState('recover_interrupted_run');const j=await post({action:'recover_interrupted_run',confirm:'RECOVER',pending_paths:paths});renderActionResult('recover_interrupted_run',j,paths);await refresh();}catch(e){renderActionFailure('recover_interrupted_run',e.message);}finally{localActionState=null;}}
async function submitSteer(){const direction=document.getElementById('steerInput').value.trim();const gate=document.getElementById('gateId').textContent.trim();if(!direction)return;try{await post({action:'steer',gate,direction});await refresh();}catch(e){showError(e.message);}}
async function submitSelfHosting(){const authority=latestSnapshot?.gate?.authority_block;const context=authority?{gate:String(authority.gate_id||''),paths:[...(authority.paths||[])]}:null;const reason=document.getElementById('selfHostingReason')?.value.trim()||'';const button=document.getElementById('selfHostingButton');const allowed=new Set(context?.paths||[]);const paths=[...document.querySelectorAll('input[data-self-host-path]:checked')].map(x=>x.value).filter(path=>allowed.has(path));if(!context){renderActionFailure('authorize_self_hosting','The controller self-hosting candidate is no longer available.');return;}if(!reason){renderActionFailure('authorize_self_hosting','Operator reason is required.');return;}if(paths.length!==context.paths.length){renderActionFailure('authorize_self_hosting','Select every controller candidate path before authorizing this exact grant.');return;}if(button)button.disabled=true;try{const j=await post({action:'authorize_self_hosting',gate:context.gate,paths,reason});renderActionResult('authorize_self_hosting',j,context.paths);await refresh();}catch(e){renderActionFailure('authorize_self_hosting',e.message);}finally{if(button)button.disabled=false;}}
async function submitReadyTestReconciliation(){const candidate=latestSnapshot?.test_reconciliation;const path=String(candidate?.path||'');const reason=document.getElementById('testReconciliationReason')?.value.trim()||'';const button=document.getElementById('testReconciliationButton');if(!candidate?.eligible||!path){renderActionFailure('reconcile_ready_test','The controller reconciliation candidate is no longer available.');return;}if(!reason){renderActionFailure('reconcile_ready_test','Operator reason is required.');return;}if(button)button.disabled=true;try{const j=await post({action:'reconcile_ready_test',confirm:'ADOPT',reason});renderActionResult('reconcile_ready_test',j,[path]);await refresh();}catch(e){renderActionFailure('reconcile_ready_test',e.message);}finally{if(button)button.disabled=false;}}
async function logout(){try{await fetch('/api/logout',{method:'POST',headers:{'X-RALPH-CSRF':CSRF}});}finally{location.reload();}}
function showError(msg){renderHTML('error',`<div class="notice errorbox">${esc(msg)}</div>`);}
function renderReadyTestReconciliation(s){const reconciliation=s.test_reconciliation;const candidate=s.controller.status==='READY_TO_COMMIT'&&reconciliation?.eligible&&String(reconciliation.path||'')?{path:String(reconciliation.path),delta_kind:String(reconciliation.delta_kind||'')}:null;const identity=JSON.stringify(candidate);const target=document.getElementById('readyTestReconciliation');if(!target||identity===renderedReadyTestReconciliationIdentity)return;renderedReadyTestReconciliationIdentity=identity;const out=candidate?`<div class="form"><div class="small">Controller-authorized late test candidate (exact path):</div><textarea id="testReconciliationPath" readonly aria-label="Controller-authorized late test candidate">${esc(candidate.path)}</textarea><textarea id="testReconciliationReason" placeholder="Operator reason for adopting this exact candidate..."></textarea><button id="testReconciliationButton" class="good" onclick="submitReadyTestReconciliation()">Adopt exact candidate (ADOPT)</button></div>`:'';renderedValues.delete(target);renderHTML('readyTestReconciliation',out);}
function renderRetirementAndReconciliation(s){const retirement=s.latest_retirement||null,reconciliation=s.reconciliation||{},refusal=String(reconciliation.controller_refusal||''),candidates=Array.isArray(reconciliation.candidates)?reconciliation.candidates:[],pending=candidates.filter(x=>x?.eligible===true&&x?.disposition==='PENDING_RECONCILIATION'),target=document.getElementById('retirementReconciliation');if(!target)return;const record=retirement?`<div class="notice"><b>Retirement provenance · ${esc(retirement.record_id)}</b><br><span class="small">Disposition: ${esc(retirement.disposition)} · manifest SHA-256: ${esc(retirement.manifest_sha256||'controller did not provide a digest')} · retired: ${esc(retirement.retired_at||'controller did not provide a timestamp')}</span>${retirement.disposition==='RETIRED_WITH_CARRY_FORWARD'?`<div class="form"><textarea id="replacementGoal" placeholder="Optional replacement goal override; leave blank to use the controller-derived retirement objective."></textarea><button class="good" onclick='submitReplacement(${JSON.stringify(retirement.record_id)})'>Start replacement plan from ${esc(retirement.record_id)}</button></div>`:`<div class="small">No replacement plan is available for this controller disposition.</div>`}</div>`:'';const rows=candidates.map(x=>{const path=String(x?.path||''),enabled=x?.eligible===true&&x?.disposition==='PENDING_RECONCILIATION';const actions=enabled?`<div class="actions"><button class="good" onclick='submitCarryForward("adopt_carry_forward",${JSON.stringify(path)})'>Adopt exact candidate (ADOPT)</button><button onclick='submitCarryForward("leave_carry_forward_outside",${JSON.stringify(path)})'>Leave outside boundary</button><button class="danger" onclick='submitCarryForward("reject_carry_forward",${JSON.stringify(path)})'>Mark externally required</button></div>`:`<div class="small">Controller classification is display-only; no action is available.</div>`;return `<div class="notice"><b>${esc(path||'invalid controller path')}</b><br><span class="small">Classification: ${esc(x?.classification||'controller did not provide classification')} · disposition: ${esc(x?.disposition||'controller did not provide disposition')} · evidence: ${esc(x?.evidence_status||x?.evidence_error||'controller-provided')} · claiming step: ${esc(x?.claiming_step??'not claimed')} · qualification: ${esc(x?.qualification_impact||'controller-provided')}</span>${actions}</div>`;}).join('');const reconcile=reconciliation.replacement?`<h3>Per-path reconciliation</h3>${refusal?`<div class="notice errorbox"><b>Controller refused reconciliation state</b><br>${esc(refusal)}<br><span class="small">All reconciliation actions are disabled until the controller provides a current state.</span></div>`:''}${rows||'<div class="small">Controller reports no reconciliation paths.</div>'}`:'';const ready=s.controller.status==='READY_TO_COMMIT'?`<div class="notice ${refusal||pending.length?'errorbox':''}"><b>READY_TO_COMMIT provenance blockers</b><br><span class="small">${refusal?`Blocking controller refusal: ${esc(refusal)}`:pending.length?`Blocking unresolved controller reconciliation paths: ${esc(pending.map(x=>x.path).join(', '))}`:s.controller.block_reason?`Blocking controller provenance message: ${esc(s.controller.block_reason)}`:'No unresolved provenance blocker was supplied by the controller.'}</span></div>`:'';renderedValues.delete(target);renderHTML('retirementReconciliation',record+reconcile+ready);}
function retirementForm(){const p=latestSnapshot?.controller?.rollback_preview||null;const preview=p?.sha256?`<div class="small">Reviewed rollback preview SHA-256: <span class="file">${esc(p.sha256)}</span></div>`:'<div class="small">No reviewed rollback preview is active.</div>';return `<div class="form"><div class="small">Retirement disposition is an explicit operator choice. The controller previews and validates exact paths; this page never derives them.</div>${preview}<textarea id="retirementReason" placeholder="Reason / evidence for retirement..."></textarea><div class="actions"><button onclick="submitRetirement('rollback-preview')">Preview exact rollback paths</button><button class="danger" onclick="submitRetirement('rollback')">Confirm rollback (ROLLBACK)</button><button onclick="submitRetirement('carry-forward')">Confirm carry-forward (CARRY_FORWARD)</button></div></div>`;}
function renderControls(s){const c=s.controller,g=s.gate,j=s.job||{},rt=s.runtime||{};let out='';const st=c.status,operation=rt.active?`${rt.command||'controller'} pid ${rt.pid}`:(j.active?`${j.activity||'WORKING'} pid ${j.pid}`:'');const planBounds=document.getElementById('planBounds'),replacementAvailable=st==='IDLE'&&s.latest_retirement?.disposition==='RETIRED_WITH_CARRY_FORWARD';if(planBounds)planBounds.hidden=Boolean(operation)||!(['IDLE','PLAN_COMPLETE','PUSHED','READ_ONLY_COMPLETE'].includes(st)||replacementAvailable);const identity=JSON.stringify([st,operation,st==='BLOCKED_HUMAN'?String(g?.id||''):'',JSON.stringify(g?.self_hosting_candidate?.paths||[])]);renderRetirementAndReconciliation(s);renderReadyTestReconciliation(s);if(identity===renderedControlsIdentity)return;renderedControlsIdentity=identity;if(operation){out=`<div class="notice"><b>Controller operation active</b><br><span class="small">${esc(operation)}. Durable controller state remains ${esc(st)}.</span></div>`;}else if(['IDLE','PLAN_COMPLETE','PUSHED','READ_ONLY_COMPLETE'].includes(st)){out=`<div class="form"><textarea id="goalInput" placeholder="Describe the bounded engineering goal..."></textarea><button class="good" onclick="submitGoal()">Propose plan</button></div>`;}else if(st==='AWAITING_APPROVAL'){out=`<div class="notice"><b>Approval review</b><br><span class="small">Read every proposed step, objective, acceptance criterion and test-change policy before granting execution authority.</span></div><div class="actions">${controlButton('Approve plan','approve',{},'good')}${controlButton('Reject','reject',{},'danger')}</div>`;}else if(['APPROVED','PAUSED_USAGE_LIMIT'].includes(st)){out=`<div class="form"><div class="small">Live efficiency/resource policy is controlled in the panel above. Current mode: <b>${esc(c.efficiency_mode||'NORMAL')}</b>.</div><button class="good" onclick="submitRun()">Run approved plan</button></div>`;}else if(st==='RUNNING'){out=`<div class="notice errorbox"><b>RUNNING without an observed controller runtime</b><br><span class="small">The durable controller says RUNNING but no live controller PID is visible. Recovery will verify the exact checkpoint-relative repository state before returning this step to APPROVED.</span></div>${interruptedRecoveryControls(c)}`;}else if(st==='BLOCKED_HUMAN'){const interrupted=String(c.block_reason||'').startsWith('controller interrupted:')||String(c.block_reason||'').startsWith('controller runtime exception:');const authority=g?.authority_block;if(interrupted){out=`<div class="notice errorbox"><b>Interrupted controller run</b><br><span class="small">Recovery is only admitted if plan, checkpoint, attribution, pending paths and current repository evidence still agree exactly.</span></div>${interruptedRecoveryControls(c)}${retirementForm()}`;}else if(authority){const pathRows=(authority.paths||[]).map(path=>`<label><input type="checkbox" data-self-host-path value="${esc(path)}" checked> <span class="file">${esc(path)}</span></label>`).join('');const reviewText=`Controller self-hosting authority block\nPlan hash: ${authority.plan_hash}\nStep: ${authority.step}\nGate: ${authority.gate_id}\nCandidate paths:\n${(authority.paths||[]).join('\n')}`;out=`<div class="notice gate"><b>Supervised self-hosting authority</b><br><span class="small">Controller-reported context only; the controller decides eligibility and grant validity.</span></div><div class="form"><textarea id="selfHostingContext" readonly aria-label="Controller self-hosting authority block">${esc(reviewText)}</textarea>${pathRows}<textarea id="selfHostingReason" placeholder="Operator reason for this exact self-hosting grant..."></textarea><button id="selfHostingButton" class="good" onclick="submitSelfHosting()">Authorize Self-Hosting</button>${retirementForm()}</div>`;}else{out=`<div class="form"><textarea id="steerInput" placeholder="Bounded human direction for this exact gate..."></textarea><button onclick="submitSteer()">Steer & retry</button><div class="actions">${controlButton('Resume retry','resume')}${controlButton('Resolve delegated gate','resolve_gate',{gate:g?.id||''},'good')}</div>${retirementForm()}</div>`;}}else if(st==='READY_TO_COMMIT'){out=`<div class="actions">${controlButton('Requalify delta','requalify')}${controlButton('Finalization review','finalize_review')}${controlButton('Commit qualified delta','finalize_commit',{},'good')}</div><div id="readyTestReconciliation"></div>${retirementForm()}`;}else if(st==='COMMITTED'){out=`<div class="actions">${controlButton('Push to configured upstream','finalize_push',{},'good')}</div>`;}else{out=`<div class="small">No web action for state ${esc(st)}. Use the CLI for exceptional recovery.</div>`;}const controls=document.getElementById('controls');renderedValues.delete(controls);renderHTML('controls',out);renderedReadyTestReconciliationIdentity=null;renderReadyTestReconciliation(s);}
function efficiencyElement(key){return document.querySelector(`[data-eff-key="${key}"]`);}
function markEfficiencyDirty(){efficiencyDirty=true;renderText('effPolicyState','changes pending');renderClass('effPolicyState','badge warn');syncEfficiencyResetIcons();syncEfficiencyModePanels();}
function syncEfficiencyResetIcons(){const defs=latestSnapshot?.efficiency_defaults||{};document.querySelectorAll('[data-eff-key]').forEach(el=>{const key=el.dataset.effKey;const button=document.querySelector(`[data-eff-reset="${key}"]`);if(!button)return;let changed;if(key==='mode')changed=String(el.value).toUpperCase()!==String(defs[key]||'NORMAL').toUpperCase();else changed=Number(el.value)!==Number(defs[key]);button.style.visibility=changed?'visible':'hidden';});}
function syncEfficiencyModePanels(){const mode=String(efficiencyElement('mode')?.value||'NORMAL').toUpperCase();document.querySelectorAll('[data-mode-panel]').forEach(panel=>{panel.hidden=panel.dataset.modePanel!==mode;});const off=document.getElementById('effOffNote');if(off)off.hidden=mode!=='OFF';document.querySelectorAll('[data-mode-limit] input').forEach(input=>{input.disabled=mode==='OFF';});}
function resetEfficiencyField(key){const el=efficiencyElement(key),defs=latestSnapshot?.efficiency_defaults||{};if(!el||!(key in defs))return;el.value=defs[key];markEfficiencyDirty();}
function stageEfficiencyDefaults(){const defs=latestSnapshot?.efficiency_defaults||{};document.querySelectorAll('[data-eff-key]').forEach(el=>{const key=el.dataset.effKey;if(key in defs)el.value=defs[key];});markEfficiencyDirty();}
function discardEfficiencyChanges(){efficiencyDirty=false;renderEfficiency(latestSnapshot,true);}
function efficiencySettingsFromForm(){const settings={};document.querySelectorAll('[data-eff-key]').forEach(el=>{const key=el.dataset.effKey;if(key==='mode')settings[key]=String(el.value).toUpperCase();else settings[key]=Number(el.value);});return settings;}
async function submitEfficiencySettings(){try{const settings=efficiencySettingsFromForm();const j=await post({action:'efficiency_update',settings});efficiencyDirty=false;renderActionResult('efficiency_update',j);await refresh();}catch(e){renderActionFailure('efficiency_update',e.message);renderText('effPolicyState','apply failed');renderClass('effPolicyState','badge bad');}}
async function selectModel(model){try{const action=model?'model_update':'model_reset';const payload=model?{action,model}:{action};showActionState(action);const j=await post(payload);renderActionResult(action,j);await refresh();}catch(e){renderActionFailure('model_update',e.message);}finally{localActionState=null;}}
async function selectEffort(effort){try{const action=effort?'effort_update':'effort_reset';const payload=effort?{action,effort}:{action};showActionState(action);const j=await post(payload);renderActionResult(action,j);await refresh();}catch(e){renderActionFailure('effort_update',e.message);}finally{localActionState=null;}}
async function redeemBankedReset(){const usage=latestSnapshot?.usage||{};const credits=(usage.reset_credits||[]).filter(c=>String(c.status||'').toLowerCase()==='available');const chosen=credits[0]||{};const creditId=String(chosen.id||'');const title=String(chosen.title||'Banked reset');const expiresAt=Number(chosen.expires_at||0);const expiry=expiresAt?`\nExpires: ${when(expiresAt)}`:'';if(!confirm(`Redeem this banked Codex reset?\n\n${title}${expiry}\n\nThis is an account-level action and cannot be undone once a reset is consumed.`))return;try{showActionState('redeem_reset');const j=await post({action:'redeem_reset',credit_id:creditId,confirm:'REDEEM'});renderActionResult('redeem_reset',j);await refresh();}catch(e){renderActionFailure('redeem_reset',e.message);}finally{localActionState=null;}}
async function resetTokenStats(){if(!confirm('Reset RALPH token-usage statistics?\n\nThis resets only RALPH\'s local statistics baseline. It does NOT reset Codex 5-hour/weekly limits and does NOT redeem a banked reset.'))return;try{const j=await post({action:'usage_reset_stats',confirm:'RESET'});renderActionResult('usage_reset_stats',j);await refresh();}catch(e){renderActionFailure('usage_reset_stats',e.message);}}
function info(label,text){return `${esc(label)} <span class="field-help" title="${esc(text)}">ⓘ</span>`;}
function renderEfficiency(s,force=false){if(!s)return;if(efficiencyDirty&&!force)return;const p=s.efficiency_policy||{},d=s.efficiency_defaults||{};const field=(key,label,help,step='1',min='0',modeLimit=false)=>{const value=p[key]??d[key]??'';const changed=Number(value)!==Number(d[key]);return `<div class="eff-field" ${modeLimit?'data-mode-limit':''}><div><label>${info(label,help)}</label><input data-eff-key="${esc(key)}" type="number" step="${esc(step)}" min="${esc(min)}" value="${esc(value)}" oninput="markEfficiencyDirty()"><div class="baseline">baseline ${esc(d[key]??'-')}</div></div><button type="button" class="icon-btn inline-reset" data-eff-reset="${esc(key)}" title="Reset ${esc(label)} to baseline" style="visibility:${changed?'visible':'hidden'}" onclick="resetEfficiencyField('${esc(key)}')">↺</button></div>`;};const mode=String(p.mode||'NORMAL').toUpperCase(),modeChanged=mode!==String(d.mode||'NORMAL').toUpperCase(),reserveValue=p.reserve_percent??d.reserve_percent??5,reserveChanged=Number(reserveValue)!==Number(d.reserve_percent);const modeHeader=`<div class="eff-header-field"><label>Mode</label><select data-eff-key="mode" onchange="markEfficiencyDirty()"><option value="STRICT" ${mode==='STRICT'?'selected':''}>Strict</option><option value="NORMAL" ${mode==='NORMAL'?'selected':''}>Normal</option><option value="RELAXED" ${mode==='RELAXED'?'selected':''}>Relaxed</option><option value="OFF" ${mode==='OFF'?'selected':''}>Off</option></select><button type="button" class="icon-btn inline-reset" data-eff-reset="mode" title="Reset mode to NORMAL" style="visibility:${modeChanged?'visible':'hidden'}" onclick="resetEfficiencyField('mode')">↺</button></div>`;const reserveHeader=`<div class="eff-header-field"><label>New-work reserve %</label><input data-eff-key="reserve_percent" type="number" step="0.5" min="0" value="${esc(reserveValue)}" oninput="markEfficiencyDirty()"><button type="button" class="icon-btn inline-reset" data-eff-reset="reserve_percent" title="Reset new-work reserve to baseline ${esc(d.reserve_percent??5)}%" style="visibility:${reserveChanged?'visible':'hidden'}" onclick="resetEfficiencyField('reserve_percent')">↺</button></div>`;const modePanel=(name)=>{const k=name.toLowerCase();return `<div class="eff-mode-panel" data-mode-panel="${name}" ${mode===name?'':'hidden'}><div class="small"><b>${name}</b> limits · baseline values are shown beneath each control.</div><div class="eff-mode-limits">${field(`${k}_prompt_command_budget`,'Prompt commands','Maximum shell-command executions requested inside one model turn.','1','1',true)}${field(`${k}_max_commands`,'Observed commands','Pause after a qualified step if the model reports more command executions than this.','1','1',true)}${field(`${k}_max_reported_files`,'Files inspected','Pause after a qualified step if reported file inspection exceeds this limit.','1','1',true)}${field(`${k}_max_cumulative_input`,'Input tokens','Maximum cumulative input tokens for one turn before the selected-mode efficiency pause.','1000','1000',true)}${field(`${k}_max_noncached_input`,'Non-cached input','Maximum non-cached input tokens for one turn before the selected-mode efficiency pause.','1000','1000',true)}</div></div>`;};renderHTML('effHeaderControls',modeHeader+reserveHeader);const html=`<div class="eff-note">Stage any changes, then <b>Apply changes</b> once. RALPH reloads the policy between model turns; plan-bound admission is not revoked by later reserve changes.</div><div id="effOffNote" class="disabled-note" ${mode==='OFF'?'':'hidden'}><b>OFF:</b> ordinary efficiency thresholds are disabled and not editable. New-work reserve and emergency runaway protection remain active.</div>${modePanel('STRICT')}${modePanel('NORMAL')}${modePanel('RELAXED')}<details class="eff-advanced"><summary>Emergency runaway ceiling</summary><div class="small">Always enforced, including OFF. Keep these above every enabled mode limit.</div><div class="eff-mode-limits">${field('runaway_max_commands','Runaway commands','Absolute emergency command ceiling, independent of efficiency mode.')}${field('runaway_max_reported_files','Runaway files','Absolute emergency file-inspection ceiling, independent of efficiency mode.')}${field('runaway_max_cumulative_input','Runaway input','Absolute emergency cumulative-input ceiling.','1000','1000')}${field('runaway_max_noncached_input','Runaway non-cached','Absolute emergency non-cached-input ceiling.','1000','1000')}</div></details><div class="eff-actions"><button class="good" type="button" onclick="submitEfficiencySettings()">Apply changes</button><button type="button" onclick="stageEfficiencyDefaults()">Restore baselines</button><button type="button" onclick="discardEfficiencyChanges()">Discard staged</button></div><div class="eff-policy-meta"><span class="eff-updated">updated ${esc(p.updated_at||'defaults')}</span><span id="effPolicyRevision" class="eff-policy-revision">Rev: ${esc(p.revision??'-')}</span></div>`;efficiencyDirty=false;renderHTML('efficiencyControls',html);renderText('effPolicyState','live');renderClass('effPolicyState','badge ok');syncEfficiencyResetIcons();syncEfficiencyModePanels();}
function breakdownTable(title,rows){if(!rows?.length)return `<div class="plan-mini"><b>${esc(title)}</b><div class="small">none</div></div>`;return `<div class="plan-mini"><b>${esc(title)}</b><table>${rows.map(r=>`<tr><td>${esc(r.name)}</td><td>${num(r.turns)}t · ${num(r.input_tokens)} in · ${num(r.output_tokens)} out</td></tr>`).join('')}</table></div>`;}
function renderUsage(u,snapshot){const p=u.current_plan||{};const ratio=p.input_tokens?((Number(p.cached_input_tokens||0)/Number(p.input_tokens))*100):0;const wins=u.windows||[];const metrics=[`<div class="usage-box"><div class="small">Plan input</div><div class="usage-value">${num(p.input_tokens)}</div><div class="small">non-cached ${num(p.noncached_input_tokens)}</div></div>`,`<div class="usage-box"><div class="small">Plan output</div><div class="usage-value">${num(p.output_tokens)}</div><div class="small">reasoning ${num(p.reasoning_output_tokens)}</div></div>`,`<div class="usage-box"><div class="small">Cached input</div><div class="usage-value">${num(p.cached_input_tokens)}</div><div class="small">cache ${ratio.toFixed(1)}%</div></div>`,`<div class="usage-box"><div class="small">Observed turns</div><div class="usage-value">${num(p.turns)}</div><div class="small">${esc(u.model||'-')} · ${esc(u.plan_type||'-')}</div></div>`];for(const w of wins.slice(0,2)){const t=w.observed_tokens||{};metrics.push(`<div class="usage-box usage-window"><div class="small">${esc(w.name||w.slot||'window')}</div><div class="usage-value">${Number(w.remaining_percent??0).toFixed(1)}% left</div><div class="small">reset ${esc(when(w.resets_at))}</div><div class="small">in ${num(t.input_tokens)} · out ${num(t.output_tokens)}</div></div>`);}renderHTML('usageSummary',metrics.join(''));renderHTML('usageWindows','');const catalog=u.model_catalog||{},models=catalog.models||[],override=String(snapshot?.model_policy?.model||''),effortOverride=String(snapshot?.model_policy?.reasoning_effort||'');const effectiveModel=override||String(catalog.configured_default||catalog.selected||'');const activeModel=models.find(m=>String(m.id)===effectiveModel)||{};const efforts=[...new Set((activeModel.reasoning_efforts||[]).map(x=>String(x).toLowerCase()).filter(Boolean))];if(effortOverride&&!efforts.includes(effortOverride))efforts.push(effortOverride);const modelOptions=[`<option value="" ${override?'':'selected'}>Codex default${catalog.configured_default?' · '+esc(catalog.configured_default):''}</option>`,...models.map(m=>`<option value="${esc(m.id)}" ${override===String(m.id)?'selected':''}>${esc(m.display_name||m.id)}</option>`)].join('');const defaultEffort=String(catalog.configured_default_effort||activeModel.default_reasoning_effort||'');const defaultEffortLabel=catalog.configured_default_effort?'Codex default':'Model default';const effortOptions=[`<option value="" ${effortOverride?'':'selected'}>${defaultEffortLabel}${defaultEffort?' · '+esc(defaultEffort):''}</option>`,...efforts.map(e=>`<option value="${esc(e)}" ${effortOverride===e?'selected':''}>${esc(e)}</option>`)].join('');renderHTML('topModelControls',`<div class="top-choice-field"><label>Model</label><div class="top-choice-control"><select aria-label="RALPH model" title="RALPH model for the next model turn. Changing this does not interrupt an in-flight Codex turn." onchange="selectModel(this.value)">${modelOptions}</select>${override?`<button class="icon-btn inline-reset" title="Return to Codex configured default model" onclick="selectModel('')">↺</button>`:''}</div></div><div class="top-choice-field"><label>Effort</label><div class="top-choice-control"><select aria-label="RALPH reasoning effort" title="Reasoning effort for the next model turn. Options follow the selected model's authenticated Codex catalog." onchange="selectEffort(this.value)" ${efforts.length?'':'disabled'}>${effortOptions}</select>${effortOverride?`<button class="icon-btn inline-reset" title="Return to Codex configured default reasoning effort" onclick="selectEffort('')">↺</button>`:''}</div></div>`);const resetCount=Number(u.available_reset_credits??0);const credits=(u.reset_credits||[]).filter(c=>String(c.status||'').toLowerCase()==='available');const chosen=credits[0]||{};const redeem=resetCount>0?`<button class="sparkle" title="${resetCount} banked reset${resetCount===1?'':'s'} available${chosen.expires_at?' · earliest expiry '+when(chosen.expires_at):''}" onclick="redeemBankedReset()">Redeem${resetCount>1?' · '+resetCount:''}</button>`:'';renderHTML('usageToolbar',redeem);const plans=(u.plans||[]).slice(0,10);const planRows=plans.map(x=>{const goal=String(x.goal||'No plan comment recorded.'),hash=(x.plan_hash||'unassigned').slice(0,8),cache=Number(x.cache_ratio_percent||0).toFixed(1),planModels=(x.models||[]).join(', ')||'-',controlStatus=String(x.control_stats_status||'legacy'),steers=controlStatus==='complete'?num(x.steering_total):controlStatus==='partial'?`${num(x.steering_total)}*`:'—',controlText=controlStatus==='complete'?`<b>${num(x.steering_total)}</b> steering · ${num(x.human_gates_opened)} gates opened · ${num(x.human_gates_resolved)} resolved · ${num(x.self_hosting_grants)} self-host grants`:controlStatus==='partial'?`<b>${num(x.steering_total)}</b> observed steering · partial plan-bound history`:'Legacy plan · plan-bound control history unavailable';return `<details class="plan-usage-detail"><summary class="plan-usage-summary"><span class="plan-hash">${x.current?'<span class="current-tag">●</span> ':''}${esc(hash)}</span><span class="plan-number">${num(x.turns)} turns</span><span class="plan-number" title="Human steering decisions; — means legacy unbound history">${esc(steers)}</span><span class="plan-number hide-mobile">${num(x.total_tokens)}</span><span class="plan-number hide-mobile">${cache}%</span><span class="plan-goal" title="${esc(goal)}">${esc(goal)}</span></summary><div class="plan-usage-meta"><div class="plan-mini"><div class="small">Input / non-cached</div><b>${num(x.input_tokens)}</b> / ${num(x.noncached_input_tokens)}</div><div class="plan-mini"><div class="small">Cached / cache-write</div><b>${num(x.cached_input_tokens)}</b> / ${num(x.cache_write_input_tokens)}</div><div class="plan-mini"><div class="small">Output / reasoning</div><b>${num(x.output_tokens)}</b> / ${num(x.reasoning_output_tokens)}</div><div class="plan-mini"><div class="small">Average / turn</div><b>${num(x.avg_input_tokens)} in</b> · ${num(x.avg_output_tokens)} out</div><div class="plan-mini"><div class="small">Observed</div>${esc(when(x.first_epoch))} → ${esc(when(x.last_epoch))}</div><div class="plan-mini"><div class="small">Models</div>${esc(planModels)}</div><div class="plan-mini"><div class="small">Human control</div>${controlText}</div><div class="plan-breakdown">${breakdownTable('Scope',x.scopes)}${breakdownTable('Phase',x.phases)}${breakdownTable('Step',x.steps)}</div></div></details>`;}).join('');const header=plans.length?'<div class="plan-usage-head"><span>Plan</span><span>Turns</span><span>Steers</span><span>Total tokens</span><span>Cache</span><span>Goal</span></div>':'';const resetNote=u.stats_reset?`<div class="small">Local stats baseline reset ${esc(u.stats_reset.reset_at||'')}</div>`:'';renderHTML('planUsage',header+(planRows||'<div class="small">No usage-ledger history since the current statistics baseline.</div>')+resetNote);}
function render(s){const c=s.controller,p=s.plan,g=s.git,j=s.job||{},rt=s.runtime||{},u=s.usage||{};renderText('version','v'+s.version);renderText('status',c.status);renderHTML('controller',kv({plan:(c.plan_hash||'-').slice(0,16),step:`${c.current_step}/${c.step_count||'-'}`,loops:c.loop_count,recovery:c.recovery_checkpoint||'-',runtime:rt.active?`${rt.command||'controller'} pid ${rt.pid}`:(rt.stale?'stale runtime record':'idle'),web_activity:j.active?String(j.activity||'WORKING'):'idle',controller_output:s.controller_output_source||'none'})+`<div class="small">Web activity is transient; durable controller status remains ${esc(c.status)}.</div>`);renderText('planMetric',`${Math.min(c.current_step,c.step_count||0)}/${c.step_count||'-'}`);renderHTML('planMeta',kv({steering:c.steering_count,commit:(c.commit_sha||'-').slice(0,12),upstream:c.push_upstream||'-'}));renderText('quota',c.quota_remaining_percent==null?'-':c.quota_remaining_percent.toFixed(1)+'%');const operation=rt.active?`${rt.command||'controller'} pid ${rt.pid}`:(j.active?`${j.activity||'RUNNING'} pid ${j.pid}`:'idle');renderHTML('eff',kv({efficiency:c.efficiency,mode:c.efficiency_mode||'NORMAL',admission:c.usage_admitted?`admitted @ ${c.usage_admission_remaining??'?'}%`:'not admitted',job:operation,limits:u.captured_at||'refreshing'}));renderText('branch',g.branch);renderHTML('git',kv({upstream:g.upstream||'-',dirty:g.dirty?`${g.dirty_count} files`:'clean',head:(g.head||'-').slice(0,12)}));renderUsage(u,s);renderEfficiency(s);renderText('goal',p.goal||'No active plan.');renderHTML('steps',p.steps.map(x=>`<div class="step ${esc(x.state)}"><div class="step-title">${x.id}. ${esc(x.title)} <span class="badge">${esc(x.state)}</span></div><div>${esc(x.objective)}</div><div class="small">Test changes: ${esc(x.test_change_policy)}</div>${(x.acceptance||[]).length?`<div class="small"><b>Acceptance criteria</b></div><ul class="criteria">${x.acceptance.map(a=>`<li>${esc(a)}</li>`).join('')}</ul>`:''}</div>`).join('')||'<div class="small">No plan steps.</div>');renderHTML('gate',s.gate?`<div class="notice gate"><div><b id="gateId">${esc(s.gate.id)}</b> · Step ${s.gate.step}</div><div class="step-title">${esc(s.gate.title||'Human review')}</div><div class="small">${s.gate.policy_review?'POLICY / AUTHORITY REVIEW':'OPERATOR EVIDENCE REVIEW'} · tests=${esc(s.gate.test_change_policy)}</div><h3>Why Ralph stopped</h3>${prettyOutput(s.gate.block_reason)}${(s.gate.acceptance||[]).length?`<h3>Acceptance criteria</h3><ul class="criteria">${s.gate.acceptance.map(a=>`<li>${esc(a)}</li>`).join('')}</ul>`:''}${s.gate.authority_block?`<h3>Controller self-hosting authority block</h3><div>${(s.gate.authority_block.paths||[]).map(path=>`<div class="file">${esc(path)}</div>`).join('')}</div><div class="small">Plan ${esc(s.gate.authority_block.plan_hash||'')} · step ${esc(s.gate.authority_block.step)} · gate ${esc(s.gate.authority_block.gate_id||'')}</div>`:''}<h3>Recommended action</h3><div>${esc(s.gate.recommendation||'Review the evidence and choose a bounded operator action.')}</div></div>`:'<div class="small">No open human gate.</div>');renderControls(s);const events=s.events.map(e=>`<div class="event ${esc(e.category||'')}"><b>${esc(e.category||'EVENT')}</b> ${esc(e.message||'')}</div>`).join('');if(renderHTML('events',events))document.getElementById('events').scrollTop=document.getElementById('events').scrollHeight;renderHTML('files',(c.plan_changed_files||[]).map(x=>`<div class="file">${esc(x)}</div>`).join('')||'<div class="small">No recorded plan files yet.</div>');renderReport(s.report);renderText('log',(s.live_log||[]).join('\n')||'No output yet.');const pidText=localActionState?localActionState.toLowerCase():(rt.active?`pid ${rt.pid}`:(j.active?`pid ${j.pid}`:'pid idle'));renderText('job',pidText);renderClass('job','badge '+((rt.active||j.active||localActionState)?'info':''));renderText('refresh','live');renderClass('refresh','badge ok');}
async function refresh(){const generation=++refreshGeneration;try{const r=await fetch('/api/snapshot',{cache:'no-store'});if(r.status===401){location.reload();return;}if(!r.ok)throw new Error('snapshot '+r.status);const s=await r.json();if(generation!==refreshGeneration)return;latestSnapshot=s;render(latestSnapshot);renderSelfHostingReview();renderActionFeedback();renderHTML('error','');}catch(e){if(generation!==refreshGeneration)return;renderText('refresh','offline');renderClass('refresh','badge bad');showError(e.message);}}
refresh();setInterval(refresh,1500);
</script></body></html>'''

LOGIN_PAGE = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><title>RALPH-Lite Login</title><style>:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#081018;color:#dce7f2;font:14px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace;padding:16px}.login{width:min(420px,100%);background:#101b26;border:1px solid #263647;border-radius:14px;padding:22px;box-shadow:0 15px 40px rgba(0,0,0,.35)}h1{font-size:22px;margin:0 0 4px}.muted{color:#8495a7;margin-bottom:18px}label{display:block;margin:10px 0 4px}input,button{width:100%;font:inherit;font-size:16px;border-radius:8px;padding:11px;background:#071019;color:#dce7f2;border:1px solid #395069}button{margin-top:15px;background:#173429;border-color:#2d7350;color:#8bf0b7;min-height:46px}.err{color:#ff8e95;margin-top:10px;min-height:20px}</style></head><body><form class="login" onsubmit="login(event)"><h1>RALPH-Lite <span style="color:#61d7e6">v__VERSION__</span></h1><div class="muted">__PROJECT_LOGIN_SUBTITLE__</div><label>Username</label><input id="user" autocomplete="username" autofocus required><label>Password</label><input id="pass" type="password" autocomplete="current-password" required><button>Sign in</button><div id="err" class="err"></div></form><script>const CSRF='__CSRF__';async function login(e){e.preventDefault();const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json','X-RALPH-CSRF':CSRF},body:JSON.stringify({username:document.getElementById('user').value,password:document.getElementById('pass').value})});const j=await r.json();if(r.ok&&j.ok){location.reload();return;}document.getElementById('err').textContent=j.error||'Sign in failed';}</script></body></html>'''


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
    server_version = "RALPH-Lite-Web/0.4.0"

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
                self._send_html(LOGIN_PAGE.replace("__CSRF__", token).replace("__VERSION__", VERSION).replace("__PROJECT_LOGIN_SUBTITLE__", html.escape(PROJECT_PROFILE.web_login_subtitle)))
            else:
                self._send_html(PAGE.replace("__CSRF__", token).replace("__PROJECT_WEB_TITLE__", html.escape(PROJECT_PROFILE.web_title)).replace("__PROJECT_WEB_CONSOLE_SUBTITLE__", html.escape(PROJECT_PROFILE.web_console_subtitle)))
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
            if result.get("ok") and str(payload.get("action") or "") in {
                "redeem_reset", "usage_reset_stats", "model_update", "model_reset", "effort_update", "effort_reset",
            }:
                monitor = getattr(self.server, "usage_monitor", None)
                if monitor is not None:
                    try:
                        monitor.refresh()
                    except (OSError, subprocess.SubprocessError, ValueError):
                        # The action has already succeeded; the normal monitor loop will retry.
                        pass
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
