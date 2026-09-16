#!/usr/bin/env python3
"""Local zero-dependency web console for RALPH-Lite.

The web console is an operator surface only. It never owns controller semantics:
all state transitions are performed by the existing scripts/ralph.py CLI. The
server binds to loopback by default; explicit private-LAN mode adds a per-start browser access token and retains CSRF for every write.
"""
from __future__ import annotations

import argparse
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
VERSION = "0.3.1"
MAX_EVENTS = 240
MAX_LOG_LINES = 160
MAX_BODY = 64 * 1024


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
    return {
        "id": f"HG-{loop_no:04d}-{step_no:02d}",
        "step": step_no,
        "title": (step or {}).get("title") or "Human review",
        "block_reason": block,
        "policy_review": policy,
        "test_change_policy": (step or {}).get("test_change_policy") or "none",
        "acceptance": (step or {}).get("acceptance") or [],
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


def snapshot() -> dict[str, Any]:
    state = _read_json(STATE, {})
    if not isinstance(state, dict):
        state = {}
    usage = state.get("codex_usage") if isinstance(state.get("codex_usage"), dict) else {}
    windows = usage.get("windows") if isinstance(usage.get("windows"), list) else []
    remaining = min((float(row.get("remaining_percent", 100.0)) for row in windows), default=None)
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
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>RALPH-Lite</title>
<style>
:root{color-scheme:dark;--bg:#081018;--panel:#101b26;--panel2:#0c151e;--text:#dce7f2;--muted:#8495a7;--green:#5ee19a;--yellow:#f4ca64;--red:#ff6b73;--blue:#6ab7ff;--cyan:#61d7e6;--magenta:#c98aff;--line:#263647;--shadow:0 10px 28px rgba(0,0,0,.28)}
*{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace}.wrap{max-width:1600px;margin:auto;padding:18px}.top{display:grid;grid-template-columns:1fr auto;gap:14px;align-items:center;margin-bottom:14px}.brand{font-size:22px;font-weight:800}.sub{color:var(--muted)}.badge{display:inline-block;padding:4px 8px;border:1px solid var(--line);border-radius:999px;margin:2px}.ok{color:var(--green)}.warn{color:var(--yellow)}.bad{color:var(--red)}.info{color:var(--cyan)}.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:12px}.card{background:linear-gradient(180deg,var(--panel),var(--panel2));border:1px solid var(--line);border-radius:12px;padding:14px;box-shadow:var(--shadow);min-width:0}.span3{grid-column:span 3}.span4{grid-column:span 4}.span5{grid-column:span 5}.span6{grid-column:span 6}.span7{grid-column:span 7}.span8{grid-column:span 8}.span12{grid-column:span 12}h2{font-size:13px;letter-spacing:.08em;text-transform:uppercase;color:var(--cyan);margin:0 0 10px}h3{font-size:14px;margin:10px 0 6px}.metric{font-size:27px;font-weight:800}.kv{display:grid;grid-template-columns:max-content 1fr;gap:4px 12px}.kv>div:nth-child(odd){color:var(--muted)}.steps{display:grid;gap:7px}.step{border-left:3px solid var(--line);padding:7px 9px;background:#0a131c}.step.PASS,.step.ACCEPTED,.step.HUMAN_CONFIRMED{border-color:var(--green)}.step.CURRENT{border-color:var(--cyan)}.step.PENDING{border-color:#39495a}.step-title{font-weight:700}.small{font-size:12px;color:var(--muted)}pre{white-space:pre-wrap;word-break:break-word;background:#071019;border:1px solid var(--line);border-radius:8px;padding:10px;max-height:460px;overflow:auto;margin:0}.events{height:520px;overflow:auto;border:1px solid var(--line);border-radius:8px;background:#071019}.event{padding:5px 9px;border-bottom:1px solid #132131}.READ{color:var(--blue)}.EDIT,.WARN,.POLICY{color:var(--yellow)}.CREATE,.PASS,.COMPLETE,.READY{color:var(--green)}.DELETE,.FAIL,.ERROR,.ENV{color:var(--red)}.BLOCKED,.STEER,.GATE-HUMAN{color:var(--magenta)}.RUN,.CMD,.COMMAND,.GATE,.VALIDATE,.CHECKPOINT{color:var(--cyan)}button{font:inherit;background:#172535;color:var(--text);border:1px solid #395069;border-radius:7px;padding:7px 10px;cursor:pointer}button:hover{border-color:var(--cyan)}button.danger{border-color:#7a3138;color:#ff9ba1}button.good{border-color:#2d7350;color:#8bf0b7}input,textarea{width:100%;font:inherit;background:#071019;color:var(--text);border:1px solid var(--line);border-radius:7px;padding:8px}textarea{min-height:90px}.actions{display:flex;gap:7px;flex-wrap:wrap;margin-top:8px}.form{display:grid;gap:7px}.notice{padding:9px;border-left:3px solid var(--cyan);background:#09141e;margin:8px 0}.gate{border-left-color:var(--magenta)}.errorbox{border-left-color:var(--red)}.file{color:var(--blue)}.footer{margin:14px 0;color:var(--muted);font-size:12px}@media(max-width:1000px){.span3,.span4,.span5,.span6,.span7,.span8{grid-column:span 12}.grid{grid-template-columns:repeat(12,1fr)}}
</style></head><body><div class="wrap">
<div class="top"><div><div class="brand">RALPH-Lite <span id="version" class="info"></span></div><div class="sub">Local operator console · CLI/TUI remains authoritative</div></div><div><span id="refresh" class="badge">connecting</span><span id="job" class="badge">job -</span></div></div>
<div id="error"></div>
<div class="grid">
<section class="card span3"><h2>Controller</h2><div id="status" class="metric">-</div><div id="controller" class="kv"></div></section>
<section class="card span3"><h2>Plan</h2><div id="planMetric" class="metric">-</div><div id="planMeta" class="kv"></div></section>
<section class="card span3"><h2>Quota / Efficiency</h2><div id="quota" class="metric">-</div><div id="eff" class="kv"></div></section>
<section class="card span3"><h2>Git</h2><div id="branch" class="metric">-</div><div id="git" class="kv"></div></section>
<section class="card span7"><h2>Plan Progress</h2><div id="goal" class="notice"></div><div id="steps" class="steps"></div></section>
<section class="card span5"><h2>Human Control</h2><div id="gate"></div><div id="controls"></div></section>
<section class="card span8"><h2>Live Activity</h2><div id="events" class="events"></div></section>
<section class="card span4"><h2>Plan Files</h2><div id="files"></div></section>
<section class="card span6"><h2>Completion Report</h2><pre id="report">No completion report yet.</pre></section>
<section class="card span6"><h2>Controller Output</h2><pre id="log">No output yet.</pre></section>
</div><div class="footer">Loopback by default · private-LAN mode requires an access token · writes also require CSRF · no force-push or policy bypass is exposed</div>
</div>
<script>
const CSRF='__CSRF__';
const ACCESS=decodeURIComponent((location.hash||'').replace(/^#/,''));
if(location.hash){history.replaceState(null,'',location.pathname+location.search);}
let lastStatus='';
function authHeaders(extra={}){const h={...extra};if(ACCESS)h['X-RALPH-AUTH']=ACCESS;return h;}
function esc(s){return String(s??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));}
function kv(obj){return Object.entries(obj).map(([k,v])=>`<div>${esc(k)}</div><div>${esc(v??'-')}</div>`).join('');}
async function post(payload){const r=await fetch('/api/action',{method:'POST',headers:authHeaders({'Content-Type':'application/json','X-RALPH-CSRF':CSRF}),body:JSON.stringify(payload)});const j=await r.json();if(!r.ok||!j.ok) throw new Error(j.error||j.stderr||'action failed');return j;}
function controlButton(label,action,extra={},cls=''){return `<button class="${cls}" onclick='act(${JSON.stringify(action)},${JSON.stringify(extra)})'>${esc(label)}</button>`;}
async function act(action,extra={}){try{let p={action,...extra}; if(['reject','resume','resolve_gate','retire'].includes(action)){const reason=prompt('Reason / evidence:');if(!reason)return;p.reason=reason;} if(action==='retire'){if(prompt('Type RETIRE to confirm')!=='RETIRE')return;p.confirm='RETIRE';} if(action==='finalize_commit'){if(prompt('Type COMMIT to confirm')!=='COMMIT')return;p.confirm='COMMIT';} if(action==='finalize_push'){if(prompt('Type PUSH to confirm')!=='PUSH')return;p.confirm='PUSH';} const j=await post(p); if(j.stdout||j.stderr) alert((j.stdout||'')+(j.stderr||'')); await refresh();}catch(e){showError(e.message);}}
async function submitGoal(){const goal=document.getElementById('goalInput').value.trim();if(!goal)return;try{await post({action:'propose',goal});await refresh();}catch(e){showError(e.message);}}
async function submitSteer(){const direction=document.getElementById('steerInput').value.trim();const gate=document.getElementById('gateId').textContent.trim();if(!direction)return;try{await post({action:'steer',gate,direction});await refresh();}catch(e){showError(e.message);}}
function showError(msg){document.getElementById('error').innerHTML=`<div class="notice errorbox">${esc(msg)}</div>`;}
function renderControls(s){const c=s.controller,g=s.gate;let out='';const st=c.status;if(['IDLE','PLAN_COMPLETE','PUSHED'].includes(st)){out=`<div class="form"><textarea id="goalInput" placeholder="Describe the bounded engineering goal..."></textarea><button class="good" onclick="submitGoal()">Propose plan</button></div>`;} else if(st==='AWAITING_APPROVAL'){out=`<div class="actions">${controlButton('Approve plan','approve',{},'good')}${controlButton('Reject','reject',{},'danger')}</div>`;} else if(['APPROVED','RUNNING','PAUSED_USAGE_LIMIT'].includes(st)){out=`<div class="actions">${controlButton('Run approved plan','run',{max_loops:40},'good')}</div>`;} else if(st==='BLOCKED_HUMAN'){out=`<div class="form"><textarea id="steerInput" placeholder="Bounded human direction for this exact gate..."></textarea><button onclick="submitSteer()">Steer & retry</button><div class="actions">${controlButton('Resume retry','resume')}${controlButton('Resolve delegated gate','resolve_gate',{gate:g?.id||''},'good')}${controlButton('Retire plan','retire',{},'danger')}</div></div>`;} else if(st==='READY_TO_COMMIT'){out=`<div class="actions">${controlButton('Finalization review','finalize_review')}${controlButton('Commit qualified delta','finalize_commit',{},'good')}</div>`;} else if(st==='COMMITTED'){out=`<div class="actions">${controlButton('Push to configured upstream','finalize_push',{},'good')}</div>`;} else {out=`<div class="small">No web action for state ${esc(st)}. Use the CLI for exceptional recovery.</div>`;} document.getElementById('controls').innerHTML=out;}
function render(s){document.getElementById('version').textContent='v'+s.version;const c=s.controller,p=s.plan,g=s.git,j=s.job;document.getElementById('status').textContent=c.status;document.getElementById('controller').innerHTML=kv({plan:(c.plan_hash||'-').slice(0,16),step:`${c.current_step}/${c.step_count||'-'}`,loops:c.loop_count,recovery:c.recovery_checkpoint||'-'});document.getElementById('planMetric').textContent=`${Math.min(c.current_step,c.step_count||0)}/${c.step_count||'-'}`;document.getElementById('planMeta').innerHTML=kv({steering:c.steering_count,commit:(c.commit_sha||'-').slice(0,12),upstream:c.push_upstream||'-'});document.getElementById('quota').textContent=c.quota_remaining_percent==null?'-':c.quota_remaining_percent.toFixed(1)+'%';document.getElementById('eff').innerHTML=kv({efficiency:c.efficiency,job:j.active?`RUNNING pid ${j.pid}`:'idle'});document.getElementById('branch').textContent=g.branch;document.getElementById('git').innerHTML=kv({upstream:g.upstream||'-',dirty:g.dirty?`${g.dirty_count} files`:'clean',head:(g.head||'-').slice(0,12)});document.getElementById('goal').textContent=p.goal||'No active plan.';document.getElementById('steps').innerHTML=p.steps.map(x=>`<div class="step ${esc(x.state)}"><div class="step-title">${x.id}. ${esc(x.title)} <span class="badge">${esc(x.state)}</span></div><div class="small">tests=${esc(x.test_change_policy)} · ${esc(x.objective)}</div></div>`).join('')||'<div class="small">No plan steps.</div>';document.getElementById('gate').innerHTML=s.gate?`<div class="notice gate"><b id="gateId">${esc(s.gate.id)}</b> · Step ${s.gate.step}<br>${esc(s.gate.block_reason)}<br><span class="small">policy=${s.gate.policy_review?'review':'operator'} · tests=${esc(s.gate.test_change_policy)}</span></div>`:'<div class="small">No open human gate.</div>';renderControls(s);const ev=document.getElementById('events');ev.innerHTML=s.events.map(e=>`<div class="event ${esc(e.category||'')}"><b>${esc(e.category||'EVENT')}</b> ${esc(e.message||'')}</div>`).join('');ev.scrollTop=ev.scrollHeight;document.getElementById('files').innerHTML=(c.plan_changed_files||[]).map(x=>`<div class="file">${esc(x)}</div>`).join('')||'<div class="small">No recorded plan files yet.</div>';document.getElementById('report').textContent=s.report?.preview||'No completion report yet.';document.getElementById('log').textContent=(s.live_log||[]).join('\n')||'No output yet.';document.getElementById('job').textContent=j.active?`job RUNNING ${j.pid}`:'job idle';document.getElementById('job').className='badge '+(j.active?'info':'');document.getElementById('refresh').textContent='live';document.getElementById('refresh').className='badge ok';lastStatus=c.status;}
async function refresh(){try{const r=await fetch('/api/snapshot',{cache:'no-store',headers:authHeaders()});if(!r.ok)throw new Error(r.status===401?'LAN access token missing or invalid':'snapshot '+r.status);const s=await r.json();render(s);document.getElementById('error').innerHTML='';}catch(e){document.getElementById('refresh').textContent='offline';document.getElementById('refresh').className='badge bad';showError(e.message);}}
refresh();setInterval(refresh,1500);
</script></body></html>'''


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
        access_token: str | None,
    ):
        super().__init__(address, handler)
        self.csrf_token = csrf_token
        self.allowed_hosts = set(allowed_hosts)
        self.lan_mode = bool(lan_mode)
        self.access_token = access_token


class Handler(BaseHTTPRequestHandler):
    server_version = "RALPH-Lite-Web/0.3.1"

    def _host_allowed(self) -> bool:
        return host_header_allowed(self.headers.get("Host"), getattr(self.server, "allowed_hosts", set()))

    def _auth_allowed(self) -> bool:
        if not bool(getattr(self.server, "lan_mode", False)):
            return True
        expected = str(getattr(self.server, "access_token", "") or "")
        supplied = str(self.headers.get("X-RALPH-AUTH") or "")
        return bool(expected) and secrets.compare_digest(supplied, expected)

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("[ralph-web] " + (fmt % args) + "\n")

    def _send_json(self, payload: Any, status: int = 200) -> None:
        raw = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
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
            self._send_html(PAGE.replace("__CSRF__", token))
            return
        if not self._auth_allowed():
            self._send_json({"ok": False, "error": "LAN access token required"}, HTTPStatus.UNAUTHORIZED)
            return
        if path == "/api/snapshot":
            self._send_json(snapshot())
            return
        if path == "/api/health":
            self._send_json({
                "ok": True,
                "version": VERSION,
                "lan_mode": bool(getattr(self.server, "lan_mode", False)),
                "auth_required": bool(getattr(self.server, "lan_mode", False)),
            })
            return
        self._send_json({"ok": False, "error": "not found"}, 404)

    def do_POST(self) -> None:  # noqa: N802
        if not self._host_allowed():
            self._send_json({"ok": False, "error": "invalid Host header"}, HTTPStatus.MISDIRECTED_REQUEST)
            return
        if not self._auth_allowed():
            self._send_json({"ok": False, "error": "LAN access token required"}, HTTPStatus.UNAUTHORIZED)
            return
        if urlparse(self.path).path != "/api/action":
            self._send_json({"ok": False, "error": "not found"}, 404)
            return
        if self.headers.get("X-RALPH-CSRF") != self.server.csrf_token:  # type: ignore[attr-defined]
            self._send_json({"ok": False, "error": "invalid CSRF token"}, 403)
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
    access_token: str | None = None,
) -> ConsoleServer:
    host = validate_bind(host, allow_lan=allow_lan)
    if not 0 <= int(port) <= 65535:
        raise WebConsoleError("port must be between 0 and 65535")
    ip = ipaddress.ip_address(host)
    lan_mode = not ip.is_loopback
    allowed_hosts = {host.lower()}
    if ip.is_loopback:
        allowed_hosts.update({"localhost", "localhost.", "127.0.0.1", "::1"})
    token = access_token or (secrets.token_urlsafe(32) if lan_mode else None)
    return ConsoleServer(
        (host, int(port)),
        Handler,
        csrf_token=csrf_token or secrets.token_urlsafe(32),
        allowed_hosts=allowed_hosts,
        lan_mode=lan_mode,
        access_token=token,
    )


def _browser_host(host: str) -> str:
    return f"[{host}]" if ":" in host else host


def serve(host: str = "127.0.0.1", port: int = 8765, *, allow_lan: bool = False) -> int:
    RALPH.mkdir(parents=True, exist_ok=True)
    server = build_server(host, port, allow_lan=allow_lan)
    actual_host, actual_port = server.server_address[:2]
    print(f"RALPH-Lite v{VERSION} web console")
    base = f"http://{_browser_host(str(actual_host))}:{actual_port}/"
    if server.lan_mode:
        print(f"URL: {base}#{server.access_token}")
        print("Security: explicit private-LAN mode; exact Host validation + per-start browser access token + CSRF")
        print("Note: use the printed tokenized URL; the token stays in the browser fragment and is not sent in the URL request")
    else:
        print(f"URL: {base}")
        print("Security: loopback-only by default")
    print("Authority: web actions invoke the existing Ralph CLI; no second state machine")
    try:
        server.serve_forever(poll_interval=0.4)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="RALPH-Lite local web console")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--allow-lan", action="store_true")
    args = parser.parse_args(argv)
    try:
        return serve(args.host, args.port, allow_lan=args.allow_lan)
    except (WebConsoleError, OSError) as exc:
        print(f"RALPH-Lite web: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
