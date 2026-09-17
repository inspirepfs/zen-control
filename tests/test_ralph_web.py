from __future__ import annotations

import importlib.util
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "ralph_web.py"
spec = importlib.util.spec_from_file_location("ralph_web_test_module", MODULE_PATH)
web = importlib.util.module_from_spec(spec)
assert spec.loader is not None
import sys
sys.modules[spec.name] = web
spec.loader.exec_module(web)


class WebHarness:
    NAMES = ("ROOT", "RALPH", "STATE", "EVENTS", "LIVE", "REPORTS", "WEB_JOB", "WEB_LOG", "RALPH_CLI")

    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.saved = {name: getattr(web, name) for name in self.NAMES}

    def __enter__(self):
        ralph = self.root / ".ralph"
        ralph.mkdir()
        scripts = self.root / "scripts"
        scripts.mkdir()
        (scripts / "ralph.py").write_text("#!/usr/bin/env python3\n", encoding="utf-8")
        web.ROOT = self.root
        web.RALPH = ralph
        web.STATE = ralph / "state.json"
        web.EVENTS = ralph / "events.jsonl"
        web.LIVE = ralph / "live.log"
        web.REPORTS = ralph / "reports"
        web.WEB_JOB = ralph / "web-job.json"
        web.WEB_LOG = ralph / "web-run.log"
        web.RALPH_CLI = scripts / "ralph.py"
        return self

    def state(self, **updates):
        state = {
            "status": "APPROVED",
            "plan_hash": "a" * 64,
            "current_step": 2,
            "loop_count": 7,
            "block_reason": None,
            "recovery_checkpoint": "RP-TEST",
            "plan_changed_files": ["app/a.py"],
            "plan_owned_files": ["tests/test_new.py"],
            "human_steering": [],
            "plan": {
                "goal": "Improve ZEN safely",
                "steps": [
                    {"id": i, "title": f"Step {i}", "objective": f"Objective {i}", "acceptance": [f"Acceptance {i}"], "test_change_policy": "add-only"}
                    for i in range(1, 6)
                ],
            },
            "step_results": [{"step": 1, "result": "PASS"}],
            "last_efficiency": {"status": "PASS"},
            "codex_usage": {"windows": [{"remaining_percent": 68.5}]},
        }
        state.update(updates)
        web.STATE.write_text(json.dumps(state), encoding="utf-8")
        return state

    def __exit__(self, exc_type, exc, tb):
        for name, value in self.saved.items():
            setattr(web, name, value)
        self.tmp.cleanup()


class HostSafetyTests(unittest.TestCase):
    def test_loopback_hosts_are_allowed(self):
        self.assertEqual(web.validate_loopback("127.0.0.1"), "127.0.0.1")
        self.assertEqual(web.validate_loopback("localhost"), "127.0.0.1")
        self.assertEqual(web.validate_loopback("::1"), "::1")

    def test_non_loopback_bind_is_refused(self):
        with self.assertRaisesRegex(web.WebConsoleError, "refuses non-loopback"):
            web.validate_loopback("0.0.0.0")
        with self.assertRaises(web.WebConsoleError):
            web.validate_loopback("192.168.2.10")

    def test_private_lan_bind_requires_explicit_opt_in(self):
        with self.assertRaisesRegex(web.WebConsoleError, "--allow-lan"):
            web.validate_bind("192.168.2.10")
        self.assertEqual(web.validate_bind("192.168.2.10", allow_lan=True), "192.168.2.10")
        with self.assertRaisesRegex(web.WebConsoleError, "wildcard"):
            web.validate_bind("0.0.0.0", allow_lan=True)
        with self.assertRaisesRegex(web.WebConsoleError, "private"):
            web.validate_bind("8.8.8.8", allow_lan=True)

    def test_lan_host_header_allows_only_exact_bind_ip(self):
        allowed = {"192.168.2.10"}
        self.assertTrue(web.host_header_allowed("192.168.2.10:8765", allowed))
        self.assertFalse(web.host_header_allowed("192.168.2.11:8765", allowed))
        self.assertFalse(web.host_header_allowed("evil.example:8765", allowed))

    def test_host_header_rejects_dns_rebinding_names(self):
        self.assertTrue(web.host_header_allowed("localhost:8765"))
        self.assertTrue(web.host_header_allowed("127.0.0.1:8765"))
        self.assertTrue(web.host_header_allowed("[::1]:8765"))
        self.assertFalse(web.host_header_allowed("evil.example:8765"))
        self.assertFalse(web.host_header_allowed("192.168.2.10:8765"))


class SnapshotTests(unittest.TestCase):
    def test_snapshot_is_bounded_operator_view(self):
        with WebHarness() as h:
            h.state()
            web.EVENTS.write_text(json.dumps({"category": "EDIT", "message": "app/a.py"}) + "\n", encoding="utf-8")
            with mock.patch.object(web, "git_snapshot", return_value={"branch": "main", "upstream": "origin/main", "head": "abc", "dirty": False, "dirty_count": 0, "status": []}):
                snap = web.snapshot()
            self.assertEqual(snap["controller"]["status"], "APPROVED")
            self.assertEqual(snap["plan"]["steps"][0]["state"], "PASS")
            self.assertEqual(snap["plan"]["steps"][1]["state"], "CURRENT")
            self.assertEqual(snap["controller"]["quota_remaining_percent"], 68.5)
            self.assertEqual(snap["events"][0]["category"], "EDIT")
            self.assertNotIn("proposal_previous_state", json.dumps(snap))

    def test_human_gate_snapshot_is_actionable(self):
        with WebHarness() as h:
            h.state(status="BLOCKED_HUMAN", current_step=3, loop_count=21, block_reason="policy violation: test paths ['tests/test_new.py']")
            gate = web.snapshot()["gate"]
            self.assertEqual(gate["id"], "HG-0021-03")
            self.assertTrue(gate["policy_review"])
            self.assertEqual(gate["test_change_policy"], "add-only")
            self.assertIn("authority mismatch", gate["recommendation"])

    def test_snapshot_exposes_only_matching_controller_self_hosting_candidate(self):
        with WebHarness() as h:
            h.state(
                status="BLOCKED_HUMAN", current_step=3, loop_count=21,
                block_reason="Codex attempted to change RALPH controller/tooling authority",
                self_hosting_candidate={
                    "plan_hash": "a" * 64, "step": 3, "gate_id": "HG-0021-03",
                    "paths": ["scripts/ralph.py"], "detected_at": "2026-09-17T00:00:00+00:00",
                },
            )
            gate = web.snapshot()["gate"]
            candidate = gate["self_hosting_candidate"]
            self.assertEqual(candidate["plan_hash"], "a" * 64)
            self.assertEqual(candidate["step"], 3)
            self.assertEqual(candidate["paths"], ["scripts/ralph.py"])
            self.assertEqual(candidate["gate_id"], "HG-0021-03")
            self.assertEqual(gate["block_reason"], "Codex attempted to change RALPH controller/tooling authority")
            self.assertEqual(
                gate["authority_block"],
                {
                    "kind": "controller_self_hosting_authority",
                    "plan_hash": "a" * 64,
                    "step": 3,
                    "gate_id": "HG-0021-03",
                    "paths": ["scripts/ralph.py"],
                },
            )

    def test_authority_block_echoes_controller_candidate_without_web_path_vetting(self):
        with WebHarness() as h:
            h.state(
                status="BLOCKED_HUMAN", current_step=3, loop_count=21,
                block_reason="Codex attempted to change RALPH controller/tooling authority",
                self_hosting_candidate={
                    "plan_hash": "a" * 64, "step": 3, "gate_id": "HG-0021-03",
                    "paths": ["controller-reported/path"],
                },
            )
            authority = web.snapshot()["gate"]["authority_block"]
            self.assertEqual(authority["paths"], ["controller-reported/path"])

    def test_snapshot_hides_stale_or_ordinary_block_candidates(self):
        with WebHarness() as h:
            for candidate, block_reason in (
                (
                    {"plan_hash": "a" * 64, "step": 3, "gate_id": "HG-0021-03", "paths": ["scripts/ralph.py"]},
                    "operator must provide runtime evidence",
                ),
                (
                    {"plan_hash": "stale-plan", "step": 3, "gate_id": "HG-0021-03", "paths": ["scripts/ralph.py"]},
                    "Codex attempted to change RALPH controller/tooling authority",
                ),
            ):
                with self.subTest(candidate=candidate, block_reason=block_reason):
                    h.state(
                        status="BLOCKED_HUMAN", current_step=3, loop_count=21,
                        block_reason=block_reason, self_hosting_candidate=candidate,
                    )
                    gate = web.snapshot()["gate"]
                    self.assertNotIn("self_hosting_candidate", gate)
                    self.assertNotIn("authority_block", gate)

    def test_snapshot_reports_active_web_operation_without_mutating_durable_state(self):
        with WebHarness() as h:
            h.state(status="READY_TO_COMMIT")
            web.WEB_JOB.write_text(json.dumps({
                "active": True, "mode": "foreground", "pid": 999,
                "activity": "COMMITTING", "argv": ["finalize", "abc", "--commit"],
            }), encoding="utf-8")
            snap = web.snapshot()
            self.assertEqual(snap["controller"]["status"], "COMMITTING")
            self.assertEqual(snap["controller"]["durable_status"], "READY_TO_COMMIT")
            self.assertEqual(snap["job"]["activity"], "COMMITTING")

    def test_event_tail_is_bounded(self):
        with WebHarness() as h:
            h.state()
            web.EVENTS.write_text("\n".join(json.dumps({"category": "READ", "message": str(i)}) for i in range(300)) + "\n", encoding="utf-8")
            rows = web.event_tail(25)
            self.assertEqual(len(rows), 25)
            self.assertEqual(rows[-1]["message"], "299")


class ActionAuthorityTests(unittest.TestCase):
    def base_state(self, status="APPROVED"):
        return {"status": status, "plan_hash": "b" * 64}

    def test_run_is_background_and_bounded(self):
        request = web.command_for_action({"action": "run", "max_loops": 999}, self.base_state())
        self.assertTrue(request.background)
        self.assertIn("--max-loops", request.argv)
        self.assertEqual(request.argv[request.argv.index("--max-loops") + 1], "40")
        self.assertEqual(request.argv[request.argv.index("--efficiency-mode") + 1], "normal")

    def test_run_accepts_explicit_efficiency_dial(self):
        request = web.command_for_action(
            {"action": "run", "max_loops": 10, "efficiency_mode": "off"},
            self.base_state(),
        )
        self.assertEqual(request.argv[request.argv.index("--efficiency-mode") + 1], "off")

    def test_actions_expose_immediate_operational_state(self):
        cases = [
            ({"action": "propose", "goal": "A sufficiently bounded engineering goal"}, {"status": "IDLE"}, "PLANNING"),
            ({"action": "run"}, self.base_state("APPROVED"), "RUNNING"),
            ({"action": "requalify"}, self.base_state("READY_TO_COMMIT"), "QUALIFYING"),
            ({"action": "finalize_review"}, self.base_state("READY_TO_COMMIT"), "REVIEWING"),
            ({"action": "finalize_commit", "confirm": "COMMIT"}, self.base_state("READY_TO_COMMIT"), "COMMITTING"),
            ({"action": "finalize_push", "confirm": "PUSH"}, self.base_state("COMMITTED"), "PUSHING"),
        ]
        for payload, state, activity in cases:
            with self.subTest(action=payload["action"]):
                self.assertEqual(web.command_for_action(payload, state).activity, activity)

    def test_propose_requires_idle_like_state_and_goal(self):
        req = web.command_for_action({"action": "propose", "goal": "A sufficiently bounded engineering goal"}, {"status": "IDLE"})
        self.assertTrue(req.background)
        with self.assertRaises(web.WebConsoleError):
            web.command_for_action({"action": "propose", "goal": "short"}, {"status": "IDLE"})
        with self.assertRaises(web.WebConsoleError):
            web.command_for_action({"action": "propose", "goal": "A sufficiently bounded engineering goal"}, {"status": "RUNNING"})

    def test_requalify_action_is_ready_to_commit_only_and_background(self):
        req = web.command_for_action({"action": "requalify"}, self.base_state("READY_TO_COMMIT"))
        self.assertEqual(req.argv, ["requalify", "b" * 64])
        self.assertTrue(req.background)
        with self.assertRaisesRegex(web.WebConsoleError, "READY_TO_COMMIT"):
            web.command_for_action({"action": "requalify"}, self.base_state("APPROVED"))

    def test_destructive_actions_require_explicit_confirmation(self):
        state = self.base_state("READY_TO_COMMIT")
        with self.assertRaisesRegex(web.WebConsoleError, "confirm=COMMIT"):
            web.command_for_action({"action": "finalize_commit"}, state)
        req = web.command_for_action({"action": "finalize_commit", "confirm": "COMMIT"}, state)
        self.assertIn("--commit", req.argv)
        with self.assertRaisesRegex(web.WebConsoleError, "confirm=PUSH"):
            web.command_for_action({"action": "finalize_push"}, self.base_state("COMMITTED"))
        with self.assertRaisesRegex(web.WebConsoleError, "confirm=RETIRE"):
            web.command_for_action({"action": "retire", "reason": "obsolete"}, self.base_state("BLOCKED_HUMAN"))

    def test_steer_preserves_exact_gate_and_direction(self):
        req = web.command_for_action({
            "action": "steer", "gate": "HG-0021-03", "direction": "Keep the approved test in scope",
            "allow_new_test": ["tests/test_exact.py"],
        }, self.base_state("BLOCKED_HUMAN"))
        self.assertEqual(req.argv[:3], ["steer", "b" * 64, "--gate"])
        self.assertIn("HG-0021-03", req.argv)
        self.assertIn("--allow-new-test", req.argv)

    def self_hosting_state(self):
        return {
            "status": "BLOCKED_HUMAN",
            "plan_hash": "b" * 64,
            "current_step": 3,
            "loop_count": 21,
            "block_reason": "Codex attempted to change RALPH controller/tooling authority",
            "self_hosting_candidate": {
                "plan_hash": "b" * 64,
                "step": 3,
                "gate_id": "HG-0021-03",
                "paths": ["scripts/ralph.py", "scripts/ralph_web.py"],
            },
        }

    def test_self_hosting_action_delegates_exact_controller_candidate(self):
        req = web.command_for_action({
            "action": "authorize_self_hosting",
            "gate": "HG-0021-03",
            "paths": ["scripts/ralph_web.py", "scripts/ralph.py"],
            "reason": "bounded operator approval",
        }, self.self_hosting_state())
        self.assertEqual(
            req.argv,
            [
                "authorize-self-hosting", "b" * 64, "--gate", "HG-0021-03",
                "--path", "scripts/ralph.py", "--path", "scripts/ralph_web.py",
                "--reason", "bounded operator approval",
            ],
        )

    def test_self_hosting_action_ignores_forged_plan_hash_and_normalizes_reason(self):
        req = web.command_for_action({
            "action": "authorize_self_hosting",
            "plan_hash": "c" * 64,
            "gate": "HG-0021-03",
            "paths": ["scripts/ralph.py", "scripts/ralph_web.py"],
            "reason": "  bounded\n operator\tapproval  ",
        }, self.self_hosting_state())
        self.assertEqual(req.argv[:2], ["authorize-self-hosting", "b" * 64])
        self.assertEqual(req.argv[-2:], ["--reason", "bounded operator approval"])

    def test_self_hosting_action_rejects_broadened_or_narrowed_paths(self):
        state = self.self_hosting_state()
        for paths in (["scripts/ralph.py"], ["scripts/ralph.py", "scripts/ralph_web.py", "tests/test_ralph_web.py"]):
            with self.subTest(paths=paths):
                with self.assertRaisesRegex(web.WebConsoleError, "exactly match"):
                    web.command_for_action({
                        "action": "authorize_self_hosting",
                        "gate": "HG-0021-03",
                        "paths": paths,
                        "reason": "bounded operator approval",
                    }, state)

    def test_self_hosting_action_requires_reason_and_matching_gate(self):
        state = self.self_hosting_state()
        with self.assertRaisesRegex(web.WebConsoleError, "reason is required"):
            web.command_for_action({
                "action": "authorize_self_hosting", "gate": "HG-0021-03",
                "paths": state["self_hosting_candidate"]["paths"],
            }, state)
        with self.assertRaisesRegex(web.WebConsoleError, "does not match current gate"):
            web.command_for_action({
                "action": "authorize_self_hosting", "gate": "HG-9999-99",
                "paths": state["self_hosting_candidate"]["paths"],
                "reason": "bounded operator approval",
            }, state)

    def test_page_contains_self_hosting_control_and_persistent_feedback(self):
        self.assertIn("Authorize Self-Hosting", web.PAGE)
        self.assertIn("submitSelfHosting", web.PAGE)
        self.assertIn("renderActionFailure", web.PAGE)
        self.assertIn("actionFeedback=null", web.PAGE)
        self.assertIn("renderSelfHostingReview();renderActionFeedback();renderHTML('error','')", web.PAGE)
        self.assertIn("You are granting authority over named RALPH tooling paths", web.PAGE)
        self.assertIn("Granted authority over named RALPH tooling paths", web.PAGE)
        self.assertIn("data-self-host-path", web.PAGE)
        self.assertIn("selfHostingContext", web.PAGE)
        self.assertIn("Controller-reported context only", web.PAGE)
        self.assertIn("Requalify delta", web.PAGE)
        self.assertIn("renderActionFailure(action,e.message)", web.PAGE)

    def test_self_hosting_submission_uses_current_snapshot_authority_context(self):
        self.assertIn("const authority=latestSnapshot?.gate?.authority_block", web.PAGE)
        self.assertIn("const allowed=new Set(context?.paths||[])", web.PAGE)
        self.assertIn("filter(path=>allowed.has(path))", web.PAGE)
        self.assertIn("gate:context.gate,paths,reason", web.PAGE)
        self.assertIn("paths.length!==context.paths.length", web.PAGE)

    def test_reconciliation_actions_are_explicit(self):
        with self.assertRaises(web.WebConsoleError):
            web.command_for_action({"action": "reconcile_commit", "commit": "abc", "reason": "manual"}, self.base_state("READY_TO_COMMIT"))
        req = web.command_for_action({"action": "reconcile_commit", "commit": "abc", "reason": "manual", "confirm": "ADOPT"}, self.base_state("READY_TO_COMMIT"))
        self.assertEqual(req.argv[0], "reconcile-commit")
        with self.assertRaises(web.WebConsoleError):
            web.command_for_action({"action": "reconcile_push"}, self.base_state("COMMITTED"))


class AuthenticationTests(unittest.TestCase):
    def test_session_auth_login_logout_and_wrong_password(self):
        auth = web.SessionAuth("peter", "correct-horse-battery", session_hours=1)
        self.assertIsNone(auth.login("peter", "wrong-password-value"))
        token = auth.login("peter", "correct-horse-battery")
        self.assertIsNotNone(token)
        self.assertTrue(auth.valid(token))
        auth.logout(token)
        self.assertFalse(auth.valid(token))

    def test_password_file_requires_private_mode(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "password"
            path.write_text("correct-horse-battery\n", encoding="utf-8")
            path.chmod(0o644)
            with self.assertRaisesRegex(web.WebConsoleError, "chmod 600"):
                web._password_from_file(str(path))
            path.chmod(0o600)
            self.assertEqual(web._password_from_file(str(path)), "correct-horse-battery")


class UsageMonitorTests(unittest.TestCase):
    def test_monitor_uses_read_only_usage_refresh(self):
        payload = {"codex_limits": {"plan_type": "plus", "windows": []}, "ledger": {"current_plan": {"input_tokens": 42}}}
        completed = mock.Mock(stdout=json.dumps(payload), returncode=0)
        monitor = web.UsageMonitor(60)
        with mock.patch.object(web.subprocess, "run", return_value=completed) as run:
            report = monitor.refresh()
        self.assertEqual(report["ledger"]["current_plan"]["input_tokens"], 42)
        argv = run.call_args.args[0]
        self.assertEqual(argv[-3:], ["usage", "--json", "--no-save"])
        self.assertIn("--no-save", argv)


class HttpSurfaceTests(unittest.TestCase):
    def test_self_hosting_action_forwards_controller_context_and_preserves_rejection(self):
        with WebHarness() as h:
            state = h.state(
                status="BLOCKED_HUMAN", current_step=3, loop_count=21,
                block_reason="Codex attempted to change RALPH controller/tooling authority",
                self_hosting_candidate={
                    "plan_hash": "a" * 64, "step": 3, "gate_id": "HG-0021-03",
                    "paths": ["scripts/ralph.py", "scripts/ralph_web.py"],
                },
            )
            server = web.build_server("127.0.0.1", 0, csrf_token="known-token")
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            host, port = server.server_address[:2]
            payload = {
                "action": "authorize_self_hosting", "plan_hash": "forged-plan",
                "gate": "HG-0021-03", "paths": ["scripts/ralph_web.py", "scripts/ralph.py"],
                "reason": "bounded operator approval",
            }
            request = urllib.request.Request(
                f"http://{host}:{port}/api/action", data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json", "X-RALPH-CSRF": "known-token"}, method="POST",
            )
            try:
                with mock.patch.object(web, "run_command", return_value={"ok": True, "stdout": "controller accepted"}) as run:
                    self.assertEqual(json.load(urllib.request.urlopen(request, timeout=3))["stdout"], "controller accepted")
                self.assertEqual(
                    run.call_args.args[0].argv,
                    [
                        "authorize-self-hosting", state["plan_hash"], "--gate", "HG-0021-03",
                        "--path", "scripts/ralph.py", "--path", "scripts/ralph_web.py",
                        "--reason", "bounded operator approval",
                    ],
                )
                controller_error = "controller rejected this exact candidate"
                with mock.patch.object(web, "run_command", return_value={"ok": False, "error": controller_error}):
                    with self.assertRaises(urllib.error.HTTPError) as ctx:
                        urllib.request.urlopen(request, timeout=3)
                self.assertEqual(ctx.exception.code, 409)
                self.assertEqual(json.load(ctx.exception)["error"], controller_error)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)

    def test_health_and_snapshot_are_available_but_write_requires_csrf(self):
        with WebHarness() as h:
            h.state()
            with mock.patch.object(web, "git_snapshot", return_value={"branch": "main", "upstream": "origin/main", "head": "abc", "dirty": False, "dirty_count": 0, "status": []}):
                server = web.build_server("127.0.0.1", 0, csrf_token="known-token")
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                host, port = server.server_address[:2]
                try:
                    health = json.load(urllib.request.urlopen(f"http://{host}:{port}/api/health", timeout=3))
                    self.assertTrue(health["ok"])
                    snap = json.load(urllib.request.urlopen(f"http://{host}:{port}/api/snapshot", timeout=3))
                    self.assertEqual(snap["controller"]["status"], "APPROVED")
                    request = urllib.request.Request(
                        f"http://{host}:{port}/api/action",
                        data=json.dumps({"action": "run"}).encode(),
                        headers={"Content-Type": "application/json"}, method="POST",
                    )
                    with self.assertRaises(urllib.error.HTTPError) as ctx:
                        urllib.request.urlopen(request, timeout=3)
                    self.assertEqual(ctx.exception.code, 403)
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=3)

    def test_http_surface_rejects_foreign_host_header(self):
        with WebHarness() as h:
            h.state()
            server = web.build_server("127.0.0.1", 0, csrf_token="known-token")
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            host, port = server.server_address[:2]
            try:
                request = urllib.request.Request(f"http://{host}:{port}/api/health", headers={"Host": "evil.example:8765"})
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    urllib.request.urlopen(request, timeout=3)
                self.assertEqual(ctx.exception.code, 421)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)

    def test_lan_surface_uses_username_password_session_for_api(self):
        with WebHarness() as h:
            h.state()
            with mock.patch.object(web, "git_snapshot", return_value={"branch": "main", "upstream": "origin/main", "head": "abc", "dirty": False, "dirty_count": 0, "status": []}):
                server = web.build_server("127.0.0.1", 0, csrf_token="known-csrf")
                server.lan_mode = True
                server.auth = web.SessionAuth("peter", "correct-horse-battery")
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                host, port = server.server_address[:2]
                try:
                    request = urllib.request.Request(f"http://{host}:{port}/api/snapshot")
                    with self.assertRaises(urllib.error.HTTPError) as ctx:
                        urllib.request.urlopen(request, timeout=3)
                    self.assertEqual(ctx.exception.code, 401)
                    login = urllib.request.Request(
                        f"http://{host}:{port}/api/login",
                        data=json.dumps({"username": "peter", "password": "correct-horse-battery"}).encode(),
                        headers={"Content-Type": "application/json", "X-RALPH-CSRF": "known-csrf"}, method="POST",
                    )
                    response = urllib.request.urlopen(login, timeout=3)
                    cookie = response.headers.get("Set-Cookie").split(";", 1)[0]
                    self.assertIn(web.SESSION_COOKIE + "=", cookie)
                    request = urllib.request.Request(
                        f"http://{host}:{port}/api/snapshot", headers={"Cookie": cookie},
                    )
                    snap = json.load(urllib.request.urlopen(request, timeout=3))
                    self.assertEqual(snap["controller"]["status"], "APPROVED")
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=3)

    def test_index_contains_operator_sections_and_csrf_token(self):
        page = web.PAGE.replace("__CSRF__", "abc123")
        for label in ("Plan Progress", "Human Control", "Live Activity", "Completion Report", "Controller Output"):
            self.assertIn(label, page)
        self.assertIn("abc123", page)
        self.assertIn("Usage / Token Economy", page)
        self.assertIn("@media(max-width:720px)", page)
        self.assertIn("Acceptance criteria", page)
        self.assertIn("Approval review", page)
        self.assertIn("renderActionResult", page)
        self.assertIn("actionResult", page)
        self.assertNotIn("alert((j.stdout", page)
        self.assertNotIn("X-RALPH-AUTH", page)
        human = page.index('<section class="card span12"><h2>Human Control</h2>')
        progress = page.index('<section class="card span12"><h2>Plan Progress</h2>')
        live = page.index('<section class="card span9"><h2>Live Activity</h2>')
        files = page.index('<section class="card span3"><h2>Plan Files</h2>')
        report = page.index('<section class="card span12"><div class="section-title-row"><h2>Completion Report</h2>')
        output = page.index('<section class="card span12"><h2>Controller Output</h2>')
        self.assertLess(human, progress)
        self.assertLess(progress, live)
        self.assertLess(live, files)
        self.assertLess(files, report)
        self.assertLess(report, output)
        self.assertIn('grid-template-columns:repeat(6,minmax(0,1fr))', page)
        self.assertIn('class="plan-comment"', page)
        self.assertIn('class="plan-comment-body"', page)
        self.assertIn('class="usage-tokens"', page)
        self.assertIn("-webkit-line-clamp:2", page)
        self.assertIn("minmax(230px,280px)", page)
        self.assertIn('id="reportRenderedButton"', page)
        self.assertIn('id="reportMarkdownButton"', page)
        self.assertIn("function renderMarkdown(text)", page)
        self.assertIn("function setReportMode(mode)", page)
        self.assertIn("renderReport(s.report)", page)
        self.assertIn("function actionState(action)", page)
        self.assertIn("'QUALIFYING'", page)
        self.assertIn("'REVIEWING'", page)
        self.assertIn("'COMMITTING'", page)
        self.assertIn("'PUSHING'", page)


class BackgroundJobTests(unittest.TestCase):
    def test_second_background_job_is_refused(self):
        with WebHarness() as h:
            h.state()
            web.WEB_JOB.write_text(json.dumps({"active": True, "pid": 1234}), encoding="utf-8")
            with mock.patch.object(web, "_process_alive", return_value=True):
                with self.assertRaisesRegex(web.WebConsoleError, "already active"):
                    web.run_command(web.CommandRequest(["run"], background=True))


if __name__ == "__main__":
    unittest.main()
