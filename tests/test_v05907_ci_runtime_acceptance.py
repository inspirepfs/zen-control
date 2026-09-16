import http.server
import importlib.util
import json
import os
import subprocess
import sys
import threading
import unittest
import io
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _load_runtime_acceptance_module():
    path = ROOT / "scripts" / "runtime_acceptance.py"
    spec = importlib.util.spec_from_file_location("zen_runtime_acceptance", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class _JsonResponse:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return json.dumps({"ok": True, "status": "alive", "version": "0.59.0"}).encode()


class _ResetThenHealthyOpener:
    def __init__(self):
        self.calls = 0

    def open(self, _req, timeout=None):
        self.calls += 1
        if self.calls == 1:
            raise ConnectionResetError(104, "Connection reset by peer")
        return _JsonResponse()


class _AcceptanceHandler(http.server.BaseHTTPRequestHandler):
    username = "ci-parent"
    password = "ci-password"
    break_login = False

    def log_message(self, _format, *_args):
        return

    def _send(self, status, body, *, content_type="text/html", headers=None):
        payload = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path == "/health/live":
            self._send(
                200,
                json.dumps({"ok": True, "status": "alive", "version": "0.59.0"}),
                content_type="application/json",
            )
            return
        if self.path == "/health/runtime":
            self._send(
                200,
                json.dumps({"ok": True, "status": "healthy"}),
                content_type="application/json",
            )
            return
        if self.path == "/login":
            if self.break_login:
                self._send(500, "broken template")
            else:
                self._send(
                    200,
                    '<title>Sign in · ZEN Control</title><form action="/login" method="post"></form>',
                )
            return
        if self.path == "/":
            if "zen_session=ok" not in self.headers.get("Cookie", ""):
                self._send(401, "not authenticated")
            else:
                self._send(
                    200,
                    '<title>ZEN Control</title><a data-tab="dashboard">Dashboard</a>',
                )
            return
        if self.path == "/api/operations/commissioning":
            if "zen_session=ok" not in self.headers.get("Cookie", ""):
                self._send(401, "not authenticated")
            else:
                self._send(
                    200,
                    json.dumps({
                        "schema": "zen_commissioning_report_v1",
                        "overall": "blocked",
                        "checks": [{"key": "routeros_api", "state": "unavailable"}],
                    }),
                    content_type="application/json",
                )
            return
        if self.path == "/local/operations/support-bundle":
            if "zen_session=ok" not in self.headers.get("Cookie", ""):
                self._send(401, "not authenticated")
            else:
                buffer = io.BytesIO()
                with zipfile.ZipFile(buffer, "w") as archive:
                    archive.writestr("manifest.json", json.dumps({"schema": "zen_support_bundle_v1"}))
                    archive.writestr("summary.txt", "ZEN Control Commissioning\n")
                self._send(200, buffer.getvalue(), content_type="application/zip")
            return
        self._send(404, "not found")

    def do_POST(self):
        if self.path != "/login":
            self._send(404, "not found")
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        if f"username={self.username}" not in body or f"password={self.password}" not in body:
            self._send(401, "invalid")
            return
        self.send_response(303)
        self.send_header("Location", "/")
        self.send_header("Set-Cookie", "zen_session=ok; Path=/; HttpOnly")
        self.end_headers()


class RuntimeAcceptanceStartupRetryTests(unittest.TestCase):
    def test_connection_reset_during_container_startup_is_retried(self):
        runtime_acceptance = _load_runtime_acceptance_module()
        opener = _ResetThenHealthyOpener()
        result = runtime_acceptance._wait_for_json(
            opener,
            "http://127.0.0.1:8080",
            "/health/live",
            timeout=2,
            request_timeout=1,
        )
        self.assertTrue(result["ok"])
        self.assertEqual(opener.calls, 2)


class RuntimeAcceptanceScriptTests(unittest.TestCase):
    def setUp(self):
        _AcceptanceHandler.break_login = False
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _AcceptanceHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.base_url = f"http://{host}:{port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def _run_probe(self):
        env = dict(os.environ)
        env["ZEN_RUNTIME_SMOKE_PASSWORD"] = _AcceptanceHandler.password
        return subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "runtime_acceptance.py"),
                "--base-url",
                self.base_url,
                "--expect-version",
                "0.59.0",
                "--admin-user",
                _AcceptanceHandler.username,
                "--admin-password-env",
                "ZEN_RUNTIME_SMOKE_PASSWORD",
                "--startup-timeout",
                "2",
                "--request-timeout",
                "2",
            ],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_acceptance_proves_health_login_and_authenticated_render(self):
        result = self._run_probe()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS · /login 200 rendered", result.stdout)
        self.assertIn("PASS · authenticated dashboard 200 rendered", result.stdout)
        self.assertIn("PASS · commissioning 200 state=blocked checks=1", result.stdout)
        self.assertIn("PASS · support bundle 200 valid-zip sanitized-contract", result.stdout)
        self.assertIn("RUNTIME ACCEPTANCE: PASS", result.stdout)

    def test_render_failure_blocks_acceptance(self):
        _AcceptanceHandler.break_login = True
        result = self._run_probe()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("RUNTIME ACCEPTANCE: FAIL", result.stderr)


class RuntimeAcceptanceWorkflowContractTests(unittest.TestCase):
    def test_quality_workflow_builds_real_container_and_runs_html_smoke(self):
        workflow = (ROOT / ".github" / "workflows" / "quality.yml").read_text()
        self.assertIn("runtime-container-smoke:", workflow)
        self.assertIn("needs: source-quality", workflow)
        self.assertIn("up -d telemetry-db", workflow)
        self.assertIn("State.Health.Status", workflow)
        self.assertIn('status" = "healthy"', workflow)
        self.assertIn("up -d --build mikrotik-control", workflow)
        self.assertLess(
            workflow.index("up -d telemetry-db"),
            workflow.index("up -d --build mikrotik-control"),
        )
        self.assertIn("scripts/runtime_acceptance.py", workflow)
        self.assertIn("--expect-version 0.59.0", workflow)
        self.assertIn("Application logs", workflow)
        self.assertIn("Telemetry database logs", workflow)
        self.assertIn("if: always()", workflow)
        self.assertIn("down -v --remove-orphans", workflow)

    def test_smoke_uses_loopback_router_and_synthetic_credentials(self):
        workflow = (ROOT / ".github" / "workflows" / "quality.yml").read_text()
        self.assertIn("MIKROTIK_HOST: 127.0.0.1", workflow)
        self.assertIn("ADMIN_USER: ci-parent", workflow)
        self.assertIn("ZEN_RUNTIME_SMOKE_PASSWORD", workflow)
        self.assertNotIn("192.168.2.", workflow)


if __name__ == "__main__":
    unittest.main()
