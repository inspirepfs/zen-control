#!/usr/bin/env python3
"""Tiny local webhook receiver for ZEN v0.55.4 delivery qualification."""

from __future__ import annotations

import hashlib
import hmac
import html
import json
import os
import threading
from collections import deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

PORT = int(os.getenv("ZEN_TEST_WEBHOOK_PORT", "8092"))
SECRET = os.getenv("ZEN_TEST_WEBHOOK_SECRET", "")
RECORDS = deque(maxlen=100)
LOCK = threading.Lock()


def verify(headers, body: bytes) -> bool:
    if not SECRET:
        return True
    timestamp = headers.get("X-ZEN-Timestamp", "")
    provided = headers.get("X-ZEN-Signature", "")
    expected = hmac.new(
        SECRET.encode("utf-8"), timestamp.encode("ascii", "ignore") + b"." + body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(provided, f"sha256={expected}")


class Handler(BaseHTTPRequestHandler):
    server_version = "ZENWebhookSink/1.0"

    def log_message(self, fmt, *args):
        print(f"[{datetime.now(timezone.utc).isoformat(timespec='seconds')}] {fmt % args}", flush=True)

    def _send(self, code: int, body: bytes, content_type="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        parsed = urlsplit(self.path)
        if parsed.path != "/webhook":
            self._send(404, b'{"error":"not found"}')
            return
        length = min(int(self.headers.get("Content-Length", "0") or 0), 1024 * 1024)
        body = self.rfile.read(length)
        valid = verify(self.headers, body)
        try:
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            payload = {"raw": body.decode("utf-8", "replace")[:4000]}
        query = parse_qs(parsed.query)
        try:
            requested_status = int((query.get("status") or ["204"])[0])
        except ValueError:
            requested_status = 204
        if not valid:
            requested_status = 401
        record = {
            "received_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "signature_valid": valid,
            "event": self.headers.get("X-ZEN-Event", ""),
            "delivery_id": self.headers.get("X-ZEN-Delivery-ID", ""),
            "timestamp": self.headers.get("X-ZEN-Timestamp", ""),
            "signature": self.headers.get("X-ZEN-Signature", ""),
            "idempotency_key": self.headers.get("Idempotency-Key", ""),
            "response_status": requested_status,
            "payload": payload,
        }
        with LOCK:
            RECORDS.appendleft(record)
        self._send(requested_status, json.dumps({"ok": valid, "stored": True}).encode())

    def do_GET(self):
        parsed = urlsplit(self.path)
        if parsed.path == "/api/deliveries":
            with LOCK:
                body = json.dumps(list(RECORDS), indent=2).encode()
            self._send(200, body)
            return
        if parsed.path not in {"/", "/index.html"}:
            self._send(404, b"not found", "text/plain")
            return
        with LOCK:
            rows = list(RECORDS)
        items = []
        for row in rows:
            payload = row.get("payload") or {}
            items.append(
                "<article style='border:1px solid #ccc;padding:10px;margin:8px 0'>"
                f"<strong>#{html.escape(str(row['delivery_id']))} {html.escape(str(row['event']))}</strong> "
                f"<span>signature={'VALID' if row['signature_valid'] else 'INVALID'} · HTTP {row['response_status']}</span>"
                f"<pre>{html.escape(json.dumps(payload, indent=2)[:12000])}</pre></article>"
            )
        page = (
            "<!doctype html><meta charset='utf-8'><title>ZEN Webhook Sink</title>"
            "<style>body{font-family:system-ui;max-width:1100px;margin:30px auto;padding:0 20px}pre{white-space:pre-wrap;background:#f4f4f4;padding:8px}</style>"
            "<h1>ZEN Webhook Sink</h1>"
            f"<p>Signing verification: {'ENABLED' if SECRET else 'DISABLED'} · retained in memory: {len(rows)}/100.</p>"
            "<p>POST to <code>/webhook</code>. Add <code>?status=500</code>, <code>?status=429</code> or <code>?status=410</code> to exercise failure handling.</p>"
            + "".join(items)
        ).encode()
        self._send(200, page, "text/html; charset=utf-8")


if __name__ == "__main__":
    print(f"ZEN webhook sink listening on 0.0.0.0:{PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
