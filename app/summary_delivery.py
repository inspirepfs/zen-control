"""Durable delivery of parent-facing daily summaries.

The delivery layer consumes the existing parent-summary contract.  It never
queries RouterOS or invents new analytics.  Scheduled sends are explicitly
opt-in, persisted through a SQLite outbox, and idempotent per report/channel.
"""

from __future__ import annotations

import hashlib
import json
import os
import smtplib
import ssl
import threading
import time
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Callable

from app.performance import timed
from urllib import request as urlrequest
from urllib.parse import urlparse
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


DELIVERY_CHANNELS = {"email", "webhook"}
DELIVERY_PERIODS = {"today", "yesterday"}


def normalize_email_recipients(value: str) -> list[str]:
    recipients = []
    seen = set()
    for raw in str(value or "").replace(";", ",").split(","):
        item = raw.strip()
        if not item:
            continue
        if len(item) > 254 or item.count("@") != 1:
            raise ValueError(f"Invalid summary email recipient: {item[:80]}")
        local, domain = item.rsplit("@", 1)
        if not local or "." not in domain or any(ch.isspace() for ch in item):
            raise ValueError(f"Invalid summary email recipient: {item[:80]}")
        lowered = item.lower()
        if lowered not in seen:
            seen.add(lowered)
            recipients.append(item)
    if len(recipients) > 10:
        raise ValueError("Summary delivery supports at most 10 email recipients")
    return recipients


def normalize_webhook_url(value: str) -> str:
    value = str(value or "").strip()
    if not value:
        return ""
    if len(value) > 1000:
        raise ValueError("Summary webhook URL is too long")
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Summary webhook URL must be an http:// or https:// URL")
    if parsed.username or parsed.password:
        raise ValueError("Do not embed credentials in the summary webhook URL")
    return value


def normalize_delivery_time(value: str) -> str:
    value = str(value or "07:00").strip()
    try:
        parsed = datetime.strptime(value, "%H:%M")
    except ValueError as exc:
        raise ValueError("Summary delivery time must use HH:MM in 24-hour format") from exc
    return parsed.strftime("%H:%M")


def delivery_destination(channel: str, settings: dict) -> str:
    if channel == "email":
        return ", ".join(normalize_email_recipients(settings.get("summary_delivery_email_to", "")))
    if channel == "webhook":
        return normalize_webhook_url(settings.get("summary_delivery_webhook_url", ""))
    raise ValueError("Unsupported summary delivery channel")


def render_summary_text(summary: dict) -> str:
    household = summary.get("household") or {}
    current = household.get("current") or {}
    comparison = household.get("comparison") or {}
    total_delta = (comparison.get("total_bytes") or {}).get("delta_percent")
    period = str(summary.get("period") or "daily").replace("_", " ").title()
    delta_text = "n/a" if total_delta is None else f"{float(total_delta):+.1f}%"
    lines = [
        f"ZEN Control parent summary — {period}",
        "",
        f"Managed devices: {household.get('managed_devices', 0)}",
        f"Active devices: {household.get('active_devices', 0)}",
        f"Traffic: {current.get('total_human') or current.get('total_bytes', 0)} ({delta_text} vs previous equivalent window)",
        f"Classification: {current.get('attributed_percent', 0)}% attributed",
        f"DNS queries: {current.get('dns_queries', 0)}",
        f"DNS blocked: {current.get('dns_blocked', 0)}",
        f"New domains: {household.get('new_domains', 0)}",
        f"Unclassified new domains: {household.get('unclassified_new_domains', 0)}",
        f"Quota warnings: {household.get('quota_warnings', 0)}",
        f"Quota exhausted: {household.get('quota_exhausted', 0)}",
        "",
    ]
    devices = list(summary.get("devices") or [])
    if devices:
        lines.append("Managed-device detail")
        for item in devices:
            facts = item.get("current") or {}
            item_delta = ((item.get("comparison") or {}).get("total_bytes") or {}).get("delta_percent")
            item_delta_text = "n/a" if item_delta is None else f"{float(item_delta):+.1f}%"
            signal_text = ", ".join(str(tag).replace("_", " ") for tag in (item.get("signals") or [])) or "none"
            lines.append(
                f"- {item.get('name') or item.get('ip')} ({item.get('ip')}): "
                f"traffic={facts.get('total_human') or facts.get('total_bytes', 0)} ({item_delta_text}), "
                f"dns={facts.get('dns_queries', 0)}, blocked={facts.get('dns_blocked', 0)}, "
                f"signals={signal_text}"
            )
            services = list(item.get("services") or [])[:3]
            if services:
                parts = []
                for service in services:
                    label = service.get("service_name") or service.get("name") or "Unknown"
                    amount = service.get("total_human") or service.get("total_bytes") or service.get("bytes") or 0
                    parts.append(f"{label} {amount}")
                lines.append("  top services: " + "; ".join(parts))
            attention = list(item.get("attention_domains") or [])[:3]
            if attention:
                parts = []
                for domain in attention:
                    tags = "/".join(str(tag).upper() for tag in (domain.get("tags") or []))
                    parts.append(f"{domain.get('domain')} [{tags or 'EVIDENCE'}]")
                lines.append("  DNS attention: " + "; ".join(parts))

    household_attention = list(summary.get("attention_domains") or [])[:8]
    if household_attention:
        lines.extend(["", "Household DNS attention"])
        for item in household_attention:
            tags = "/".join(str(tag).upper() for tag in (item.get("tags") or []))
            device = item.get("device_name") or item.get("client_ip") or "managed device"
            lines.append(f"- {item.get('domain')} — {device} — {tags or 'EVIDENCE'}")

    lines.extend([
        "",
        str(summary.get("evidence_note") or ""),
        "ZEN Control reports network/DNS evidence, not browser history or proof of user intent.",
    ])
    return "\n".join(lines).strip() + "\n"


def build_webhook_payload(summary: dict, *, delivery_id: int | None = None) -> dict:
    window = summary.get("window") or {}
    serial_window = {
        key: (value.isoformat() if hasattr(value, "isoformat") else value)
        for key, value in window.items()
    }
    return {
        "schema": "zen_control_parent_summary_v1",
        "delivery_id": delivery_id,
        "period": summary.get("period"),
        "timezone": summary.get("timezone_name"),
        "window": serial_window,
        "household": summary.get("household") or {},
        "devices": summary.get("devices") or [],
        "attention_domains": summary.get("attention_domains") or [],
        "evidence_note": summary.get("evidence_note") or "",
    }


class SummaryDeliveryService:
    """Background summary scheduler and durable outbox processor."""

    def __init__(
        self,
        *,
        policy_store,
        summary_builder: Callable[[str], dict],
        audit: Callable[[str, str, str], object],
        email_sender: Callable[[dict, str, dict], None] | None = None,
        webhook_sender: Callable[[dict, str, dict], None] | None = None,
        poll_seconds: int | None = None,
    ):
        self.policy_store = policy_store
        self.summary_builder = summary_builder
        self.audit = audit
        self.email_sender = email_sender or self._send_email
        self.webhook_sender = webhook_sender or self._send_webhook
        self.poll_seconds = max(10, min(int(poll_seconds or os.getenv("SUMMARY_DELIVERY_POLL_SECONDS", "30")), 300))
        self._thread = None
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._lock = threading.Lock()
        self._last_cycle = {
            "result": "never",
            "summary": "Parent summary delivery has not run yet.",
            "started_at": "",
            "finished_at": "",
        }
        self._generation_failures = 0
        self._generation_retry_after_epoch = 0.0

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def settings(self) -> dict:
        raw = self.policy_store.get_settings()
        period = str(raw.get("summary_delivery_period", "yesterday")).strip().lower()
        if period not in DELIVERY_PERIODS:
            period = "yesterday"
        return {
            "enabled": str(raw.get("summary_delivery_enabled", "0")) == "1",
            "time": normalize_delivery_time(raw.get("summary_delivery_time", "07:00")),
            "period": period,
            "timezone": str(raw.get("policy_timezone", "Europe/London")),
            "email_enabled": str(raw.get("summary_delivery_email_enabled", "0")) == "1",
            "email_to": str(raw.get("summary_delivery_email_to", "")),
            "webhook_enabled": str(raw.get("summary_delivery_webhook_enabled", "0")) == "1",
            "webhook_url": str(raw.get("summary_delivery_webhook_url", "")),
            "retry_limit": int(raw.get("summary_delivery_retry_limit", "3") or 3),
            "retention_days": int(raw.get("summary_delivery_retention_days", "90") or 90),
        }

    def channel_readiness(self, settings: dict | None = None) -> dict:
        settings = settings or self.settings()
        email_recipients = []
        email_error = ""
        try:
            email_recipients = normalize_email_recipients(settings.get("email_to", ""))
        except ValueError as exc:
            email_error = str(exc)
        smtp_host = str(os.getenv("SUMMARY_SMTP_HOST", "")).strip()
        smtp_from = str(os.getenv("SUMMARY_SMTP_FROM", "")).strip()
        email_ready = bool(email_recipients and smtp_host and smtp_from and not email_error)

        webhook_url = ""
        webhook_error = ""
        try:
            webhook_url = normalize_webhook_url(settings.get("webhook_url", ""))
        except ValueError as exc:
            webhook_error = str(exc)
        webhook_ready = bool(webhook_url and not webhook_error)
        return {
            "email": {
                "enabled": bool(settings.get("email_enabled")),
                "ready": email_ready,
                "recipients": len(email_recipients),
                "smtp_configured": bool(smtp_host and smtp_from),
                "error": email_error,
            },
            "webhook": {
                "enabled": bool(settings.get("webhook_enabled")),
                "ready": webhook_ready,
                "token_configured": bool(os.getenv("SUMMARY_WEBHOOK_TOKEN")),
                "error": webhook_error,
            },
        }

    def next_due(self, settings: dict | None = None, now: datetime | None = None) -> str:
        settings = settings or self.settings()
        if not settings["enabled"]:
            return "Disabled"
        local = self._local_now(now, settings["timezone"])
        hour, minute = (int(part) for part in settings["time"].split(":"))
        due = local.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if local > due:
            due += timedelta(days=1)
        return due.isoformat(timespec="minutes")

    def reconcile_configuration(self) -> int:
        settings = self.settings()
        return self.policy_store.cancel_disabled_summary_deliveries(
            scheduled_enabled=settings["enabled"],
            enabled_channels=self._enabled_channels(settings),
        )

    def snapshot(self) -> dict:
        settings = self.settings()
        return {
            **settings,
            "channels": self.channel_readiness(settings),
            "worker_running": bool(self._thread and self._thread.is_alive()),
            "poll_seconds": self.poll_seconds,
            "next_due": self.next_due(settings),
            "generation_failures": self._generation_failures,
            "generation_retry_after": (
                datetime.fromtimestamp(self._generation_retry_after_epoch, timezone.utc).isoformat(timespec="seconds")
                if self._generation_retry_after_epoch > time.time() else ""
            ),
            "last_cycle": dict(self._last_cycle),
            "stats": self.policy_store.summary_delivery_stats(),
            "history": self.policy_store.list_summary_deliveries(20),
        }

    def _local_now(self, now: datetime | None = None, timezone_name: str | None = None) -> datetime:
        timezone_name = timezone_name or self.settings()["timezone"]
        try:
            tz = ZoneInfo(timezone_name)
        except ZoneInfoNotFoundError as exc:
            raise ValueError(f"Summary delivery timezone '{timezone_name}' is unavailable") from exc
        value = now or datetime.now(timezone.utc)
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(tz)

    def _scheduled_due(self, settings: dict, now: datetime | None = None) -> tuple[bool, str]:
        local = self._local_now(now, settings["timezone"])
        due_h, due_m = (int(part) for part in settings["time"].split(":"))
        due = local.replace(hour=due_h, minute=due_m, second=0, microsecond=0)
        return local >= due, local.date().isoformat()

    def _enabled_channels(self, settings: dict) -> list[str]:
        result = []
        if settings.get("email_enabled"):
            result.append("email")
        if settings.get("webhook_enabled"):
            result.append("webhook")
        return result

    def enqueue_due(self, *, now: datetime | None = None) -> list[dict]:
        settings = self.settings()
        if not settings["enabled"]:
            return []
        due, local_date = self._scheduled_due(settings, now)
        if not due:
            return []
        channels = self._enabled_channels(settings)
        if not channels:
            return []

        local_day = datetime.fromisoformat(local_date).date()
        report_date = (
            local_day.isoformat()
            if settings["period"] == "today"
            else (local_day - timedelta(days=1)).isoformat()
        )
        existing = self.policy_store.scheduled_summary_deliveries(report_date, settings["period"])
        rows = []
        missing = []
        for channel in channels:
            destination = delivery_destination(channel, {
                "summary_delivery_email_to": settings["email_to"],
                "summary_delivery_webhook_url": settings["webhook_url"],
            })
            if not destination:
                continue
            current = existing.get(channel)
            if current:
                if current.get("status") != "sent" and current.get("destination") != destination:
                    current = self.policy_store.update_summary_delivery_destination(current["id"], destination)
                rows.append({**current, "created": False})
            else:
                missing.append((channel, destination))
        if not missing:
            return rows

        summary = self.summary_builder(settings["period"])
        payload = build_webhook_payload(summary)
        for channel, destination in missing:
            row = self.policy_store.enqueue_summary_delivery(
                report_date=report_date,
                period=settings["period"],
                channel=channel,
                destination=destination,
                payload=payload,
                kind="scheduled",
            )
            rows.append(row)
        return rows

    def enqueue_test(self, channel: str, *, actor: str, period: str = "today") -> dict:
        channel = str(channel or "").strip().lower()
        if channel not in DELIVERY_CHANNELS:
            raise ValueError("Select email or webhook for the test delivery")
        settings = self.settings()
        readiness = self.channel_readiness(settings).get(channel) or {}
        if not readiness.get("ready"):
            raise ValueError(f"{channel.title()} delivery is not fully configured")
        if channel == "email" and not settings["email_enabled"]:
            raise ValueError("Enable email summary delivery before sending a test")
        if channel == "webhook" and not settings["webhook_enabled"]:
            raise ValueError("Enable webhook summary delivery before sending a test")
        if period not in DELIVERY_PERIODS:
            raise ValueError("Test summary period must be today or yesterday")

        summary = self.summary_builder(period)
        report_start = (summary.get("window") or {}).get("start")
        report_date = report_start.date().isoformat() if hasattr(report_start, "date") else self._local_now().date().isoformat()
        destination = delivery_destination(channel, {
            "summary_delivery_email_to": settings["email_to"],
            "summary_delivery_webhook_url": settings["webhook_url"],
        })
        row = self.policy_store.enqueue_summary_delivery(
            report_date=report_date,
            period=period,
            channel=channel,
            destination=destination,
            payload=build_webhook_payload(summary),
            kind="test",
            unique_suffix=f"{time.time_ns()}",
        )
        self.audit("SUMMARY_DELIVERY_TEST_QUEUED", actor, f"delivery={row['id']} channel={channel} period={period}")
        self.wake()
        return row

    @timed("worker.summary_delivery.outbox")
    def process_outbox(self) -> dict:
        settings = self.settings()
        readiness = self.channel_readiness(settings)
        due_rows = self.policy_store.claim_summary_deliveries(
            limit=10,
            retry_limit=settings["retry_limit"],
        )
        sent = 0
        failed = 0
        deferred = 0
        for row in due_rows:
            channel = row["channel"]
            channel_state = readiness.get(channel) or {}
            if (row.get("kind") == "scheduled" and not settings["enabled"]) or not channel_state.get("enabled"):
                self.policy_store.cancel_summary_delivery(
                    row["id"], "Cancelled because this delivery channel or schedule is disabled"
                )
                continue
            if not channel_state.get("ready"):
                self.policy_store.defer_summary_delivery(
                    row["id"],
                    f"{channel.title()} transport is not fully configured",
                )
                deferred += 1
                continue
            try:
                payload = json.loads(row["payload_json"])
                sender = self.email_sender if channel == "email" else self.webhook_sender
                sender(payload, row["destination"], row)
                self.policy_store.complete_summary_delivery(row["id"])
                sent += 1
                self.audit(
                    "SUMMARY_DELIVERY_SENT",
                    "system:summary-delivery",
                    f"delivery={row['id']} kind={row['kind']} channel={channel} report={row['report_date']}",
                )
            except Exception as exc:
                message = str(exc)[:500] or exc.__class__.__name__
                result = self.policy_store.fail_summary_delivery(
                    row["id"], message, retry_limit=settings["retry_limit"]
                )
                failed += 1
                self.audit(
                    "SUMMARY_DELIVERY_FAILED",
                    "system:summary-delivery",
                    f"delivery={row['id']} channel={channel} status={result['status']} error={message}",
                )
        return {"claimed": len(due_rows), "sent": sent, "failed": failed, "deferred": deferred}

    @timed("worker.summary_delivery.cycle")
    def run_cycle(self, *, now: datetime | None = None) -> dict:
        if not self._lock.acquire(blocking=False):
            return {"result": "busy", "summary": "Summary delivery cycle already running"}
        started = self._now_iso()
        result = {"result": "ok", "summary": ""}
        try:
            self.reconcile_configuration()
            self.policy_store.recover_summary_deliveries()

            queued = []
            generation_error = ""
            clock = time.time()
            if clock >= self._generation_retry_after_epoch:
                try:
                    queued = self.enqueue_due(now=now)
                    self._generation_failures = 0
                    self._generation_retry_after_epoch = 0.0
                except Exception as exc:
                    generation_error = str(exc)[:500] or exc.__class__.__name__
                    self._generation_failures += 1
                    delay = min(300 * (2 ** max(0, self._generation_failures - 1)), 1800)
                    self._generation_retry_after_epoch = clock + delay
                    self.audit(
                        "SUMMARY_DELIVERY_GENERATION_FAILED",
                        "system:summary-delivery",
                        f"retry_in={delay}s error={generation_error}",
                    )
            elif self._generation_failures:
                generation_error = "Summary generation backoff active after previous failure"

            processed = self.process_outbox()
            self.policy_store.prune_summary_deliveries(self.settings()["retention_days"])
            result = {
                "result": "degraded" if generation_error else "ok",
                "queued": len([row for row in queued if row.get("created")]),
                **processed,
            }
            if generation_error:
                result["generation_error"] = generation_error
                result["generation_retry_after"] = datetime.fromtimestamp(
                    self._generation_retry_after_epoch, timezone.utc
                ).isoformat(timespec="seconds")
            result["summary"] = (
                f"queued={result['queued']} claimed={result['claimed']} sent={result['sent']} "
                f"failed={result['failed']} deferred={result['deferred']}"
                + (f"; summary generation degraded: {generation_error}" if generation_error else "")
            )
            return result
        except Exception as exc:
            result = {"result": "error", "summary": str(exc), "error": str(exc)}
            self.audit("SUMMARY_DELIVERY_CYCLE_FAILED", "system:summary-delivery", str(exc))
            return result
        finally:
            finished = self._now_iso()
            self._last_cycle = {**result, "started_at": started, "finished_at": finished}
            self._lock.release()

    def _loop(self):
        while not self._stop.is_set():
            self.run_cycle()
            self._wake.wait(timeout=self.poll_seconds)
            self._wake.clear()

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="summary-delivery", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._wake.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)

    def wake(self):
        self._wake.set()

    def retry(self, delivery_id: int, *, actor: str) -> dict:
        row = self.policy_store.retry_summary_delivery(delivery_id)
        self.audit("SUMMARY_DELIVERY_RETRY", actor, f"delivery={delivery_id} channel={row['channel']}")
        self.wake()
        return row

    @staticmethod
    def _smtp_env() -> dict:
        host = str(os.getenv("SUMMARY_SMTP_HOST", "")).strip()
        port = int(os.getenv("SUMMARY_SMTP_PORT", "587") or 587)
        username = str(os.getenv("SUMMARY_SMTP_USERNAME", "")).strip()
        password = str(os.getenv("SUMMARY_SMTP_PASSWORD", ""))
        sender = str(os.getenv("SUMMARY_SMTP_FROM", "")).strip()
        starttls = str(os.getenv("SUMMARY_SMTP_STARTTLS", "1")).strip().lower() in {"1", "true", "yes", "on"}
        return {
            "host": host,
            "port": port,
            "username": username,
            "password": password,
            "sender": sender,
            "starttls": starttls,
        }

    def _send_email(self, payload: dict, destination: str, row: dict):
        env = self._smtp_env()
        recipients = normalize_email_recipients(destination)
        if not env["host"] or not env["sender"] or not recipients:
            raise RuntimeError("SMTP host, sender and summary recipients must be configured")
        summary = dict(payload)
        summary.setdefault("period", row.get("period"))
        message = EmailMessage()
        message["From"] = env["sender"]
        message["To"] = ", ".join(recipients)
        message["Subject"] = f"ZEN Control parent summary — {row.get('report_date')}"
        stable_identity = hashlib.sha256(str(row.get("idempotency_key") or row.get("id")).encode("utf-8")).hexdigest()[:32]
        message["Message-ID"] = f"<zen-{stable_identity}@zen-control.local>"
        message["X-ZEN-Delivery-ID"] = str(row.get("id") or "")
        message.set_content(render_summary_text(summary))
        with smtplib.SMTP(env["host"], env["port"], timeout=10) as client:
            client.ehlo()
            if env["starttls"]:
                client.starttls(context=ssl.create_default_context())
                client.ehlo()
            if env["username"]:
                client.login(env["username"], env["password"])
            client.send_message(message)

    def _send_webhook(self, payload: dict, destination: str, row: dict):
        url = normalize_webhook_url(destination)
        body = json.dumps({
            **payload,
            "delivery": {
                "id": row.get("id"),
                "kind": row.get("kind"),
                "report_date": row.get("report_date"),
                "channel": "webhook",
            },
        }, separators=(",", ":"), default=str).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "ZEN-Control/0.25",
            "X-ZEN-Event": "parent-summary",
            "X-ZEN-Delivery-ID": str(row.get("id") or ""),
            "Idempotency-Key": str(row.get("idempotency_key") or ""),
        }
        token = str(os.getenv("SUMMARY_WEBHOOK_TOKEN", "")).strip()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urlrequest.Request(url, data=body, headers=headers, method="POST")
        with urlrequest.urlopen(req, timeout=10) as response:
            status = int(getattr(response, "status", 200))
            if status < 200 or status >= 300:
                raise RuntimeError(f"Webhook returned HTTP {status}")
