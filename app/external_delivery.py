"""External notification delivery adapters for ZEN Control.

Email and webhook delivery are downstream of durable notification evidence and
notification attention policy.  This module has no RouterOS dependency and no
policy mutation authority. SMTP credentials and webhook signing secrets remain
environment-only; ordinary webhook destination metadata is stored in PolicyStore.
"""

from __future__ import annotations

import hashlib
import hmac
import html
import json
import os
import smtplib
import ssl
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formataddr
from typing import Callable

from app.performance import timed


class ExternalDeliveryError(RuntimeError):
    """An external notification delivery could not be completed."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        retryable: bool = True,
        retire_destination: bool = False,
    ):
        super().__init__(message)
        self.status_code = status_code
        self.retryable = bool(retryable)
        self.retire_destination = bool(retire_destination)


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return bool(default)
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, low: int, high: int) -> int:
    try:
        value = int(str(os.getenv(name, str(default))).strip())
    except (TypeError, ValueError):
        value = default
    return max(low, min(value, high))


class NotificationExternalDeliveryService:
    """Durable SMTP and signed-webhook delivery worker."""

    def __init__(
        self,
        *,
        policy_store,
        audit: Callable[[str, str, str], object],
        email_sender: Callable[[dict, str, dict], None] | None = None,
        webhook_sender: Callable[[dict, str, dict], None] | None = None,
        poll_seconds: int | None = None,
    ):
        self.policy_store = policy_store
        self.audit = audit
        self.email_sender = email_sender or self._send_email
        self.webhook_sender = webhook_sender or self._send_webhook
        self.poll_seconds = max(
            2,
            min(int(poll_seconds or os.getenv("ZEN_EXTERNAL_DELIVERY_POLL_SECONDS", "5")), 60),
        )
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._lock = threading.Lock()
        self._last_cycle = {
            "result": "never",
            "summary": "External notification delivery has not run yet.",
            "started_at": "",
            "finished_at": "",
        }

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    @staticmethod
    def smtp_config() -> dict:
        """Return a sanitized/config-capable SMTP description.

        The password value is used internally by the sender but must never be
        returned by snapshot/status APIs.
        """
        return {
            "enabled": _env_bool("ZEN_SMTP_ENABLED", False),
            "host": str(os.getenv("ZEN_SMTP_HOST", "")).strip(),
            "port": _env_int("ZEN_SMTP_PORT", 587, 1, 65535),
            "username": str(os.getenv("ZEN_SMTP_USERNAME", "")).strip(),
            "password": str(os.getenv("ZEN_SMTP_PASSWORD", "")),
            "from_address": str(os.getenv("ZEN_SMTP_FROM", "")).strip(),
            "from_name": str(os.getenv("ZEN_SMTP_FROM_NAME", "ZEN Control")).strip()[:120],
            "to": str(os.getenv("ZEN_SMTP_TO", "")).strip(),
            "starttls": _env_bool("ZEN_SMTP_STARTTLS", True),
            "ssl": _env_bool("ZEN_SMTP_SSL", False),
            "timeout_seconds": _env_int("ZEN_SMTP_TIMEOUT_SECONDS", 10, 2, 60),
        }

    @staticmethod
    def webhook_config() -> dict:
        secret = str(os.getenv("ZEN_WEBHOOK_SIGNING_SECRET", ""))
        return {
            "signing_secret_present": bool(secret),
            "timeout_seconds": _env_int("ZEN_WEBHOOK_TIMEOUT_SECONDS", 10, 2, 60),
            "max_attempts": _env_int("ZEN_WEBHOOK_MAX_ATTEMPTS", 5, 1, 10),
            "allow_http": _env_bool("ZEN_WEBHOOK_ALLOW_HTTP", False),
        }

    @staticmethod
    def _split_addresses(raw: str) -> list[str]:
        values = []
        for chunk in str(raw or "").replace(";", ",").split(","):
            value = chunk.strip()
            if not value:
                continue
            if "@" not in value or any(char in value for char in "\r\n"):
                raise ExternalDeliveryError("ZEN_SMTP_TO contains an invalid email address", retryable=False)
            values.append(value)
        return values

    def readiness(self) -> dict:
        settings = self.policy_store.notification_external_delivery_settings()
        smtp = self.smtp_config()
        webhook = self.webhook_config()
        try:
            recipients = self._split_addresses(smtp["to"])
            email_error = ""
        except ExternalDeliveryError as exc:
            recipients = []
            email_error = str(exc)
        if smtp["ssl"] and smtp["starttls"]:
            email_error = "ZEN_SMTP_SSL and ZEN_SMTP_STARTTLS cannot both be enabled"
        email_ready = bool(
            smtp["enabled"]
            and smtp["host"]
            and smtp["from_address"]
            and recipients
            and not email_error
        )
        webhook_error = ""
        webhook_ready = bool(
            settings.get("webhook_enabled")
            and settings.get("webhook_url")
            and webhook["signing_secret_present"]
        )
        if settings.get("webhook_enabled") and not webhook["signing_secret_present"]:
            webhook_error = "ZEN_WEBHOOK_SIGNING_SECRET is not configured"
        return {
            "email": {
                "enabled": smtp["enabled"],
                "ready": email_ready,
                "host": smtp["host"],
                "port": smtp["port"],
                "from": smtp["from_address"],
                "from_name": smtp["from_name"],
                "recipients": len(recipients),
                "starttls": smtp["starttls"],
                "ssl": smtp["ssl"],
                "credentials_present": bool(smtp["username"] and smtp["password"]),
                "error": email_error,
            },
            "webhook": {
                "enabled": bool(settings.get("webhook_enabled")),
                "ready": webhook_ready,
                "name": str(settings.get("webhook_name") or "Webhook"),
                "url": str(settings.get("webhook_url") or ""),
                "signing_secret_present": webhook["signing_secret_present"],
                "allow_http": webhook["allow_http"],
                "error": webhook_error,
            },
        }

    def snapshot(self) -> dict:
        return {
            "schema": "zen_external_notification_delivery_v1",
            "worker_running": bool(self._thread and self._thread.is_alive()),
            "poll_seconds": self.poll_seconds,
            "channels": self.readiness(),
            "stats": self.policy_store.notification_external_delivery_stats(),
            "history": self.policy_store.list_notification_external_deliveries(limit=30),
            "last_cycle": dict(self._last_cycle),
            "authority": "notification-delivery-only-no-routeros-authority",
        }

    @staticmethod
    def _email_subject(payload: dict) -> str:
        severity = str(payload.get("severity") or "info").upper()
        title = str(payload.get("title") or "ZEN Control notification")[:160]
        return f"[ZEN {severity}] {title}"

    def _send_email(self, payload: dict, destination: str, row: dict) -> None:
        config = self.smtp_config()
        destination_value = config["to"] if str(destination or "").startswith("env:") else destination
        recipients = self._split_addresses(destination_value or config["to"])
        if not config["enabled"]:
            raise ExternalDeliveryError("ZEN SMTP delivery is disabled", retryable=False)
        if not config["host"] or not config["from_address"] or not recipients:
            raise ExternalDeliveryError("ZEN SMTP host, sender and recipient must be configured", retryable=False)
        if config["ssl"] and config["starttls"]:
            raise ExternalDeliveryError("SMTP SSL and STARTTLS cannot both be enabled", retryable=False)

        message = EmailMessage()
        message["From"] = formataddr((config["from_name"], config["from_address"]))
        message["To"] = ", ".join(recipients)
        message["Subject"] = self._email_subject(payload)
        message["X-ZEN-Delivery-ID"] = str(row.get("id") or "")
        message["X-ZEN-Notification-ID"] = str(payload.get("notification_id") or "")
        message["X-ZEN-Event"] = str(payload.get("event") or "notification")
        stable = hashlib.sha256(str(row.get("idempotency_key") or row.get("id") or "").encode()).hexdigest()[:32]
        message["Message-ID"] = f"<zen-notification-{stable}@zen-control.local>"

        body = str(payload.get("detail") or payload.get("body") or "ZEN Control notification")
        source = str(payload.get("source") or "ZEN Control")
        subject = str(payload.get("subject") or "")
        target = str(payload.get("url") or "")
        text_lines = [
            str(payload.get("title") or "ZEN Control notification"),
            "",
            f"Severity: {str(payload.get('severity') or 'info').upper()}",
            f"Source: {source}",
        ]
        if subject:
            text_lines.append(f"Subject: {subject}")
        text_lines.extend(["", body])
        if target:
            text_lines.extend(["", f"ZEN path: {target}"])
        text_lines.extend(["", "This notification is informational/attention evidence and does not itself change RouterOS or policy state."])
        message.set_content("\n".join(text_lines))

        safe_title = html.escape(str(payload.get("title") or "ZEN Control notification"))
        safe_body = html.escape(body).replace("\n", "<br>")
        safe_source = html.escape(source)
        safe_subject = html.escape(subject)
        safe_target = html.escape(target)
        message.add_alternative(
            "<html><body>"
            f"<h2>{safe_title}</h2>"
            f"<p><strong>Severity:</strong> {html.escape(str(payload.get('severity') or 'info').upper())}<br>"
            f"<strong>Source:</strong> {safe_source}"
            + (f"<br><strong>Subject:</strong> {safe_subject}" if subject else "")
            + f"</p><p>{safe_body}</p>"
            + (f"<p><strong>ZEN path:</strong> <code>{safe_target}</code></p>" if target else "")
            + "<p><small>This notification is attention evidence only; it does not itself change RouterOS or policy state.</small></p>"
            "</body></html>",
            subtype="html",
        )

        smtp_cls = smtplib.SMTP_SSL if config["ssl"] else smtplib.SMTP
        context = ssl.create_default_context()
        try:
            if config["ssl"]:
                client = smtp_cls(config["host"], config["port"], timeout=config["timeout_seconds"], context=context)
            else:
                client = smtp_cls(config["host"], config["port"], timeout=config["timeout_seconds"])
            with client:
                client.ehlo()
                if config["starttls"]:
                    client.starttls(context=context)
                    client.ehlo()
                if config["username"]:
                    client.login(config["username"], config["password"])
                client.send_message(message)
        except (smtplib.SMTPException, OSError) as exc:
            raise ExternalDeliveryError(str(exc)[:500] or "SMTP delivery failed") from exc

    def _send_webhook(self, payload: dict, destination: str, row: dict) -> None:
        secret = str(os.getenv("ZEN_WEBHOOK_SIGNING_SECRET", ""))
        if not secret:
            raise ExternalDeliveryError("ZEN_WEBHOOK_SIGNING_SECRET is not configured", retryable=False)
        body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        timestamp = str(int(time.time()))
        signature = hmac.new(secret.encode("utf-8"), timestamp.encode("ascii") + b"." + body, hashlib.sha256).hexdigest()
        event = str(payload.get("event") or "notification")[:120]
        delivery_id = str(row.get("id") or "")
        request = urllib.request.Request(
            destination,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "User-Agent": "ZEN-Control-Notification-Delivery/1",
                "X-ZEN-Event": event,
                "X-ZEN-Delivery-ID": delivery_id,
                "X-ZEN-Timestamp": timestamp,
                "X-ZEN-Signature": f"sha256={signature}",
                "Idempotency-Key": str(row.get("idempotency_key") or f"zen-delivery-{delivery_id}"),
            },
        )
        timeout = self.webhook_config()["timeout_seconds"]
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                status = int(getattr(response, "status", 200) or 200)
                if status < 200 or status >= 300:
                    raise ExternalDeliveryError(
                        f"Webhook returned HTTP {status}",
                        status_code=status,
                        retryable=(status >= 500 or status in {408, 425, 429}),
                        retire_destination=(status == 410),
                    )
        except urllib.error.HTTPError as exc:
            status = int(exc.code or 0)
            retryable = status >= 500 or status in {408, 425, 429}
            raise ExternalDeliveryError(
                f"Webhook returned HTTP {status}",
                status_code=status,
                retryable=retryable,
                retire_destination=(status == 410),
            ) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ExternalDeliveryError(str(exc)[:500] or "Webhook delivery failed") from exc

    @timed("worker.external_notification_delivery.cycle")
    def run_cycle(self) -> dict:
        if not self._lock.acquire(blocking=False):
            return {"result": "busy", "summary": "External delivery cycle already running"}
        started = self._now_iso()
        result = {"result": "ok", "claimed": 0, "sent": 0, "failed": 0, "retried": 0, "retired": 0}
        try:
            self.policy_store.recover_notification_external_deliveries()
            rows = self.policy_store.claim_notification_external_deliveries(limit=20)
            result["claimed"] = len(rows)
            for row in rows:
                try:
                    payload = json.loads(row["payload_json"])
                    if row["channel"] == "email":
                        self.email_sender(payload, row["destination"], row)
                    elif row["channel"] == "webhook":
                        self.webhook_sender(payload, row["destination"], row)
                    else:
                        raise ExternalDeliveryError("Unsupported external delivery channel", retryable=False)
                    self.policy_store.complete_notification_external_delivery(row["id"])
                    result["sent"] += 1
                    self.audit(
                        "NOTIFICATION_EXTERNAL_SENT",
                        "system:external-delivery",
                        f"delivery={row['id']} channel={row['channel']} kind={row.get('kind') or 'notification'}",
                    )
                except Exception as exc:
                    retryable = bool(getattr(exc, "retryable", True))
                    retire = bool(getattr(exc, "retire_destination", False))
                    status_code = getattr(exc, "status_code", None)
                    failed = self.policy_store.fail_notification_external_delivery(
                        row["id"],
                        str(exc)[:500] or exc.__class__.__name__,
                        retryable=retryable,
                        http_status=status_code,
                    )
                    if failed.get("status") == "pending":
                        result["retried"] += 1
                    else:
                        result["failed"] += 1
                    if retire and row["channel"] == "webhook":
                        self.policy_store.retire_notification_webhook(
                            reason=f"Endpoint returned HTTP {status_code or 410}"
                        )
                        result["retired"] += 1
                    self.audit(
                        "NOTIFICATION_EXTERNAL_FAILED",
                        "system:external-delivery",
                        f"delivery={row['id']} channel={row['channel']} status={failed.get('status')} http={status_code or 0} error={str(exc)[:220]}",
                    )
            if result["failed"] or result["retried"]:
                result["result"] = "degraded"
            result["summary"] = (
                f"claimed={result['claimed']} sent={result['sent']} retried={result['retried']} "
                f"failed={result['failed']} retired={result['retired']}"
            )
            return result
        finally:
            finished = self._now_iso()
            self._last_cycle = {**result, "started_at": started, "finished_at": finished}
            self._lock.release()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_cycle()
            except Exception as exc:  # fail-soft background delivery
                self._last_cycle = {
                    "result": "error",
                    "summary": str(exc)[:500],
                    "started_at": self._now_iso(),
                    "finished_at": self._now_iso(),
                }
                try:
                    self.audit("NOTIFICATION_EXTERNAL_WORKER_ERROR", "system:external-delivery", str(exc)[:500])
                except Exception:
                    pass
            self._wake.wait(self.poll_seconds)
            self._wake.clear()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop,
            name="notification-external-delivery",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)

    def wake(self) -> None:
        self._wake.set()

    def enqueue_test(self, channel: str, *, actor: str) -> dict:
        queued = self.policy_store.enqueue_notification_external_test(channel=channel)
        self.audit(
            "NOTIFICATION_EXTERNAL_TEST_QUEUED",
            actor,
            f"channel={channel} queued={queued.get('queued', 0)}",
        )
        self.wake()
        return queued
