"""Standard Web Push delivery for ZEN notification attention.

The service owns only browser/PWA delivery. It has no RouterOS dependency and
never changes incident, policy, reconciliation or source-evidence state.
Subscriptions and delivery attempts are durable in PolicyStore; browser-vendor
push services carry encrypted Web Push payloads using a persistent local VAPID
identity.
"""

from __future__ import annotations

import base64
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.performance import timed


class PushDeliveryError(RuntimeError):
    """A Web Push delivery could not be completed."""

    def __init__(self, message: str, *, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class VapidIdentity:
    """Persistent self-hosted VAPID identity.

    The default key lives beside policy.db in the persistent /data volume. The
    private key never leaves the host; only the public application-server key is
    returned to authenticated browsers.
    """

    def __init__(self, *, key_file: str | None = None, subject: str | None = None):
        self.key_file = str(
            key_file
            or os.getenv("ZEN_PUSH_VAPID_KEY_FILE", "/data/zen-push-vapid-private.pem")
        )
        self.subject = str(
            subject
            or os.getenv("ZEN_PUSH_VAPID_SUBJECT", "mailto:zen-control@example.invalid")
        ).strip()
        if not (self.subject.startswith("mailto:") or self.subject.startswith("https://")):
            raise ValueError("ZEN_PUSH_VAPID_SUBJECT must be a mailto: or https:// URI")
        self._ensure_key()
        self.public_key = self._public_key()

    def _ensure_key(self) -> None:
        path = Path(self.key_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            self._load_private_key()
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            return
        private_key = ec.generate_private_key(ec.SECP256R1())
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        tmp = path.with_suffix(path.suffix + ".tmp")
        with open(tmp, "wb") as handle:
            handle.write(pem)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)

    def _load_private_key(self):
        try:
            key = serialization.load_pem_private_key(Path(self.key_file).read_bytes(), password=None)
        except Exception as exc:  # pragma: no cover - exact backend text varies
            raise ValueError("Configured Web Push VAPID private key is invalid") from exc
        if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
            raise ValueError("Web Push VAPID key must use the P-256 curve")
        return key

    def _public_key(self) -> str:
        private_key = self._load_private_key()
        public = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        return _b64url(public)

    def status(self) -> dict:
        return {
            "configured": True,
            "public_key": self.public_key,
            "subject": self.subject,
            "key_storage": "persistent-local-file",
            "private_key_exposed": False,
        }


class WebPushSender:
    """Small adapter around pywebpush, imported only when a send is attempted."""

    def __init__(self, identity: VapidIdentity):
        self.identity = identity

    def send(self, subscription: dict, payload: dict) -> None:
        try:
            from pywebpush import WebPushException, webpush
        except ImportError as exc:  # pragma: no cover - deployment packaging fault
            raise PushDeliveryError("pywebpush is not installed") from exc

        info = {
            "endpoint": str(subscription.get("endpoint") or ""),
            "keys": {
                "p256dh": str(subscription.get("p256dh") or ""),
                "auth": str(subscription.get("auth") or ""),
            },
        }
        if not info["endpoint"] or not info["keys"]["p256dh"] or not info["keys"]["auth"]:
            raise PushDeliveryError("Push subscription is incomplete")
        try:
            webpush(
                subscription_info=info,
                data=json.dumps(payload, separators=(",", ":"), ensure_ascii=False),
                vapid_private_key=self.identity.key_file,
                vapid_claims={"sub": self.identity.subject},
                ttl=300,
            )
        except WebPushException as exc:  # pragma: no cover - exercised through injected sender tests
            response = getattr(exc, "response", None)
            status = int(getattr(response, "status_code", 0) or 0) or None
            detail = str(exc) or "Web Push provider rejected the request"
            raise PushDeliveryError(detail[:500], status_code=status) from exc


class PushDeliveryService:
    """Durable browser/PWA push outbox processor.

    This worker can perform outbound HTTPS to browser-vendor Web Push endpoints,
    but it has no RouterOS adapter and cannot become an enforcement writer.
    """

    def __init__(
        self,
        *,
        policy_store,
        audit: Callable[[str, str, str], object],
        identity: VapidIdentity | None = None,
        sender: Callable[[dict, dict], None] | None = None,
        poll_seconds: int | None = None,
    ):
        self.policy_store = policy_store
        self.audit = audit
        self.identity = identity or VapidIdentity()
        web_sender = WebPushSender(self.identity)
        self.sender = sender or web_sender.send
        self.poll_seconds = max(
            2,
            min(int(poll_seconds or os.getenv("ZEN_PUSH_POLL_SECONDS", "5")), 60),
        )
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._lock = threading.Lock()
        self._last_cycle = {
            "result": "never",
            "summary": "Push delivery has not run yet.",
            "started_at": "",
            "finished_at": "",
        }

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def snapshot(self, *, username: str | None = None) -> dict:
        return {
            "schema": "zen_push_delivery_status_v1",
            "worker_running": bool(self._thread and self._thread.is_alive()),
            "poll_seconds": self.poll_seconds,
            "vapid": self.identity.status(),
            "subscriptions": self.policy_store.push_subscription_stats(username=username),
            "deliveries": self.policy_store.notification_push_delivery_stats(),
            "last_cycle": dict(self._last_cycle),
            "authority": "notification-delivery-only",
        }

    @timed("worker.push_delivery.cycle")
    def run_cycle(self) -> dict:
        if not self._lock.acquire(blocking=False):
            return {"result": "busy", "summary": "Push delivery cycle already running"}
        started = self._now_iso()
        result = {"result": "ok", "claimed": 0, "sent": 0, "failed": 0, "disabled": 0}
        try:
            self.policy_store.recover_notification_push_deliveries()
            rows = self.policy_store.claim_notification_push_deliveries(limit=20)
            result["claimed"] = len(rows)
            for row in rows:
                subscription = self.policy_store.get_push_subscription(row["subscription_id"], include_secret=True)
                if not subscription or not subscription.get("enabled"):
                    self.policy_store.cancel_notification_push_delivery(
                        row["id"], "Subscription is no longer enabled"
                    )
                    continue
                try:
                    payload = json.loads(row["payload_json"])
                    self.sender(subscription, payload)
                    self.policy_store.complete_notification_push_delivery(row["id"])
                    result["sent"] += 1
                    self.audit(
                        "NOTIFICATION_PUSH_SENT",
                        "system:push-delivery",
                        f"delivery={row['id']} subscription={row['subscription_id']} kind={row.get('kind') or 'notification'}",
                    )
                except Exception as exc:
                    status_code = getattr(exc, "status_code", None)
                    terminal_subscription = status_code in {404, 410}
                    failed = self.policy_store.fail_notification_push_delivery(
                        row["id"],
                        str(exc)[:500] or exc.__class__.__name__,
                        disable_subscription=terminal_subscription,
                    )
                    result["failed"] += 1
                    if terminal_subscription:
                        result["disabled"] += 1
                    self.audit(
                        "NOTIFICATION_PUSH_FAILED",
                        "system:push-delivery",
                        f"delivery={row['id']} status={failed['status']} http={status_code or 0} error={str(exc)[:240]}",
                    )
            if result["failed"]:
                result["result"] = "degraded"
            result["summary"] = (
                f"claimed={result['claimed']} sent={result['sent']} "
                f"failed={result['failed']} disabled={result['disabled']}"
            )
            return result
        except Exception as exc:
            result = {"result": "error", "summary": str(exc), "error": str(exc)}
            self.audit("NOTIFICATION_PUSH_CYCLE_FAILED", "system:push-delivery", str(exc)[:500])
            return result
        finally:
            result["started_at"] = started
            result["finished_at"] = self._now_iso()
            self._last_cycle = dict(result)
            self._lock.release()

    def _loop(self) -> None:
        while not self._stop.is_set():
            self.run_cycle()
            self._wake.wait(timeout=self.poll_seconds)
            self._wake.clear()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="notification-push-delivery", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)

    def wake(self) -> None:
        self._wake.set()
