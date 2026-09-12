from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable

from app.performance import timed

from app.bypass import summarize_bypass_evidence


VALID_INTERVALS = {30, 60, 120, 300}
VALID_BYPASS_THRESHOLDS = {"watch", "elevated", "high"}
_BYPASS_RANK = {"clear": 0, "watch": 1, "elevated": 2, "high": 3}


class IncidentMonitor:
    """Durable, evidence-led incident lifecycle for operator attention.

    The monitor is intentionally read-only with respect to RouterOS. It turns
    already-proven controller signals into durable incidents, deduplicates them,
    and auto-resolves them only after the corresponding source has been scanned
    successfully and the condition is no longer present.
    """

    def __init__(
        self,
        *,
        policy_store: Any,
        router: Any,
        reconciler: Any,
        operations: Any,
        activity_store: Any,
        device_loader: Callable[[], list[dict]],
        policy_loader: Callable[[str], dict],
        audit: Callable[[str, str, str], None],
    ) -> None:
        self.policy_store = policy_store
        self.router = router
        self.reconciler = reconciler
        self.operations = operations
        self.activity_store = activity_store
        self.device_loader = device_loader
        self.policy_loader = policy_loader
        self.audit = audit

        self._stop = threading.Event()
        self._wake = threading.Event()
        self._run_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._last = {
            "started_at": None,
            "finished_at": None,
            "duration_ms": None,
            "result": "never",
            "summary": "Incident monitor has not run yet.",
            "opened": 0,
            "reopened": 0,
            "updated": 0,
            "resolved": 0,
            "errors": [],
        }

    @staticmethod
    def _iso_now() -> str:
        return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")

    def settings(self) -> dict:
        raw = self.policy_store.get_settings()
        enabled = str(raw.get("incident_monitor_enabled", "1")) == "1"
        try:
            interval = int(raw.get("incident_scan_interval_seconds", "60") or 60)
        except (TypeError, ValueError):
            interval = 60
        if interval not in VALID_INTERVALS:
            interval = 60
        threshold = str(raw.get("incident_bypass_min_status", "elevated") or "elevated").lower()
        if threshold not in VALID_BYPASS_THRESHOLDS:
            threshold = "elevated"
        return {
            "enabled": enabled,
            "interval_seconds": interval,
            "bypass_min_status": threshold,
        }

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop,
            name="incident-monitor",
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

    def snapshot(self) -> dict:
        with self._state_lock:
            last = {**self._last, "errors": list(self._last.get("errors") or [])}
        return {
            **self.settings(),
            "worker_alive": bool(self._thread and self._thread.is_alive()),
            "busy": self._run_lock.locked(),
            "last": last,
            "counts": self.policy_store.incident_counts(),
        }

    def _record_signal(
        self,
        active: dict[str, set[str]],
        source: str,
        fingerprint: str,
        *,
        severity: str,
        title: str,
        detail: str,
        subject: str = "",
    ) -> str:
        active.setdefault(source, set()).add(fingerprint)
        result = self.policy_store.upsert_incident(
            fingerprint=fingerprint,
            source=source,
            severity=severity,
            title=title,
            detail=detail,
            subject=subject,
            actor="system:incident-monitor",
        )
        action = result.get("action", "unchanged")
        if action in {"opened", "reopened", "severity_changed"}:
            self.audit(
                "INCIDENT_" + ("OPENED" if action == "opened" else "UPDATED"),
                "system:incident-monitor",
                f"{severity} {fingerprint}: {title}",
            )
        return action

    @timed("worker.incidents.cycle")
    def run_cycle(self, trigger: str = "scheduled") -> dict:
        if not self._run_lock.acquire(blocking=False):
            return {"result": "busy", "summary": "Incident scan already running"}

        started_mono = time.monotonic()
        started_at = self._iso_now()
        settings = self.settings()
        stats = {"opened": 0, "reopened": 0, "updated": 0, "resolved": 0}
        errors: list[str] = []
        active: dict[str, set[str]] = {}
        scanned_sources: set[str] = set()

        try:
            if not settings["enabled"] and trigger == "scheduled":
                result = {
                    "started_at": started_at,
                    "finished_at": self._iso_now(),
                    "duration_ms": int((time.monotonic() - started_mono) * 1000),
                    "result": "disabled",
                    "summary": "Incident monitor is disabled.",
                    **stats,
                    "errors": [],
                }
                self._store_last(result)
                return result

            # Security authority/posture.
            try:
                posture = self.router.get_security_posture()
                scanned_sources.add("security")
                failed = [
                    item for item in posture.get("checks", [])
                    if item.get("severity") == "critical" and item.get("status") == "fail"
                ]
                warned = [
                    item for item in posture.get("checks", [])
                    if item.get("status") == "warn"
                ]
                if failed:
                    names = ", ".join(item.get("name", item.get("key", "unknown")) for item in failed[:8])
                    action = self._record_signal(
                        active,
                        "security",
                        "security:enforcement-authority",
                        severity="critical",
                        title="RouterOS enforcement authority degraded",
                        detail=f"ENFORCE write gate is CLOSED. Critical checks: {names}",
                        subject="RouterOS",
                    )
                    self._count_action(stats, action)
                if warned:
                    names = ", ".join(item.get("name", item.get("key", "unknown")) for item in warned[:8])
                    action = self._record_signal(
                        active,
                        "security",
                        "security:posture-warnings",
                        severity="warning",
                        title="RouterOS security posture has warnings",
                        detail=f"Warning checks: {names}",
                        subject="RouterOS",
                    )
                    self._count_action(stats, action)
            except Exception as exc:
                errors.append(f"security: {exc}")

            # Reconciler state/circuit breaker.
            try:
                rec = self.reconciler.snapshot()
                scanned_sources.add("reconciler")
                if rec.get("hold_active"):
                    action = self._record_signal(
                        active,
                        "reconciler",
                        "reconciler:cooldown-hold",
                        severity="critical",
                        title="Automatic reconciliation is in cooldown hold",
                        detail=(
                            f"Consecutive failures={rec.get('consecutive_failures', 0)}; "
                            f"hold_until={rec.get('hold_until') or 'unknown'}"
                        ),
                        subject="Auto reconciler",
                    )
                    self._count_action(stats, action)
                last = rec.get("last") or {}
                if last.get("result") == "security_hold":
                    action = self._record_signal(
                        active,
                        "reconciler",
                        "reconciler:security-hold",
                        severity="critical",
                        title="Automatic enforcement is security-held",
                        detail=last.get("summary") or "The security gate closed automatic enforcement.",
                        subject="Auto reconciler",
                    )
                    self._count_action(stats, action)
                elif last.get("result") == "failed":
                    action = self._record_signal(
                        active,
                        "reconciler",
                        "reconciler:last-cycle-failed",
                        severity="warning",
                        title="Automatic reconciliation cycle failed",
                        detail=last.get("summary") or "; ".join(last.get("failures") or [])[:1200],
                        subject="Auto reconciler",
                    )
                    self._count_action(stats, action)
            except Exception as exc:
                errors.append(f"reconciler: {exc}")

            # Overall readiness. This is kept as one durable incident rather than
            # exploding every failed component into a duplicate operator alert.
            try:
                ready = self.operations.readiness()
                scanned_sources.add("operations")
                if not ready.get("ok"):
                    issue_list = list(ready.get("issues") or [])
                    # Do not duplicate the dedicated security-authority incident
                    # when readiness is degraded solely because that same gate is
                    # closed. Router/API/DB/worker failures remain distinct.
                    non_security = [
                        item for item in issue_list
                        if item != "RouterOS enforcement posture"
                    ]
                    if non_security:
                        issues = ", ".join(non_security)
                        action = self._record_signal(
                            active,
                            "operations",
                            "operations:not-ready",
                            severity="critical",
                            title="Controller readiness is degraded",
                            detail=f"Readiness failed: {issues}",
                            subject="ZEN Control",
                        )
                        self._count_action(stats, action)
            except Exception as exc:
                errors.append(f"operations: {exc}")

            # Managed-device inventory is needed for both bypass and quota scans.
            devices: list[dict] = []
            try:
                devices = self.device_loader()
            except Exception as exc:
                errors.append(f"devices: {exc}")

            managed_ips = [
                str(item.get("ip") or item.get("address") or "")
                for item in devices
                if item.get("ip") or item.get("address")
            ]

            # Telemetry-backed bypass risk. Do not resolve old bypass incidents
            # when telemetry is unavailable because absence of evidence is then
            # not evidence of clearing.
            if managed_ips:
                try:
                    evidence = self.activity_store.bypass_evidence(managed_ips, 24, 200)
                    summary = summarize_bypass_evidence(evidence)
                    scanned_sources.add("bypass")
                    threshold_rank = _BYPASS_RANK[settings["bypass_min_status"]]
                    for item in summary.get("devices", []):
                        status = str(item.get("status") or "clear")
                        if _BYPASS_RANK.get(status, 0) < threshold_rank:
                            continue
                        ip = str(item.get("client_ip") or "unknown")
                        categories = ", ".join(item.get("categories") or []) or "network"
                        severity = "critical" if status == "high" else "warning"
                        action = self._record_signal(
                            active,
                            "bypass",
                            f"bypass:{ip}",
                            severity=severity,
                            title=f"Managed-device bypass risk is {status.upper()}",
                            detail=(
                                f"Risk score={item.get('score', 0)}; signals={item.get('signals', 0)}; "
                                f"events={item.get('flows', 0)}; categories={categories}. "
                                "This is evidence-led visibility, not protocol proof."
                            ),
                            subject=ip,
                        )
                        self._count_action(stats, action)
                    scanned_sources.add("telemetry")
                except Exception as exc:
                    errors.append(f"telemetry: {exc}")
                    action = self._record_signal(
                        active,
                        "telemetry",
                        "telemetry:bypass-unavailable",
                        severity="warning",
                        title="Bypass telemetry is unavailable",
                        detail=f"Bypass evidence could not be evaluated: {exc}",
                        subject="Telemetry",
                    )
                    self._count_action(stats, action)

            # Quota warnings/exhaustion are generated per device and retain the
            # exact quota key as the fingerprint. A disabled quota engine is not
            # an incident; a configured quota with unavailable telemetry is.
            for device in devices:
                ip = str(device.get("ip") or device.get("address") or "")
                if not ip:
                    continue
                source = f"quota:{ip}"
                try:
                    policy = self.policy_loader(ip)
                    quota = policy.get("quota_state") or {}
                    scanned_sources.add(source)
                    if not quota.get("configured"):
                        continue
                    if quota.get("enabled") and not quota.get("available"):
                        action = self._record_signal(
                            active,
                            source,
                            f"quota:{ip}:telemetry",
                            severity="warning",
                            title="Quota telemetry is unavailable",
                            detail=quota.get("telemetry_error") or "Quota accounting is fail-open.",
                            subject=ip,
                        )
                        self._count_action(stats, action)
                        continue

                    daily = quota.get("daily") or {}
                    if daily.get("exhausted"):
                        action = self._record_signal(
                            active,
                            source,
                            f"quota:{ip}:daily",
                            severity="warning",
                            title="Daily data quota exhausted",
                            detail=(
                                f"{daily.get('used_human', '0 B')} used; limit={daily.get('limit_mb', 0)} MiB; "
                                f"action={str(daily.get('action') or 'blocked').upper()}"
                            ),
                            subject=ip,
                        )
                        self._count_action(stats, action)
                    elif daily.get("warning"):
                        action = self._record_signal(
                            active,
                            source,
                            f"quota:{ip}:daily",
                            severity="warning",
                            title="Daily data quota nearing limit",
                            detail=(
                                f"{daily.get('percent', 0):.1f}% used; "
                                f"{daily.get('used_human', '0 B')} of {daily.get('limit_mb', 0)} MiB"
                            ),
                            subject=ip,
                        )
                        self._count_action(stats, action)

                    for service in quota.get("services") or []:
                        if not service.get("warning") and not service.get("exhausted"):
                            continue
                        key = str(service.get("key") or "unknown")
                        title = (
                            f"{service.get('name') or key} quota exhausted"
                            if service.get("exhausted")
                            else f"{service.get('name') or key} quota nearing limit"
                        )
                        action = self._record_signal(
                            active,
                            source,
                            f"quota:{ip}:service:{key}",
                            severity="warning",
                            title=title,
                            detail=(
                                f"{service.get('percent', 0):.1f}% used; "
                                f"{service.get('used_human', '0 B')} of {service.get('limit_mb', 0)} MiB"
                            ),
                            subject=ip,
                        )
                        self._count_action(stats, action)
                except Exception as exc:
                    errors.append(f"quota {ip}: {exc}")

            # Only auto-resolve a source family after that source completed a
            # successful scan. This is the key false-clear protection.
            for source in sorted(scanned_sources):
                resolved = self.policy_store.resolve_inactive_incidents(
                    source,
                    active.get(source, set()),
                    actor="system:incident-monitor",
                )
                if resolved:
                    stats["resolved"] += len(resolved)
                    for item in resolved:
                        self.audit(
                            "INCIDENT_AUTO_RESOLVED",
                            "system:incident-monitor",
                            f"{item.get('fingerprint')}: signal cleared",
                        )

            result_name = "ok" if not errors else "partial"
            summary = (
                f"Incident scan {result_name}: opened={stats['opened']} reopened={stats['reopened']} "
                f"updated={stats['updated']} resolved={stats['resolved']} errors={len(errors)}"
            )
            result = {
                "started_at": started_at,
                "finished_at": self._iso_now(),
                "duration_ms": int((time.monotonic() - started_mono) * 1000),
                "result": result_name,
                "summary": summary,
                **stats,
                "errors": errors[:12],
            }
            self._store_last(result)
            return result
        finally:
            self._run_lock.release()

    @staticmethod
    def _count_action(stats: dict, action: str) -> None:
        if action == "opened":
            stats["opened"] += 1
        elif action == "reopened":
            stats["reopened"] += 1
        elif action in {"updated", "severity_changed"}:
            stats["updated"] += 1

    def _store_last(self, result: dict) -> None:
        with self._state_lock:
            self._last = {**result, "errors": list(result.get("errors") or [])}

    def _loop(self) -> None:
        # Run immediately on startup, then use the configured bounded cadence.
        while not self._stop.is_set():
            try:
                self.run_cycle(trigger="scheduled")
            except Exception as exc:
                self._store_last({
                    "started_at": self._iso_now(),
                    "finished_at": self._iso_now(),
                    "duration_ms": 0,
                    "result": "failed",
                    "summary": f"Incident monitor failed: {exc}",
                    "opened": 0,
                    "reopened": 0,
                    "updated": 0,
                    "resolved": 0,
                    "errors": [str(exc)],
                })
            interval = self.settings()["interval_seconds"]
            self._wake.wait(timeout=interval)
            self._wake.clear()
