from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Callable, Any

from app.performance import timed


VALID_AUTO_MODES = {"off", "observe", "enforce"}
VALID_INTERVALS = {15, 30, 60, 120, 300}
VALID_FAILURE_THRESHOLDS = {1, 2, 3, 5, 10}
VALID_COOLDOWNS = {60, 300, 600, 1800}


class ReconciliationError(RuntimeError):
    pass


def reconcile_device(
    address: str,
    *,
    plan_loader: Callable[[str], dict],
    router: Any,
    description: str,
) -> dict:
    """Apply one effective policy and verify that RouterOS converges.

    The caller owns the authority decision (manual vs automatic). Temporary
    access always wins and is returned as a skip rather than being overwritten.
    """
    plan = plan_loader(address)

    if plan.get("temporary_override"):
        return {
            "address": address,
            "status": "temporary",
            "changes": [],
            "plan": plan,
            "verified": plan,
        }

    if not plan.get("policy_actionable"):
        return {
            "address": address,
            "status": "partial" if plan.get("status") == "partial" else "synced",
            "changes": [],
            "plan": plan,
            "verified": plan,
        }

    changes = []

    if plan.get("mode_drift"):
        before = plan["live_mode"]
        result = router.set_device_mode(
            address,
            plan["desired_mode"],
            description=description,
        )
        changes.append(
            f"mode {str(before).upper()}->{str(result['mode']).upper()}"
        )

    if plan.get("bandwidth_drift"):
        target_preset = (
            plan["bandwidth_preset"]
            if plan.get("bandwidth_expected_active")
            else "normal"
        )
        result = router.set_device_bandwidth(
            address,
            target_preset,
            plan["bandwidth_upload"],
            plan["bandwidth_download"],
            description=description,
        )
        changes.append(
            "bandwidth="
            + (result.get("max_limit") if result.get("active") else "unlimited")
        )

    if plan.get("service_drift"):
        result = router.set_device_services(
            address,
            plan["desired_supported_blocked_services"],
            description=description,
        )
        changes.append(
            "services=" + (",".join(result.get("blocked_services") or []) or "none")
        )
        if result.get("terminated_connections"):
            changes.append(
                f"connections_reset={int(result['terminated_connections'])}"
            )

    verified = plan_loader(address)
    if (
        verified.get("mode_drift")
        or verified.get("service_drift")
        or verified.get("bandwidth_drift")
    ):
        raise ReconciliationError(f"Policy apply did not converge for {address}")

    return {
        "address": address,
        "status": "applied",
        "changes": changes,
        "plan": plan,
        "verified": verified,
    }


class AutoReconciler:
    """Bounded, observable policy reconciliation worker.

    Safety properties:
      * default mode is OFF;
      * OBSERVE computes drift but never writes RouterOS;
      * ENFORCE writes only through the already-proven per-device adapter;
      * temporary access is never overridden;
      * one worker cycle runs at a time;
      * repeated failed cycles open a cooldown hold (circuit breaker);
      * manual reconciliation endpoints remain independent and available.
    """

    def __init__(
        self,
        *,
        policy_store: Any,
        router: Any,
        device_loader: Callable[[], list[dict]],
        plan_loader: Callable[[str], dict],
        audit: Callable[[str, str, str], None],
    ) -> None:
        self.policy_store = policy_store
        self.router = router
        self.device_loader = device_loader
        self.plan_loader = plan_loader
        self.audit = audit

        self._stop = threading.Event()
        self._wake = threading.Event()
        self._cycle_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._thread: threading.Thread | None = None

        self._consecutive_failures = 0
        self._hold_until_epoch = 0.0
        self._last: dict = {
            "started_at": None,
            "finished_at": None,
            "duration_ms": None,
            "trigger": None,
            "mode": "off",
            "result": "never",
            "summary": "Automatic reconciliation has not run yet.",
            "counts": {
                "devices": 0,
                "drift": 0,
                "applied": 0,
                "synced": 0,
                "temporary": 0,
                "partial": 0,
                "failed": 0,
            },
            "failures": [],
        }

    @staticmethod
    def _iso_now() -> str:
        return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")

    @staticmethod
    def _validate_settings(settings: dict) -> dict:
        mode = str(settings.get("auto_reconcile_mode") or "off").strip().lower()
        if mode not in VALID_AUTO_MODES:
            mode = "off"

        try:
            interval = int(settings.get("auto_reconcile_interval_seconds") or 30)
        except (TypeError, ValueError):
            interval = 30
        if interval not in VALID_INTERVALS:
            interval = 30

        try:
            threshold = int(settings.get("auto_reconcile_failure_threshold") or 3)
        except (TypeError, ValueError):
            threshold = 3
        if threshold not in VALID_FAILURE_THRESHOLDS:
            threshold = 3

        try:
            cooldown = int(settings.get("auto_reconcile_cooldown_seconds") or 300)
        except (TypeError, ValueError):
            cooldown = 300
        if cooldown not in VALID_COOLDOWNS:
            cooldown = 300

        return {
            "mode": mode,
            "interval_seconds": interval,
            "failure_threshold": threshold,
            "cooldown_seconds": cooldown,
        }

    def settings(self) -> dict:
        return self._validate_settings(self.policy_store.get_settings())

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop,
            name="policy-auto-reconciler",
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

    def clear_hold(self) -> None:
        with self._state_lock:
            self._consecutive_failures = 0
            self._hold_until_epoch = 0.0
        self._wake.set()

    @contextmanager
    def authority_transfer_guard(self, timeout: float = 5.0):
        """Pause automatic reconciliation while an authority transfer is atomic.

        Manual cutover/rollback owns the same cycle lock as the worker so an
        automatic policy cycle cannot race a legacy-authority transition.
        """
        acquired = self._cycle_lock.acquire(timeout=max(0.1, float(timeout)))
        if not acquired:
            raise ReconciliationError(
                "Automatic reconciliation is busy; retry authority transfer after the current cycle completes"
            )
        try:
            yield
        finally:
            self._cycle_lock.release()
            self._wake.set()

    def snapshot(self) -> dict:
        settings = self.settings()
        now = time.time()
        with self._state_lock:
            hold_until = self._hold_until_epoch
            failures = self._consecutive_failures
            last = {
                **self._last,
                "counts": dict(self._last.get("counts") or {}),
                "failures": list(self._last.get("failures") or []),
            }

        hold_active = hold_until > now
        hold_until_iso = None
        if hold_active:
            hold_until_iso = datetime.fromtimestamp(
                hold_until, tz=timezone.utc
            ).astimezone().isoformat(timespec="seconds")

        return {
            **settings,
            "worker_alive": bool(self._thread and self._thread.is_alive()),
            "busy": self._cycle_lock.locked(),
            "consecutive_failures": failures,
            "hold_active": hold_active,
            "hold_until": hold_until_iso,
            "last": last,
        }

    @timed("worker.reconciler.cycle")
    def run_cycle(
        self,
        *,
        trigger: str = "manual-run-now",
        actor: str = "system:auto",
        mode_override: str | None = None,
        ignore_hold: bool = False,
    ) -> dict:
        if not self._cycle_lock.acquire(blocking=False):
            raise ReconciliationError("A reconciliation cycle is already running")

        started = time.monotonic()
        started_at = self._iso_now()
        settings = self.settings()
        mode = (mode_override or settings["mode"]).strip().lower()
        if mode not in VALID_AUTO_MODES:
            self._cycle_lock.release()
            raise ReconciliationError(f"Invalid reconciliation mode '{mode}'")

        counts = {
            "devices": 0,
            "drift": 0,
            "applied": 0,
            "synced": 0,
            "temporary": 0,
            "partial": 0,
            "failed": 0,
        }
        failures: list[str] = []
        result = "ok"
        summary = ""

        try:
            with self._state_lock:
                hold_active = self._hold_until_epoch > time.time()

            if mode == "off":
                result = "disabled"
                summary = "Automatic reconciliation is OFF. No RouterOS reads or writes were performed."
                return self._finish_cycle(
                    started,
                    started_at,
                    trigger,
                    mode,
                    result,
                    summary,
                    counts,
                    failures,
                )

            if mode == "enforce" and hold_active and not ignore_hold:
                result = "hold"
                summary = "Automatic enforcement is in cooldown hold after repeated failed cycles. Observe-only checks remain available."
                return self._finish_cycle(
                    started,
                    started_at,
                    trigger,
                    mode,
                    result,
                    summary,
                    counts,
                    failures,
                )

            # Security gate: automatic writes are permitted only while the
            # RouterOS authority/hardening contract can be proven intact.
            # OBSERVE deliberately remains available to diagnose drift even
            # when the write gate is closed.
            if mode == "enforce":
                posture_getter = getattr(self.router, "get_security_posture", None)
                if posture_getter:
                    posture = posture_getter()
                    if not posture.get("enforcement_ready"):
                        failed_names = [
                            item.get("name", item.get("key", "unknown"))
                            for item in posture.get("checks", [])
                            if item.get("severity") == "critical"
                            and item.get("status") == "fail"
                        ]
                        result = "security_hold"
                        failures = ["security: " + ", ".join(failed_names[:8])]
                        summary = (
                            "Automatic enforcement is SECURITY HELD because the "
                            "RouterOS enforcement contract is degraded: "
                            + (", ".join(failed_names[:6]) or "critical hardening check failed")
                        )
                        self.audit(
                            "AUTO_RECONCILE_SECURITY_HOLD",
                            actor,
                            failures[0],
                        )
                        return self._finish_cycle(
                            started, started_at, trigger, mode, result, summary, counts, failures
                        )

            devices = self.device_loader()
            counts["devices"] = len(devices)

            for device in devices:
                address = device.get("ip") or device.get("address")
                if not address:
                    continue
                try:
                    plan = self.plan_loader(address)
                    if plan.get("temporary_override"):
                        counts["temporary"] += 1
                        continue

                    if not plan.get("policy_actionable"):
                        counts["synced"] += 1
                        if plan.get("status") == "partial":
                            counts["partial"] += 1
                        continue

                    counts["drift"] += 1
                    if mode == "observe":
                        continue

                    reconciliation = reconcile_device(
                        address,
                        plan_loader=self.plan_loader,
                        router=self.router,
                        description="auto:effective-policy",
                    )
                    if reconciliation["status"] == "applied":
                        counts["applied"] += 1
                        changes = "; ".join(reconciliation.get("changes") or [])
                        self.audit(
                            "AUTO_POLICY_APPLIED",
                            actor,
                            f"{address}: {changes or 'converged'}",
                        )
                    elif reconciliation["status"] == "temporary":
                        counts["temporary"] += 1
                    elif reconciliation["status"] == "partial":
                        counts["partial"] += 1
                        counts["synced"] += 1
                    else:
                        counts["synced"] += 1

                except Exception as exc:  # isolate one bad device from the cycle
                    counts["failed"] += 1
                    failures.append(f"{address}: {exc}")

            if failures:
                result = "failed"
                summary = (
                    f"{counts['failed']} device(s) failed; "
                    f"{counts['applied']} applied, {counts['drift']} drifted."
                )
                if mode == "enforce":
                    self._record_failed_cycle(settings, actor, failures)
                else:
                    self.audit(
                        "AUTO_POLICY_OBSERVE_FAILED",
                        actor,
                        "; ".join(failures[:6]),
                    )
            else:
                if mode == "enforce":
                    self._record_successful_cycle()
                if mode == "observe":
                    result = "drift" if counts["drift"] else "ok"
                    summary = (
                        f"Observe-only: {counts['drift']} drifted, "
                        f"{counts['synced']} synced, {counts['temporary']} temporary."
                    )
                    if counts["drift"]:
                        self.audit(
                            "AUTO_POLICY_OBSERVED_DRIFT",
                            actor,
                            f"drift={counts['drift']} devices={counts['devices']}",
                        )
                else:
                    result = "applied" if counts["applied"] else "ok"
                    summary = (
                        f"Enforce: {counts['applied']} applied, "
                        f"{counts['synced']} synced, {counts['temporary']} temporary, "
                        f"{counts['partial']} partial."
                    )
                    if counts["applied"]:
                        self.audit(
                            "AUTO_RECONCILE_CYCLE",
                            actor,
                            (
                                f"applied={counts['applied']} synced={counts['synced']} "
                                f"temporary={counts['temporary']} partial={counts['partial']}"
                            ),
                        )

            return self._finish_cycle(
                started,
                started_at,
                trigger,
                mode,
                result,
                summary,
                counts,
                failures,
            )

        except Exception as exc:
            # Only failed ENFORCE cycles feed the circuit breaker. OBSERVE is
            # diagnostic and must never clear or extend an enforcement hold.
            if mode == "enforce":
                self._record_failed_cycle(settings, actor, [f"cycle-level: {exc}"])
            else:
                self.audit(
                    "AUTO_POLICY_OBSERVE_FAILED",
                    actor,
                    f"cycle-level: {exc}",
                )
            raise
        finally:
            self._cycle_lock.release()

    def _record_successful_cycle(self) -> None:
        with self._state_lock:
            self._consecutive_failures = 0
            self._hold_until_epoch = 0.0

    def _record_failed_cycle(self, settings: dict, actor: str, failures: list[str]) -> None:
        opened = False
        with self._state_lock:
            self._consecutive_failures += 1
            if self._consecutive_failures >= settings["failure_threshold"]:
                self._hold_until_epoch = time.time() + settings["cooldown_seconds"]
                opened = True
        self.audit(
            "AUTO_RECONCILE_FAILED",
            actor,
            "; ".join(failures[:6]),
        )
        if opened:
            self.audit(
                "AUTO_RECONCILE_HOLD",
                actor,
                (
                    f"threshold={settings['failure_threshold']} "
                    f"cooldown={settings['cooldown_seconds']}s"
                ),
            )

    def _finish_cycle(
        self,
        started: float,
        started_at: str,
        trigger: str,
        mode: str,
        result: str,
        summary: str,
        counts: dict,
        failures: list[str],
    ) -> dict:
        finished_at = self._iso_now()
        duration_ms = int((time.monotonic() - started) * 1000)
        payload = {
            "started_at": started_at,
            "finished_at": finished_at,
            "duration_ms": duration_ms,
            "trigger": trigger,
            "mode": mode,
            "result": result,
            "summary": summary,
            "counts": dict(counts),
            "failures": list(failures[:12]),
        }
        with self._state_lock:
            self._last = payload
        return payload

    def _loop(self) -> None:
        # Delay the first background cycle slightly so application startup and
        # health/readiness are not coupled to RouterOS availability.
        self._stop.wait(2.0)

        while not self._stop.is_set():
            settings = self.settings()
            if settings["mode"] != "off":
                try:
                    self.run_cycle(trigger="background", actor="system:auto")
                except Exception as exc:
                    self.audit(
                        "AUTO_RECONCILE_WORKER_ERROR",
                        "system:auto",
                        str(exc),
                    )

            self._wake.clear()
            self._wake.wait(timeout=settings["interval_seconds"])
