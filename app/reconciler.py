from __future__ import annotations

import os
import threading
import time
from contextlib import contextmanager, nullcontext
from datetime import datetime, timezone
from typing import Callable, Any

from app.parallel_observation import ParallelObserver
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

    if not (
        plan.get("mode_drift")
        or plan.get("bandwidth_drift")
        or plan.get("service_drift")
    ):
        return {
            "address": address,
            "status": "synced",
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

        try:
            observation_workers = int(os.getenv("ZEN_ROUTER_OBSERVE_WORKERS", "4"))
        except (TypeError, ValueError):
            observation_workers = 4
        self._observer = ParallelObserver(
            max_workers=max(1, min(8, observation_workers)),
            name="router-plan",
        )

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
                "observed": 0,
                "plan_failed": 0,
                "drift": 0,
                "applied": 0,
                "synced": 0,
                "temporary": 0,
                "partial": 0,
                "failed": 0,
            },
            "failures": [],
            "observation": {
                "schema": "zen_parallel_observation_v1",
                "items": 0,
                "workers": 0,
                "max_active": 0,
                "duration_ms": 0.0,
                "failed": 0,
            },
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
            with self._mutation_context("authority-transfer"):
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

        try:
            mutation = self.router.mutation_status()
        except Exception:
            mutation = {"schema": "zen_router_mutation_lane_v1", "busy": False, "available": False}

        try:
            requested = self.policy_store.reconciliation_request_stats()
        except Exception as exc:
            requested = {
                "schema": "zen_reconciliation_queue_v1",
                "pending": 0, "running": 0, "failed": 0,
                "counts": {}, "latest": None, "error": str(exc),
            }

        return {
            **settings,
            "worker_alive": bool(self._thread and self._thread.is_alive()),
            "busy": self._cycle_lock.locked(),
            "observation_workers_configured": self._observer.max_workers,
            "consecutive_failures": failures,
            "hold_active": hold_active,
            "hold_until": hold_until_iso,
            "last": last,
            "requested": requested,
            "router_mutation": mutation,
        }

    def performance_snapshot(self) -> dict:
        """Return the last read-side fan-out evidence without probing RouterOS."""
        with self._state_lock:
            observation = dict((self._last.get("observation") or {}))
        workers = int(observation.get("workers") or 0)
        max_active = int(observation.get("max_active") or 0)
        utilisation = None
        if workers > 0:
            utilisation = round(min(1.0, max_active / workers) * 100.0, 1)
        return {
            "schema": "zen_parallel_observation_performance_v1",
            "workers_configured": self._observer.max_workers,
            "items": int(observation.get("items") or 0),
            "workers": workers,
            "max_active": max_active,
            "utilisation_percent": utilisation,
            "duration_ms": observation.get("duration_ms"),
            "failed": int(observation.get("failed") or 0),
        }

    def _mutation_context(self, owner: str):
        router = getattr(self, "router", None)
        factory = getattr(router, "mutation_session", None) if router is not None else None
        if factory is None:
            return nullcontext()
        return factory(owner=owner)

    @staticmethod
    def _failed_security_names(posture: dict) -> list[str]:
        if posture.get("enforcement_ready"):
            return []
        return [
            item.get("name", item.get("key", "unknown"))
            for item in posture.get("checks", [])
            if item.get("severity") == "critical" and item.get("status") == "fail"
        ]

    def _security_posture(self) -> tuple[dict, list[str]]:
        posture_getter = getattr(self.router, "get_security_posture", None)
        if not posture_getter:
            return {"enforcement_ready": True, "checks": []}, []
        posture = posture_getter()
        return posture, self._failed_security_names(posture)

    def _publish_security_posture(self, posture: dict) -> None:
        """Publish advisory posture outside mutation authority.

        Prepared-view persistence must never extend the RouterOS mutation-lane
        hold time. Mutation paths always re-prove posture live and never consume
        this cached observation.
        """
        try:
            self.policy_store.save_prepared_view(
                view_key="router:security-posture",
                kind="router.observation",
                scope="router:security",
                payload=posture,
                source_revision=int(self.policy_store.current_config_revision().get("revision") or 0),
                ttl_seconds=180,
            )
        except Exception:
            pass

    def _observe_plans(self, devices: list[dict]) -> dict:
        usable = [
            device for device in devices
            if str(device.get("ip") or device.get("address") or "").strip()
        ]
        return self._observer.observe(
            usable,
            key=lambda device: str(device.get("ip") or device.get("address")),
            reader=lambda device: self.plan_loader(
                str(device.get("ip") or device.get("address"))
            ),
        )

    def request_reconciliation(
        self, *, target="*", actor="system:manual", reason="Manual reconciliation requested"
    ) -> dict:
        request = self.policy_store.enqueue_reconciliation_request(
            target=target,
            actor=actor,
            reason=reason,
            requested_revision=int(self.policy_store.current_config_revision().get("revision") or 0),
        )
        self._wake.set()
        return request

    @timed("worker.reconciler.requested")
    def run_requested_reconciliation(self, *, actor="system:requested") -> dict | None:
        """Consume one durable manual request through the normal mutation lane.

        Explicit requests remain available even when automatic reconciliation is
        OFF. They never reuse pre-queue RouterOS observations. If desired state
        changes while a request is running, the completed request is marked
        superseded and a new request is queued for the latest revision.
        """
        if not self._cycle_lock.acquire(blocking=False):
            return None
        request = None
        try:
            request = self.policy_store.claim_reconciliation_request()
            if not request:
                return None
            target = str(request.get("target") or "*")
            request_actor = str(request.get("actor") or actor)
            requested_revision = int(request.get("requested_revision") or 0)
            started_revision = int(self.policy_store.current_config_revision().get("revision") or 0)
            outcomes = []
            failures = []

            with self._mutation_context(f"requested-reconcile:{request['id']}"):
                _posture, failed_names = self._security_posture()
                if failed_names:
                    raise ReconciliationError(
                        "RouterOS enforcement contract is degraded: "
                        + (", ".join(failed_names[:6]) or "critical hardening check failed")
                    )

                if target == "*":
                    addresses = [
                        str(item.get("ip") or item.get("address") or "").strip()
                        for item in self.device_loader()
                    ]
                    addresses = [item for item in addresses if item]
                else:
                    addresses = [target]

                for address in addresses:
                    try:
                        outcome = reconcile_device(
                            address,
                            plan_loader=self.plan_loader,
                            router=self.router,
                            description="requested:effective-policy",
                        )
                        outcomes.append({
                            "address": address,
                            "status": outcome.get("status"),
                            "changes": list(outcome.get("changes") or []),
                        })
                    except Exception as exc:
                        failures.append(f"{address}: {exc}")

            finished_revision = int(self.policy_store.current_config_revision().get("revision") or 0)
            result = {
                "schema": "zen_requested_reconciliation_result_v1",
                "target": target,
                "requested_revision": requested_revision,
                "started_revision": started_revision,
                "finished_revision": finished_revision,
                "outcomes": outcomes,
                "failures": failures,
            }
            if failures:
                status = "failed"
                error = "; ".join(failures[:6])
            elif finished_revision != started_revision:
                status = "superseded"
                error = "Desired state changed during reconciliation; latest revision re-queued"
            elif any(item.get("status") == "temporary" for item in outcomes):
                status = "temporary"
                error = ""
            elif any(item.get("status") == "partial" for item in outcomes):
                status = "partial"
                error = ""
            else:
                status = "succeeded"
                error = ""

            finished = self.policy_store.finish_reconciliation_request(
                request["id"],
                status=status,
                applied_revision=finished_revision,
                result=result,
                error=error,
            )
            if status == "superseded":
                self.request_reconciliation(
                    target=target,
                    actor=request_actor,
                    reason=f"Superseding request {request['id']} at revision {finished_revision}",
                )
            event = "POLICY_RECONCILE_REQUEST_FAILED" if status == "failed" else "POLICY_RECONCILE_REQUEST_COMPLETED"
            self.audit(
                event, request_actor,
                f"id={request['id']} target={target} status={status} revision={finished_revision} outcomes={len(outcomes)} failures={len(failures)}",
            )
            return finished
        except Exception as exc:
            if request:
                try:
                    self.policy_store.finish_reconciliation_request(
                        request["id"], status="failed",
                        applied_revision=int(self.policy_store.current_config_revision().get("revision") or 0),
                        result={"target": request.get("target"), "outcomes": []},
                        error=str(exc),
                    )
                except Exception:
                    pass
                try:
                    self.audit(
                        "POLICY_RECONCILE_REQUEST_FAILED",
                        str(request.get("actor") or actor),
                        f"id={request['id']} target={request.get('target')} error={exc}",
                    )
                except Exception:
                    pass
            return None
        finally:
            self._cycle_lock.release()

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
            "observed": 0,
            "plan_failed": 0,
            "drift": 0,
            "applied": 0,
            "synced": 0,
            "temporary": 0,
            "partial": 0,
            "failed": 0,
        }
        failures: list[str] = []
        observation = {
            "schema": "zen_parallel_observation_v1",
            "items": 0,
            "workers": 0,
            "max_active": 0,
            "duration_ms": 0.0,
            "failed": 0,
        }
        result = "ok"
        summary = ""

        try:
            with self._state_lock:
                hold_active = self._hold_until_epoch > time.time()

            if mode == "off":
                result = "disabled"
                summary = "Automatic reconciliation is OFF. No RouterOS reads or writes were performed."
                return self._finish_cycle(
                    started, started_at, trigger, mode, result, summary, counts, failures,
                    observation=observation,
                )

            if mode == "enforce" and hold_active and not ignore_hold:
                result = "hold"
                summary = "Automatic enforcement is in cooldown hold after repeated failed cycles. Observe-only checks remain available."
                return self._finish_cycle(
                    started, started_at, trigger, mode, result, summary, counts, failures,
                    observation=observation,
                )

            # Preserve the pre-existing fail-closed gate before spending time on
            # planning. ENFORCE repeats this proof while owning the mutation lane
            # immediately before the first possible write.
            if mode == "enforce":
                _posture, failed_names = self._security_posture()
                self._publish_security_posture(_posture)
                if failed_names:
                    result = "security_hold"
                    failures = ["security: " + ", ".join(failed_names[:8])]
                    summary = (
                        "Automatic enforcement is SECURITY HELD because the "
                        "RouterOS enforcement contract is degraded: "
                        + (", ".join(failed_names[:6]) or "critical hardening check failed")
                    )
                    self.audit("AUTO_RECONCILE_SECURITY_HOLD", actor, failures[0])
                    return self._finish_cycle(
                        started, started_at, trigger, mode, result, summary, counts, failures,
                        observation=observation,
                    )

            devices = self.device_loader()
            counts["devices"] = len(devices)
            batch = self._observe_plans(devices)
            observation = {
                key: batch.get(key)
                for key in ("schema", "items", "workers", "max_active", "duration_ms")
            }
            observation["failed"] = len(batch.get("errors") or {})
            counts["observed"] = len(batch.get("results") or {})
            counts["plan_failed"] = len(batch.get("errors") or {})

            for address, error in (batch.get("errors") or {}).items():
                counts["failed"] += 1
                failures.append(f"{address}: observation failed: {error}")

            candidates: list[str] = []
            for address in batch.get("order") or []:
                plan = (batch.get("results") or {}).get(address)
                if plan is None:
                    continue
                if plan.get("temporary_override"):
                    counts["temporary"] += 1
                    continue
                if not plan.get("policy_actionable"):
                    counts["synced"] += 1
                    if plan.get("status") == "partial":
                        counts["partial"] += 1
                    continue
                counts["drift"] += 1
                candidates.append(address)

            if mode == "enforce" and candidates:
                # Parallel observation never grants write authority. Once the
                # mutation lane is owned, re-prove security and re-read each
                # candidate serially inside reconcile_device before mutation.
                with self._mutation_context(f"reconciler:{trigger}"):
                    _posture, failed_names = self._security_posture()
                    if failed_names:
                        result = "security_hold"
                        failures = ["security: " + ", ".join(failed_names[:8])]
                        summary = (
                            "Automatic enforcement is SECURITY HELD because authority "
                            "changed after parallel observation: "
                            + (", ".join(failed_names[:6]) or "critical hardening check failed")
                        )
                        self.audit("AUTO_RECONCILE_SECURITY_HOLD", actor, failures[0])
                        return self._finish_cycle(
                            started, started_at, trigger, mode, result, summary, counts, failures,
                            observation=observation,
                        )

                    for address in candidates:
                        try:
                            reconciliation = reconcile_device(
                                address,
                                plan_loader=self.plan_loader,
                                router=self.router,
                                description="auto:effective-policy",
                            )
                            status = reconciliation["status"]
                            if status == "applied":
                                counts["applied"] += 1
                                changes = "; ".join(reconciliation.get("changes") or [])
                                self.audit(
                                    "AUTO_POLICY_APPLIED", actor,
                                    f"{address}: {changes or 'converged'}",
                                )
                            elif status == "temporary":
                                counts["temporary"] += 1
                            elif status == "partial":
                                counts["partial"] += 1
                                counts["synced"] += 1
                            else:
                                counts["synced"] += 1
                        except Exception as exc:
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
                    self.audit("AUTO_POLICY_OBSERVE_FAILED", actor, "; ".join(failures[:6]))
            else:
                if mode == "enforce":
                    self._record_successful_cycle()
                if mode == "observe":
                    result = "drift" if counts["drift"] else "ok"
                    summary = (
                        f"Observe-only: {counts['drift']} drifted, "
                        f"{counts['synced']} synced, {counts['temporary']} temporary; "
                        f"planned with {observation['workers']} worker(s)."
                    )
                    if counts["drift"]:
                        self.audit(
                            "AUTO_POLICY_OBSERVED_DRIFT", actor,
                            f"drift={counts['drift']} devices={counts['devices']}",
                        )
                else:
                    result = "applied" if counts["applied"] else "ok"
                    summary = (
                        f"Enforce: {counts['applied']} applied, "
                        f"{counts['synced']} synced, {counts['temporary']} temporary, "
                        f"{counts['partial']} partial; observation workers={observation['workers']}."
                    )
                    if counts["applied"]:
                        self.audit(
                            "AUTO_RECONCILE_CYCLE", actor,
                            (
                                f"applied={counts['applied']} synced={counts['synced']} "
                                f"temporary={counts['temporary']} partial={counts['partial']}"
                            ),
                        )

            return self._finish_cycle(
                started, started_at, trigger, mode, result, summary, counts, failures,
                observation=observation,
            )

        except Exception as exc:
            if mode == "enforce":
                self._record_failed_cycle(settings, actor, [f"cycle-level: {exc}"])
            else:
                self.audit("AUTO_POLICY_OBSERVE_FAILED", actor, f"cycle-level: {exc}")
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
        *,
        observation: dict | None = None,
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
            "observation": dict(observation or {}),
        }
        with self._state_lock:
            self._last = payload
        return payload

    def _loop(self) -> None:
        # Delay the first background cycle slightly so application startup and
        # health/readiness are not coupled to RouterOS availability.
        self._stop.wait(2.0)
        try:
            self.policy_store.recover_reconciliation_requests()
        except Exception:
            pass

        while not self._stop.is_set():
            settings = self.settings()

            # Explicit user reconciliation is durable and independent of the
            # automatic OFF/OBSERVE/ENFORCE setting. Consume a bounded number per
            # wake so request acknowledgement is never coupled to RouterOS speed.
            for _ in range(4):
                try:
                    handled = self.run_requested_reconciliation()
                except Exception as exc:
                    self.audit("REQUESTED_RECONCILE_WORKER_ERROR", "system:requested", str(exc))
                    break
                if not handled:
                    break

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
