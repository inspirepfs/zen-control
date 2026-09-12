from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable

from app.performance import timed


class BackgroundWorkError(RuntimeError):
    """Durable background work could not be completed safely."""


class BackgroundWorker:
    """Durable read-side worker for non-authoritative background computation.

    The worker deliberately has no RouterOS dependency. Handlers receive only a
    copied job payload and may write job/result bookkeeping through PolicyStore;
    they cannot become an alternate enforcement path by construction.
    """

    def __init__(
        self,
        *,
        policy_store: Any,
        handlers: dict[str, Callable[[dict], dict]],
        audit: Callable[[str, str, str], None],
        producer: Callable[[], int] | None = None,
        worker_name: str = "background-read-worker",
        interval_seconds: float = 2.0,
        lease_seconds: int = 30,
        max_jobs_per_cycle: int = 8,
    ) -> None:
        self.policy_store = policy_store
        self.handlers = dict(handlers)
        self.audit = audit
        self.producer = producer
        self.worker_name = str(worker_name or "background-read-worker")[:80]
        self.interval_seconds = max(0.25, float(interval_seconds))
        self.lease_seconds = max(5, int(lease_seconds))
        self.max_jobs_per_cycle = max(1, min(50, int(max_jobs_per_cycle)))

        self._stop = threading.Event()
        self._wake = threading.Event()
        self._cycle_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._last: dict = {
            "started_at": None,
            "finished_at": None,
            "duration_ms": None,
            "result": "never",
            "scheduled": 0,
            "dispatched": 0,
            "claimed": 0,
            "succeeded": 0,
            "failed": 0,
            "deferred": 0,
            "last_error": "",
        }

    @staticmethod
    def _iso_now() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop,
            name=self.worker_name,
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
            last = dict(self._last)
        try:
            durable = self.policy_store.background_work_stats()
        except Exception as exc:
            durable = {"available": False, "error": str(exc)}
        return {
            "worker_name": self.worker_name,
            "worker_alive": bool(self._thread and self._thread.is_alive()),
            "busy": self._cycle_lock.locked(),
            "interval_seconds": self.interval_seconds,
            "lease_seconds": self.lease_seconds,
            "handlers": sorted(self.handlers),
            "last": last,
            "durable": durable,
        }

    def performance_snapshot(self) -> dict:
        """Return in-memory worker timing evidence without touching durable state."""
        with self._state_lock:
            last = dict(self._last)
        return {
            "schema": "zen_background_worker_performance_v1",
            "worker_alive": bool(self._thread and self._thread.is_alive()),
            "busy": self._cycle_lock.locked(),
            "last_duration_ms": last.get("duration_ms"),
            "last_result": last.get("result"),
            "last_claimed": int(last.get("claimed") or 0),
            "last_succeeded": int(last.get("succeeded") or 0),
            "last_failed": int(last.get("failed") or 0),
            "last_deferred": int(last.get("deferred") or 0),
            "last_error": str(last.get("last_error") or ""),
        }

    @timed("worker.background.cycle")
    def run_cycle(self, *, trigger: str = "manual") -> dict:
        if not self._cycle_lock.acquire(blocking=False):
            raise BackgroundWorkError("A background-work cycle is already running")

        started_monotonic = time.monotonic()
        started_at = self._iso_now()
        result = {
            "started_at": started_at,
            "finished_at": None,
            "duration_ms": None,
            "trigger": str(trigger or "manual"),
            "result": "ok",
            "scheduled": 0,
            "dispatched": 0,
            "claimed": 0,
            "succeeded": 0,
            "failed": 0,
            "deferred": 0,
            "last_error": "",
        }
        try:
            recovered = self.policy_store.recover_expired_background_work()
            result["recovered"] = int(recovered or 0)
            if self.producer is not None:
                result["scheduled"] = int(self.producer() or 0)
            result["dispatched"] = int(
                self.policy_store.dispatch_outbox_to_background_jobs(limit=50) or 0
            )

            for _ in range(self.max_jobs_per_cycle):
                job = self.policy_store.claim_background_job(
                    worker_name=self.worker_name,
                    lease_seconds=self.lease_seconds,
                    kinds=tuple(self.handlers),
                )
                if not job:
                    break
                result["claimed"] += 1

                token = str(job.get("lease_token") or "")
                scope = str(job.get("scope") or "global")
                locked = self.policy_store.acquire_background_scope_lock(
                    scope=scope,
                    owner=self.worker_name,
                    token=token,
                    lease_seconds=self.lease_seconds,
                )
                if not locked:
                    self.policy_store.defer_background_job(
                        job["id"],
                        worker_name=self.worker_name,
                        lease_token=token,
                        delay_seconds=1,
                        reason="scope lock busy",
                    )
                    result["deferred"] += 1
                    continue

                try:
                    handler = self.handlers.get(str(job.get("kind") or ""))
                    if handler is None:
                        raise BackgroundWorkError(
                            f"No read-side handler registered for {job.get('kind')!r}"
                        )
                    payload = dict(job.get("payload") or {})
                    output = handler(payload)
                    self.policy_store.complete_background_job(
                        job["id"],
                        worker_name=self.worker_name,
                        lease_token=token,
                        result=output or {},
                    )
                    result["succeeded"] += 1
                except Exception as exc:
                    result["failed"] += 1
                    result["last_error"] = str(exc)[:240]
                    self.policy_store.fail_background_job(
                        job["id"],
                        worker_name=self.worker_name,
                        lease_token=token,
                        error=str(exc),
                    )
                finally:
                    self.policy_store.release_background_scope_lock(
                        scope=scope,
                        owner=self.worker_name,
                        token=token,
                    )

            if result["failed"]:
                result["result"] = "degraded"
            return result
        finally:
            result["finished_at"] = self._iso_now()
            result["duration_ms"] = round(
                (time.monotonic() - started_monotonic) * 1000.0, 3
            )
            try:
                self.policy_store.record_background_worker_metrics(
                    worker_name=self.worker_name,
                    cycle=result,
                )
            except Exception:
                pass
            with self._state_lock:
                self._last = dict(result)
            self._cycle_lock.release()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_cycle(trigger="timer")
            except BackgroundWorkError:
                pass
            except Exception as exc:
                with self._state_lock:
                    self._last = {
                        **self._last,
                        "finished_at": self._iso_now(),
                        "result": "error",
                        "last_error": str(exc)[:240],
                    }
                try:
                    self.audit(
                        "BACKGROUND_WORKER_ERROR",
                        "system:background",
                        str(exc)[:240],
                    )
                except Exception:
                    pass
            self._wake.wait(self.interval_seconds)
            self._wake.clear()
