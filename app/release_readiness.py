from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.policy_store import PolicyStore


RELEASE_READINESS_SCHEMA = "zen_release_readiness_v1"

CORE_CLOSURE_MATRIX = (
    ("time_policy", "Policy & time-boundary closure", "0.40"),
    ("router_authority", "RouterOS authority & security hostile closure", "0.41"),
    ("auth_device_lifecycle", "Authentication, shared display & device lifecycle", "0.42"),
    ("quota_reward_temp", "Quotas, rewards & temporary access closure", "0.43"),
    ("service_lifecycle", "Service intelligence & custom service lifecycle", "0.44"),
    ("policy_parity", "Explainability, simulation & Device 360 parity", "0.45"),
    ("classification", "Classification intelligence & degraded evidence", "0.46"),
    ("dependency_chaos", "Operational diagnostics & dependency-chaos closure", "0.47"),
    ("aggregate_groups", "Aggregate policy group lifecycle closure", "0.48"),
    ("history", "Historical policy correlation & retained evidence", "0.49"),
    ("policy_quality", "Policy Conflict & Shadow hostile closure", "0.50.1"),
    ("parent_unlock", "Parent unlock & time-extension hardening", "0.50.2"),
    ("diagnostic_gate", "Diagnostic warning attribution & pre-HTTPS gate", "0.51.0"),
    ("kid_control_migration", "MikroTik Kid Control staged migration", "0.52.0"),
    ("kid_control_authority", "MikroTik Kid Control controlled authority transfer", "0.53.0"),
)

PARENT_JOURNEY_MATRIX = (
    ("inspect_explain", "Inspect a managed device and explain its effective policy", "Device 360 → Why this policy?"),
    ("preview_change", "Preview a policy change before saving it", "Policy Simulation → guarded policy write"),
    ("temporary_access", "Grant bounded temporary access and recover/expire safely", "Temporary access → RouterOS expiry/reconciliation"),
    ("quota_reward", "Use quota/reward evidence without inventing telemetry", "Activity/quota → reward recovery"),
    ("recover_config", "Checkpoint, export and restore semantic configuration", "Operations snapshot → restore → reconciliation"),
    ("shared_unlock", "Use a shared display with server-enforced parent unlock", "Shared display → TOTP step-up → guarded writes"),
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _check(key: str, label: str, state: str, summary: str, **evidence: Any) -> dict[str, Any]:
    return {
        "key": key,
        "label": label,
        "state": state,
        "summary": summary,
        "evidence": evidence,
    }


def _state(value: Any, allowed: set[str], default: str) -> str:
    text = str(value or "").strip().lower()
    return text if text in allowed else default


def _bounded_text(value: Any, limit: int) -> str:
    text = " ".join(str(value or "").split())
    return text[: max(1, int(limit))]


def _diagnostic_gate_findings(diagnostics: dict[str, Any], states: set[str]) -> list[dict[str, str]]:
    """Carry only bounded, already-sanitized diagnostic identity into release evidence.

    Operational Diagnostics owns the underlying health semantics and privacy
    contract. Release Readiness needs enough identity to explain why its
    dependency gate is PENDING/FAIL, but must not copy diagnostic facts or raw
    exception material into the portable release artifact.
    """
    findings: list[dict[str, str]] = []
    for item in list((diagnostics or {}).get("checks") or [])[:20]:
        if not isinstance(item, dict):
            continue
        state = str(item.get("state") or "").strip().lower()
        if state not in states:
            continue
        findings.append({
            "key": _bounded_text(item.get("key") or "unknown", 64),
            "label": _bounded_text(item.get("label") or "Diagnostic check", 120),
            "state": state,
            "summary": _bounded_text(item.get("summary") or "Review diagnostic evidence", 240),
        })
    return findings


def config_roundtrip_smoke(policy_store: Any) -> dict[str, Any]:
    """Prove configuration export/import symmetry without touching live state.

    The live store is read-only for this check. Its exported payload is restored
    into a temporary SQLite database and the semantic configuration digest is
    compared after a reopen. Runtime ledgers/history/auth state are intentionally
    outside normal configuration backup identity and remain untouched.
    """
    try:
        source_digest = str(policy_store.config_digest())
        payload = policy_store.export_config()
        with tempfile.TemporaryDirectory(prefix="zen-release-smoke-") as directory:
            path = Path(directory) / "policy.db"
            restored = PolicyStore(str(path))
            restored.import_config(payload)
            restored_digest = str(restored.config_digest())
            # Reopen to include the same SQLite persistence boundary used after
            # an application/container restart.
            reopened = PolicyStore(str(path))
            reopened_digest = str(reopened.config_digest())
        ok = source_digest == restored_digest == reopened_digest
        return {
            "state": "pass" if ok else "fail",
            "non_destructive": True,
            "source_digest": source_digest,
            "restored_digest": restored_digest,
            "reopened_digest": reopened_digest,
            "summary": (
                "Configuration export/import/reopen digest matched"
                if ok else "Configuration round-trip digest mismatch"
            ),
        }
    except Exception:
        return {
            "state": "fail",
            "non_destructive": True,
            "source_digest": None,
            "restored_digest": None,
            "reopened_digest": None,
            "summary": "Configuration round-trip smoke could not be completed",
        }


def restart_evidence(policy_store: Any, version: str) -> dict[str, Any]:
    """Find durable evidence of a controlled stop followed by this release start.

    This deliberately does not infer a successful restart from process uptime or
    from a current readiness result. The previous process must have written a
    durable APPLICATION_STOP event and the current release must then have written
    a STARTUP_INTEGRITY_OK event carrying its release identity.
    """
    try:
        rows = list(policy_store.list_audit(300) or [])
    except Exception:
        return {
            "state": "pending",
            "controlled_stop_seen": False,
            "current_release_start_seen": False,
            "summary": "Durable restart evidence is unavailable",
        }

    ordered = sorted(rows, key=lambda row: int(row.get("id") or 0))
    startup_index = None
    current_release_start_seen = False
    startup_event = None
    marker = f"version={version}"
    for index, row in enumerate(ordered):
        if str(row.get("event") or "") != "STARTUP_INTEGRITY_OK":
            continue
        if marker not in str(row.get("detail") or ""):
            continue
        startup_index = index
        startup_event = row
        current_release_start_seen = True

    controlled_stop_seen = False
    if startup_index is not None:
        lifecycle_events = {"APPLICATION_STOP", "STARTUP_INTEGRITY_OK", "STARTUP_INTEGRITY_DEGRADED"}
        previous_lifecycle = next(
            (row for row in reversed(ordered[:startup_index])
             if str(row.get("event") or "") in lifecycle_events),
            None,
        )
        controlled_stop_seen = bool(
            previous_lifecycle
            and str(previous_lifecycle.get("event") or "") == "APPLICATION_STOP"
        )

    passed = bool(current_release_start_seen and controlled_stop_seen)
    return {
        "state": "pass" if passed else "pending",
        "controlled_stop_seen": controlled_stop_seen,
        "current_release_start_seen": current_release_start_seen,
        "startup_event_id": int((startup_event or {}).get("id") or 0) or None,
        "summary": (
            f"Controlled stop followed by v{version} startup integrity PASS"
            if passed
            else f"Run one controlled restart on v{version} to capture durable restart evidence"
        ),
    }


def build_release_readiness(
    *,
    version: str,
    operations: dict[str, Any],
    startup: dict[str, Any],
    diagnostics: dict[str, Any],
    performance: dict[str, Any],
    config_smoke: dict[str, Any],
    restart: dict[str, Any],
    auth: dict[str, Any],
    pwa: dict[str, Any],
    secure_transport: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build an evidence-honest release readiness contract.

    PASS is reserved for proven current evidence. PENDING means evidence or
    commissioning is still outstanding. FAIL means a blocking requirement is
    currently disproven. Deferred post-core work is reported separately and is
    never laundered into either PASS or a core blocker.
    """
    checks: list[dict[str, Any]] = []

    operations_ok = bool((operations or {}).get("ok"))
    checks.append(_check(
        "runtime_readiness",
        "Runtime readiness",
        "pass" if operations_ok else "fail",
        "Policy DB, RouterOS authority and reconciler are ready"
        if operations_ok else "One or more core runtime readiness checks failed",
        issues=list((operations or {}).get("issues") or []),
    ))

    startup_state = str((startup or {}).get("status") or "pending").lower()
    checks.append(_check(
        "startup_integrity",
        "Startup integrity",
        "pass" if startup_state == "ready" else ("fail" if startup_state == "degraded" else "pending"),
        "Current startup integrity checks passed"
        if startup_state == "ready" else (
            "Current startup integrity checks are degraded"
            if startup_state == "degraded" else "Startup integrity evidence has not run"
        ),
        checked_at=(startup or {}).get("checked_at"),
        issue_count=len((startup or {}).get("issues") or []),
    ))

    diagnostic_state = str((diagnostics or {}).get("overall") or "offline").lower()
    diagnostic_counts = dict((diagnostics or {}).get("counts") or {})
    warning_checks = _diagnostic_gate_findings(diagnostics, {"warning"})
    blocking_checks = _diagnostic_gate_findings(diagnostics, {"critical", "offline"})
    expected_detail_count = (
        int(diagnostic_counts.get("warning") or 0)
        if diagnostic_state == "warning"
        else int(diagnostic_counts.get("critical") or 0) + int(diagnostic_counts.get("offline") or 0)
        if diagnostic_state in {"critical", "offline"}
        else 0
    )
    actual_detail_count = len(warning_checks) if diagnostic_state == "warning" else len(blocking_checks)
    detail_incomplete = expected_detail_count > actual_detail_count
    if diagnostic_state == "healthy":
        diag_release_state = "pass"
    elif diagnostic_state == "warning":
        diag_release_state = "pending"
    else:
        diag_release_state = "fail"

    if diag_release_state == "pass":
        diagnostic_summary = "All diagnostic dependencies are healthy"
    elif detail_incomplete:
        diagnostic_summary = (
            "Diagnostic warnings require review; warning detail unavailable"
            if diag_release_state == "pending"
            else "Diagnostic dependencies are unavailable or critical; detailed blocker identity unavailable"
        )
    else:
        named = warning_checks if diag_release_state == "pending" else blocking_checks
        labels = ", ".join(item["label"] for item in named[:3])
        if len(named) > 3:
            labels += f", +{len(named) - 3} more"
        diagnostic_summary = (
            f"Diagnostic warning requires review: {labels}"
            if diag_release_state == "pending" and len(named) == 1
            else f"Diagnostic warnings require review: {labels}"
            if diag_release_state == "pending"
            else f"Diagnostic dependencies unavailable or critical: {labels}"
        )

    checks.append(_check(
        "dependency_health",
        "Dependency health",
        diag_release_state,
        diagnostic_summary,
        overall=diagnostic_state,
        counts=diagnostic_counts,
        warning_checks=warning_checks,
        blocking_checks=blocking_checks,
        detail_incomplete=detail_incomplete,
    ))

    acceptance = dict((performance or {}).get("acceptance") or {})
    performance_state = _state(acceptance.get("state"), {"pass", "pending", "fail"}, "pending")
    checks.append(_check(
        "live_performance",
        "Live performance acceptance",
        performance_state,
        "All live responsiveness classes meet their p95 budgets"
        if performance_state == "pass" else (
            "More live samples are required before responsiveness can be accepted"
            if performance_state == "pending" else "One or more live responsiveness budgets are exceeded"
        ),
        target_count=len(acceptance.get("targets") or []),
        min_samples=acceptance.get("min_samples"),
    ))

    config_state = _state((config_smoke or {}).get("state"), {"pass", "fail"}, "fail")
    checks.append(_check(
        "backup_restore",
        "Backup / restore smoke",
        config_state,
        str((config_smoke or {}).get("summary") or "Configuration round-trip evidence unavailable"),
        non_destructive=bool((config_smoke or {}).get("non_destructive")),
        digest_match=(
            bool((config_smoke or {}).get("source_digest"))
            and (config_smoke or {}).get("source_digest") == (config_smoke or {}).get("restored_digest")
        ),
    ))

    restart_state = _state((restart or {}).get("state"), {"pass", "pending"}, "pending")
    checks.append(_check(
        "controlled_restart",
        "Controlled restart / upgrade smoke",
        restart_state,
        str((restart or {}).get("summary") or "Controlled restart evidence pending"),
        controlled_stop_seen=bool((restart or {}).get("controlled_stop_seen")),
        current_release_start_seen=bool((restart or {}).get("current_release_start_seen")),
    ))

    pwa_ok = all((
        str((pwa or {}).get("mode") or "") == "online_first",
        (pwa or {}).get("cached_private_data") is False,
        (pwa or {}).get("offline_mutations") is False,
        (pwa or {}).get("background_sync") is False,
        (pwa or {}).get("push_notifications") is False,
        bool((pwa or {}).get("server_auth_required")),
        bool((pwa or {}).get("shared_display_lock_server_enforced")),
    ))
    checks.append(_check(
        "pwa_security",
        "PWA / shared-display security contract",
        "pass" if pwa_ok else "fail",
        "Online-first PWA keeps authenticated data and mutations server-controlled"
        if pwa_ok else "PWA safety contract does not match the accepted core design",
        online_first=str((pwa or {}).get("mode") or "") == "online_first",
        cached_private_data=bool((pwa or {}).get("cached_private_data")),
        offline_mutations=bool((pwa or {}).get("offline_mutations")),
        server_auth_required=bool((pwa or {}).get("server_auth_required")),
    ))

    auth_available = (auth or {}).get("available", True) is not False
    shared_mode = bool((auth or {}).get("shared_display_mode"))
    totp_count = max(0, int((auth or {}).get("totp_count") or 0))
    login_mode = str((auth or {}).get("login_mode") or "unknown")
    recovery_codes = max(0, int((auth or {}).get("recovery_codes_remaining") or 0))
    if not auth_available:
        shared_state = "fail"
        shared_summary = "Parent authentication configuration is unavailable"
    elif not shared_mode:
        shared_state = "pending"
        shared_summary = "Shared display has not yet been commissioned on this deployment"
    elif totp_count < 1:
        shared_state = "fail"
        shared_summary = "Shared display is enabled without an active authenticator"
    elif login_mode == "totp_only" and recovery_codes < 1:
        shared_state = "fail"
        shared_summary = "OTP-only parent access has no remaining recovery code"
    else:
        shared_state = "pass"
        shared_summary = "Shared display is commissioned with server-enforced unlock and active TOTP"
    checks.append(_check(
        "shared_display",
        "Shared-display commissioning",
        shared_state,
        shared_summary,
        auth_available=auth_available,
        enabled=shared_mode,
        totp_count=totp_count,
        login_mode=login_mode,
        recovery_codes_remaining=recovery_codes,
    ))

    states = [item["state"] for item in checks]
    overall = "fail" if "fail" in states else ("pending" if "pending" in states else "pass")
    counts = {state: states.count(state) for state in ("pass", "pending", "fail")}

    closure_matrix = [
        {
            "key": key,
            "label": label,
            "closed_in": closed_in,
            "state": "qualified",
        }
        for key, label, closed_in in CORE_CLOSURE_MATRIX
    ]

    # HTTPS is post-core commissioning evidence. Its state is intentionally
    # reported outside `checks`, so transport work does not alter the core
    # PASS/PENDING/FAIL count or manufacture a core release result.
    transport = dict(secure_transport or {})
    transport_state = str(transport.get("state") or "disabled")
    if transport_state == "ready_for_live_validation":
        https_state = "ready_for_live_validation"
        https_summary = (
            "Secure-cookie, Host allowlist and Cloudflare Access configuration are ready; "
            "live public-edge and authenticated journey validation remain outstanding."
        )
    elif transport_state == "blocked":
        https_state = "blocked"
        https_summary = "Remote access is enabled but one or more secure-transport configuration checks fail."
    else:
        https_state = "deferred"
        https_summary = "Remote access is not enabled on this deployment."

    deferred = [
        {
            "key": "https_remote_access",
            "label": "HTTPS / secure remote access",
            "state": https_state,
            "summary": https_summary,
            "evidence": {
                "public_host": transport.get("public_host"),
                "secure_cookies": bool(transport.get("secure_cookies")),
                "host_allowlist_enforced": bool(transport.get("host_allowlist_enforced")),
                "cloudflare_access_protected": bool(transport.get("cloudflare_access_protected")),
                "live_external_validation": transport.get("live_external_validation", "not_run"),
            },
        },
        {
            "key": "notifications",
            "label": "Notification expansion",
            "state": "deferred",
            "summary": "Human gate remains required; notification expansion is outside the core closure release.",
        },
    ]

    return {
        "schema": RELEASE_READINESS_SCHEMA,
        "version": str(version),
        "captured_at": _now_iso(),
        "state": overall,
        "core_ready": overall == "pass",
        "counts": counts,
        "checks": checks,
        "closure_matrix": closure_matrix,
        "parent_journeys": [
            {"key": key, "label": label, "path": path, "state": "source_qualified"}
            for key, label, path in PARENT_JOURNEY_MATRIX
        ],
        "deferred": deferred,
        "meaning": {
            "pass": "Every current core release check has affirmative evidence.",
            "pending": "No blocking failure is proven, but one or more live/commissioning checks still need evidence.",
            "fail": "At least one core release requirement is currently disproven.",
        },
        "notes": [
            "PENDING is not PASS; missing evidence never becomes a healthy result.",
            "The backup/restore smoke imports only into a temporary database and does not mutate live policy state.",
            "The controlled restart check requires durable stop/start evidence; current uptime alone is insufficient.",
            "HTTPS/remote access is post-core commissioning evidence and does not alter the core PASS/PENDING/FAIL count.",
            "Notification expansion remains behind its explicit human gate.",
        ],
    }
