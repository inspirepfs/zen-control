"""Fail-closed readiness helpers for legacy MikroTik Kid Control authority transfer.

The helpers in this module are deliberately side-effect free.  RouterOS writes
remain in the adapter boundary and local policy materialisation remains in the
PolicyStore.  This module only decides whether a staged migration is safe to
hand to those authority boundaries.
"""
from __future__ import annotations

from typing import Any


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "yes", "true", "on"}


SOURCE = "mikrotik_kid_control"


def _mac(value: Any) -> str:
    return str(value or "").strip().upper().replace("-", ":")


def _profile_semantics(profile: dict) -> dict:
    proposed = profile.get("proposed") or {}
    return {
        "name": str(proposed.get("name") or "").strip(),
        "desired_mode": str(proposed.get("desired_mode") or "").strip().lower(),
        "bandwidth_preset": str(proposed.get("bandwidth_preset") or "").strip().lower(),
        "blocked_services": sorted(proposed.get("blocked_services") or []),
        "daily_quota_mb": int(proposed.get("daily_quota_mb") or 0),
        "daily_quota_action": str(proposed.get("daily_quota_action") or "blocked").strip().lower(),
        "service_quotas": dict(proposed.get("service_quotas") or {}),
    }


def _existing_profile_matches(existing: dict, proposed_profile: dict) -> bool:
    expected = _profile_semantics(proposed_profile)
    return (
        str(existing.get("name") or "").strip() == expected["name"]
        and str(existing.get("desired_mode") or "").strip().lower() == expected["desired_mode"]
        and str(existing.get("bandwidth_preset") or "").strip().lower() == expected["bandwidth_preset"]
        and sorted(existing.get("blocked_services") or []) == expected["blocked_services"]
        and int(existing.get("daily_quota_mb") or 0) == expected["daily_quota_mb"]
        and str(existing.get("daily_quota_action") or "blocked").strip().lower() == expected["daily_quota_action"]
        and dict(existing.get("service_quotas") or {}) == expected["service_quotas"]
    )


def _static_lease_for_device(snapshot: dict, device: dict) -> dict | None:
    identity = device.get("identity") or {}
    ip = str(identity.get("ipv4") or "").strip()
    mac = _mac(device.get("mac"))
    if not ip or not mac:
        return None
    matches = []
    for lease in snapshot.get("dhcp_leases", []) or []:
        if not isinstance(lease, dict):
            continue
        if str(lease.get("address") or "").strip() != ip:
            continue
        if _mac(lease.get("mac") or lease.get("mac-address")) != mac:
            continue
        matches.append(lease)
    if len(matches) != 1:
        return None
    if _truthy(matches[0].get("dynamic")):
        return None
    return matches[0]



def failed_cutover_cleanup_complete(cutover: dict | None) -> bool:
    """Return True only when a FAILED event proves its fail-safe cleanup completed.

    This lets the explicit rollback action finalize durable recovery without
    replaying mode or membership writes against RouterOS state that the initial
    failure handler already restored.
    """
    if not isinstance(cutover, dict) or str(cutover.get("state") or "").lower() != "failed":
        return False
    evidence = cutover.get("evidence") or {}
    if not isinstance(evidence, dict):
        return False
    return bool(evidence.get("cleanup_complete")) and not (evidence.get("cleanup_errors") or [])

def build_kid_control_cutover_readiness(
    *,
    staged: dict | None,
    fresh_preview: dict | None,
    fresh_snapshot: dict | None,
    settings: dict | None,
    existing_profiles: list[dict] | None,
    existing_device_policy: dict | None,
    current_cutover: dict | None = None,
) -> dict:
    """Return deterministic authority-transfer readiness without making writes."""
    checks: list[dict] = []

    def add(key: str, ok: bool, detail: str, *, blocking: bool = True) -> None:
        checks.append({"key": key, "ok": bool(ok), "blocking": bool(blocking), "detail": detail})

    if current_cutover and current_cutover.get("state") in {"prepared", "authoritative", "failed"}:
        state = str(current_cutover.get("state") or "").upper()
        add("authority_state", False, f"Authority transfer is already {state}; roll it back before starting another cutover")
        return {
            "schema": "zen_kid_control_cutover_readiness_v1",
            "ready": False,
            "checks": checks,
            "blocking": [item for item in checks if item["blocking"] and not item["ok"]],
            "devices": [],
        }

    staged_payload = (staged or {}).get("payload") if isinstance(staged, dict) else None
    staged_payload = staged_payload if isinstance(staged_payload, dict) else {}
    staged_fp = str((staged or {}).get("source_fingerprint") or staged_payload.get("source_fingerprint") or "").strip().lower()
    fresh_fp = str((fresh_preview or {}).get("source_fingerprint") or "").strip().lower()

    add("staged", bool(staged_payload), "A staged replacement exists" if staged_payload else "Stage the replacement before cutover")
    add(
        "source_unchanged",
        bool(staged_fp and fresh_fp and staged_fp == fresh_fp),
        "Fresh legacy fingerprint matches the staged proposal" if staged_fp and staged_fp == fresh_fp else "Legacy Kid Control changed since staging; re-stage before cutover",
    )

    warnings = int((fresh_preview or {}).get("summary", {}).get("warnings") or 0)
    add("translation_clean", warnings == 0, "Translation has no unresolved semantic warnings" if warnings == 0 else f"Translation has {warnings} warning(s) requiring review")

    profiles = list((fresh_preview or {}).get("profiles") or [])
    add("profiles_present", bool(profiles), f"{len(profiles)} legacy profile(s) are present" if profiles else "No legacy Kid Control profiles were found")
    disabled_profiles = [item.get("legacy_name") for item in profiles if item.get("legacy_disabled")]
    add("legacy_profiles_active", not disabled_profiles, "Legacy profiles are currently active" if not disabled_profiles else "Disabled legacy profiles cannot be cut over: " + ", ".join(str(x) for x in disabled_profiles))

    auto_mode = str((settings or {}).get("auto_reconcile_mode") or "off").strip().lower()
    add(
        "automatic_reconciliation",
        auto_mode == "enforce",
        "Automatic reconciliation is ENFORCE" if auto_mode == "enforce" else f"Automatic reconciliation is {auto_mode.upper()}; ENFORCE is required for scheduled replacement policy",
    )

    by_name = {str(item.get("name") or "").strip(): item for item in (existing_profiles or [])}
    profile_name_by_id = {str(item.get("id")): str(item.get("name") or "").strip() for item in (existing_profiles or [])}
    profile_conflicts = []
    for profile in profiles:
        name = str((profile.get("proposed") or {}).get("name") or "").strip()
        existing = by_name.get(name)
        if existing and not _existing_profile_matches(existing, profile):
            profile_conflicts.append(name)
    add(
        "local_profile_conflicts",
        not profile_conflicts,
        "No conflicting ZEN profile names" if not profile_conflicts else "Existing ZEN profile differs from staged replacement: " + ", ".join(profile_conflicts),
    )

    device_rows = []
    device_blockers = []
    device_policy = existing_device_policy or {}
    for device in (fresh_preview or {}).get("devices", []) or []:
        identity = device.get("identity") or {}
        ip = str(identity.get("ipv4") or "").strip()
        state = str(identity.get("state") or "").strip().lower()
        mac = _mac(device.get("mac"))
        profile_name = str((device.get("proposed") or {}).get("profile_name") or "").strip()
        row = {
            "name": str(device.get("legacy_name") or ""),
            "mac": mac,
            "ip": ip,
            "profile_name": profile_name,
            "identity_state": state,
            "static_lease": False,
            "existing_policy": bool(ip and ip in device_policy),
            "ready": True,
            "reason": "",
        }
        if state != "matched" or not ip or not mac:
            row["ready"] = False
            row["reason"] = "A unique live IPv4/MAC match is required"
        elif not profile_name:
            row["ready"] = False
            row["reason"] = "Legacy profile assignment is unresolved"
        else:
            lease = _static_lease_for_device(fresh_snapshot or {}, device)
            if not lease:
                row["ready"] = False
                row["reason"] = "A unique static DHCP lease matching this MAC/IP is required before authority transfer"
            else:
                row["static_lease"] = True
                existing = device_policy.get(ip) if isinstance(device_policy, dict) else None
                if existing:
                    current_profile_id = existing.get("profile_id")
                    current_profile_name = profile_name_by_id.get(str(current_profile_id), "") if current_profile_id not in (None, "", 0, "0") else ""
                    if current_profile_name and current_profile_name != profile_name:
                        row["ready"] = False
                        row["reason"] = f"Existing ZEN assignment uses profile '{current_profile_name}'"
                    elif str(existing.get("mode_override") or "inherit").strip().lower() != "inherit":
                        row["ready"] = False
                        row["reason"] = "Existing ZEN mode override must be INHERIT before cutover"
        if not row["ready"]:
            device_blockers.append(row["name"] or mac or ip or "unknown")
        device_rows.append(row)

    add(
        "device_identity",
        bool(device_rows) and not device_blockers,
        f"All {len(device_rows)} configured device(s) have unique live identity and static DHCP leases" if device_rows and not device_blockers else ("Device cutover blockers: " + ", ".join(device_blockers) if device_blockers else "No configured devices were found"),
    )

    blocking = [item for item in checks if item["blocking"] and not item["ok"]]
    return {
        "schema": "zen_kid_control_cutover_readiness_v1",
        "ready": not blocking,
        "source_fingerprint": fresh_fp,
        "checks": checks,
        "blocking": blocking,
        "devices": device_rows,
    }
