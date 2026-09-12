"""Read-only translation of legacy MikroTik Kid Control into staged ZEN intent.

This module has no RouterOS client and performs no writes. It converts a bounded
inventory snapshot into a deterministic migration proposal whose stable identity
is the configured MAC address. Live IPv4 observations are evidence only.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any

DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "yes", "true", "on"}


def _mac(value: Any) -> str:
    raw = str(value or "").strip().upper().replace("-", ":")
    if not re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", raw):
        return ""
    return raw


def _ipv4_values(value: Any) -> list[str]:
    result: list[str] = []
    for token in re.split(r"[\s,;]+", str(value or "").strip()):
        if not token:
            continue
        try:
            parsed = ipaddress.ip_address(token)
        except ValueError:
            continue
        if parsed.version == 4:
            text = str(parsed)
            if text not in result:
                result.append(text)
    return result


def _router_clock(value: str) -> str:
    raw = str(value or "").strip().lower()
    if re.fullmatch(r"(?:[01]?\d|2[0-3]):[0-5]\d(?::[0-5]\d)?", raw):
        hh, mm, *_ = raw.split(":")
        return f"{int(hh):02d}:{int(mm):02d}"
    match = re.fullmatch(r"(?:(\d{1,2})h)?(?:(\d{1,2})m)?(?:(\d{1,2})s)?", raw)
    if not match or not any(match.groups()):
        raise ValueError(f"Unsupported RouterOS clock value '{value}'")
    hour = int(match.group(1) or 0)
    minute = int(match.group(2) or 0)
    second = int(match.group(3) or 0)
    if hour > 23 or minute > 59 or second > 59:
        raise ValueError(f"Unsupported RouterOS clock value '{value}'")
    if second:
        raise ValueError(
            f"RouterOS second-level clock '{value}' cannot be represented by ZEN minute schedules"
        )
    return f"{hour:02d}:{minute:02d}"


def _day_windows(raw: Any) -> list[tuple[str, str]]:
    text = str(raw or "").strip()
    if not text:
        return []
    # RouterOS Kid Control commonly stores comma-separated time ranges. Accept
    # semicolons too, but reject anything ambiguous rather than guessing.
    ranges: list[tuple[str, str]] = []
    for part in re.split(r"\s*[,;]\s*", text):
        if not part:
            continue
        if "-" not in part:
            raise ValueError(f"Unsupported RouterOS Kid Control window '{part}'")
        start_raw, end_raw = [item.strip() for item in part.split("-", 1)]
        start = _router_clock(start_raw)
        end = _router_clock(end_raw)
        if start == end:
            raise ValueError(f"Kid Control window '{part}' has identical start and end")
        if start > end:
            raise ValueError(
                f"Overnight Kid Control window '{part}' requires manual review; ZEN will not guess cross-day semantics"
            )
        ranges.append((start, end))
    return ranges


def _configured_profiles(snapshot: dict) -> list[dict]:
    result = []
    for raw in snapshot.get("profiles", []) or []:
        if not isinstance(raw, dict):
            continue
        name = str(raw.get("name") or "").strip()
        if not name:
            continue
        item = {
            "name": name,
            "disabled": _truthy(raw.get("disabled")),
            "rate-limit": str(raw.get("rate-limit") or "").strip(),
        }
        for day in DAYS:
            item[day] = str(raw.get(day) or "").strip()
            item[f"tur-{day}"] = str(raw.get(f"tur-{day}") or "").strip()
        result.append(item)
    return sorted(result, key=lambda item: item["name"].casefold())


def _configured_devices(snapshot: dict) -> list[dict]:
    result = []
    for raw in snapshot.get("devices", []) or []:
        if not isinstance(raw, dict) or _truthy(raw.get("dynamic")):
            continue
        mac = _mac(raw.get("mac-address") or raw.get("mac"))
        name = str(raw.get("name") or "").strip()
        user = str(raw.get("user") or "").strip()
        # A malformed configured row is still surfaced rather than silently
        # becoming some other device. Stable MAC is mandatory for later cutover.
        result.append({
            "name": name,
            "mac": mac,
            "user": user,
            "disabled": _truthy(raw.get("disabled")),
            "inactive": _truthy(raw.get("inactive")),
            "ip-address": ",".join(_ipv4_values(raw.get("ip-address"))),
        })
    return result


def legacy_policy_fingerprint(snapshot: dict) -> str:
    """Hash policy-bearing legacy configuration only.

    Activity, counters, current IPs, ARP/DHCP state, dynamic discovery rows and
    capture time are deliberately excluded. A fresh identity match is always
    performed again at eventual cutover.
    """
    profiles = _configured_profiles(snapshot)
    devices = []
    for item in _configured_devices(snapshot):
        devices.append({
            "name": item["name"],
            "mac": item["mac"],
            "user": item["user"],
            "disabled": item["disabled"],
        })
    devices = sorted(devices, key=lambda item: (item["name"].casefold(), item["mac"], item["user"]))
    canonical = {"profiles": profiles, "devices": devices}
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _identity_evidence(mac: str, configured_ips: list[str], snapshot: dict) -> dict:
    if not mac:
        return {
            "state": "invalid_mac",
            "ipv4": "",
            "candidates": [],
            "evidence": [],
        }

    by_source: dict[str, list[str]] = {"kid_control": [], "dhcp": [], "arp": []}
    by_source["kid_control"] = list(configured_ips)

    for row in snapshot.get("dhcp_leases", []) or []:
        if not isinstance(row, dict) or _mac(row.get("mac") or row.get("mac-address")) != mac:
            continue
        by_source["dhcp"].extend(_ipv4_values(row.get("address")))

    for row in snapshot.get("arp_entries", []) or []:
        if not isinstance(row, dict) or _mac(row.get("mac") or row.get("mac-address")) != mac:
            continue
        # If a caller supplies an explicit completeness flag, ignore incomplete
        # ARP observations. Absence of the flag is treated as unknown but usable.
        if "complete" in row and not bool(row.get("complete")):
            continue
        by_source["arp"].extend(_ipv4_values(row.get("address")))

    for source in by_source:
        by_source[source] = sorted(set(by_source[source]))

    # Kid Control's own configured-device observation is the most specific
    # current evidence. If exactly one IPv4 is present, retain it even if ARP is
    # stale/missing. Otherwise use unique corroborating inventory evidence.
    if len(by_source["kid_control"]) == 1:
        selected = by_source["kid_control"][0]
        evidence = [source for source, values in by_source.items() if selected in values]
        return {"state": "matched", "ipv4": selected, "candidates": [selected], "evidence": evidence}

    candidates = sorted(set(by_source["kid_control"] + by_source["dhcp"] + by_source["arp"]))
    if len(candidates) == 1:
        selected = candidates[0]
        evidence = [source for source, values in by_source.items() if selected in values]
        return {"state": "matched", "ipv4": selected, "candidates": candidates, "evidence": evidence}
    if not candidates:
        return {"state": "unresolved", "ipv4": "", "candidates": [], "evidence": []}
    return {
        "state": "ambiguous",
        "ipv4": "",
        "candidates": candidates,
        "evidence": [source for source, values in by_source.items() if values],
    }


def _translate_profile(raw: dict) -> dict:
    warnings: list[str] = []
    notices: list[str] = []
    schedule_slots: dict[tuple[str, str], list[str]] = {}
    for day in DAYS:
        try:
            windows = _day_windows(raw.get(day))
        except ValueError as exc:
            warnings.append(f"{day.upper()} schedule requires manual review: {exc}")
            windows = []
        for start, end in windows:
            schedule_slots.setdefault((start, "normal"), []).append(day)
            schedule_slots.setdefault((end, "blocked"), []).append(day)

    schedule = [
        {"days": [day for day in DAYS if day in days], "time": time, "mode": mode}
        for (time, mode), days in sorted(schedule_slots.items(), key=lambda item: (item[0][0], item[0][1] != "normal"))
    ]

    rate_limit = str(raw.get("rate-limit") or "").strip()
    if rate_limit:
        warnings.append(
            f"Legacy rate-limit '{rate_limit}' requires manual bandwidth mapping; ZEN did not guess a preset."
        )

    unlimited_windows = {
        day: str(raw.get(f"tur-{day}") or "").strip()
        for day in DAYS
        if str(raw.get(f"tur-{day}") or "").strip()
    }
    if unlimited_windows:
        warnings.append(
            "Legacy unlimited-rate (tur-*) windows require manual review; ZEN did not invent a bandwidth schedule."
        )

    if bool(raw.get("disabled")):
        notices.append(
            "Legacy Kid Control profile is currently disabled. Its retained configuration may be the expected rollback copy after authority transfer."
        )

    return {
        "legacy_name": raw["name"],
        "legacy_disabled": bool(raw.get("disabled")),
        "legacy_rate_limit": rate_limit,
        "legacy_unlimited_windows": unlimited_windows,
        "warnings": warnings,
        "notices": notices,
        "proposed": {
            "name": raw["name"],
            # Default BLOCKED plus explicit opening/closing events is equivalent
            # to Kid Control's allowed-window semantics, including blank days.
            "desired_mode": "blocked",
            "bandwidth_preset": "normal",
            "blocked_services": [],
            "daily_quota_mb": 0,
            "daily_quota_action": "blocked",
            "service_quotas": {},
            "notes": "Staged from MikroTik Kid Control; not active until explicit cutover.",
            "schedule": schedule,
        },
    }


def translate_kid_control_snapshot(snapshot: dict) -> dict:
    if not isinstance(snapshot, dict):
        raise ValueError("Kid Control snapshot must be an object")

    captured_at = str(snapshot.get("captured_at") or "").strip()
    if not captured_at:
        captured_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    raw_profiles = _configured_profiles(snapshot)
    profile_names = {item["name"] for item in raw_profiles}
    profiles = [_translate_profile(item) for item in raw_profiles]

    raw_devices = _configured_devices(snapshot)
    devices = []
    for raw in raw_devices:
        warnings: list[str] = []
        if not raw["mac"]:
            warnings.append("Configured Kid Control device has no valid MAC address; cutover must remain blocked.")
        profile_name = raw["user"] if raw["user"] in profile_names else ""
        if raw["user"] and not profile_name:
            warnings.append(
                f"Device references missing legacy profile '{raw['user']}'; no ZEN profile was guessed."
            )
        configured_ips = _ipv4_values(raw.get("ip-address"))
        identity = _identity_evidence(raw["mac"], configured_ips, snapshot)
        if identity["state"] == "ambiguous":
            warnings.append("MAC currently resolves to multiple IPv4 candidates; activation must re-match and fail closed.")
        elif identity["state"] == "invalid_mac":
            warnings.append("Stable MAC identity is invalid; activation must remain blocked.")
        devices.append({
            "legacy_name": raw["name"],
            "mac": raw["mac"],
            "legacy_profile": raw["user"],
            "legacy_disabled": bool(raw["disabled"]),
            "legacy_inactive": bool(raw["inactive"]),
            "identity": identity,
            "warnings": warnings,
            "proposed": {
                "alias": raw["name"],
                "identity_key": f"mac:{raw['mac']}" if raw["mac"] else "",
                "profile_name": profile_name,
                "mode_override": "inherit",
                "category": "other",
                "notes": "Staged from MikroTik Kid Control; IPv4 is observational and will be re-matched at cutover.",
            },
        })

    ignored_dynamic = sum(
        1 for row in (snapshot.get("devices", []) or [])
        if isinstance(row, dict) and _truthy(row.get("dynamic"))
    )
    warning_count = sum(len(item["warnings"]) for item in profiles) + sum(len(item["warnings"]) for item in devices)
    identity_states = {"matched": 0, "unresolved": 0, "ambiguous": 0, "invalid_mac": 0}
    for item in devices:
        identity_states[item["identity"]["state"]] = identity_states.get(item["identity"]["state"], 0) + 1

    return {
        "schema": "zen_kid_control_migration_v1",
        "source": "mikrotik_kid_control",
        "captured_at": captured_at,
        "source_fingerprint": legacy_policy_fingerprint(snapshot),
        "state": "preview",
        "authority": {
            "router_reads": True,
            "router_writes": 0,
            "legacy_modified": False,
            "zen_enforcement_active": False,
        },
        "summary": {
            "legacy_profiles": len(profiles),
            "configured_devices": len(devices),
            "ignored_dynamic_devices": ignored_dynamic,
            "matched_devices": identity_states.get("matched", 0),
            "unresolved_devices": identity_states.get("unresolved", 0),
            "ambiguous_devices": identity_states.get("ambiguous", 0) + identity_states.get("invalid_mac", 0),
            "warnings": warning_count,
        },
        "profiles": profiles,
        "devices": devices,
    }
