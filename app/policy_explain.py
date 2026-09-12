"""Evidence-led effective-policy explanation for ZEN Control.

This module does not decide policy and never writes RouterOS.  It explains the
already-computed desired policy and, when available, the fresh live policy plan.
"""

from app.policy_groups import group_members, normalized_group_catalog
from app.policy_parity import policy_parity_contract


_MODE_RANK = {"normal": 0, "slow": 1, "blocked": 2}


def _mode(value):
    value = str(value or "unknown").strip().lower()
    return value if value in _MODE_RANK else "unknown"


def _strongest_mode(*values):
    modes = [_mode(value) for value in values]
    if any(value == "unknown" for value in modes):
        return "unknown"
    return max(modes, key=lambda value: _MODE_RANK[value]) if modes else "unknown"


def _service_name(key, definitions, policy_groups=None):
    item = definitions.get(key) or {}
    groups = normalized_group_catalog(policy_groups)
    return item.get("name") or groups.get(key, {}).get("name") or key


def _active_quota_sources(service_key, quota_state, definitions, policy_groups=None):
    sources = []
    groups = normalized_group_catalog(policy_groups)
    group_keys = frozenset(groups)
    for quota_key in quota_state.get("active_service_blocks") or []:
        if quota_key == service_key:
            sources.append(f"service quota: {_service_name(quota_key, definitions, groups)}")
        elif quota_key in group_keys and service_key in group_members(quota_key, groups):
            sources.append(f"{groups[quota_key]['name']} quota")
    return sources


def _service_decision_source(service_key, desired_policy, profile, definitions, policy_groups=None):
    """Describe the highest-value visible provenance for one concrete service."""
    profile = profile or {}
    profile_blocks = set(profile.get("blocked_services") or [])
    requested = set(desired_policy.get("requested_blocked_services") or [])
    effective = set(desired_policy.get("blocked_services") or [])
    quota_state = desired_policy.get("quota_state") or {}
    overrides = list(desired_policy.get("scheduled_service_overrides") or [])
    groups = normalized_group_catalog(policy_groups)
    group_keys = frozenset(groups)

    quota_sources = _active_quota_sources(service_key, quota_state, definitions, groups)
    if quota_sources:
        return {
            "kind": "quota",
            "label": quota_sources[0],
            "detail": "Quota exhaustion is evaluated after schedules and is authoritative for this service.",
        }

    direct_schedule = next(
        (row for row in reversed(overrides) if row.get("service") == service_key),
        None,
    )
    if direct_schedule:
        return {
            "kind": "schedule",
            "label": f"schedule: {direct_schedule.get('label') or service_key}",
            "detail": f"Concrete service schedule says {str(direct_schedule.get('state') or '').upper()}.",
        }

    group_schedules = [
        row for row in overrides
        if row.get("service") in group_keys
        and service_key in group_members(row.get("service"), groups)
    ]
    if group_schedules:
        row = group_schedules[-1]
        group = groups[row["service"]]["name"]
        # A direct profile block can survive an aggregate ALLOW schedule, so only
        # attribute the final state to the group schedule when it explains it.
        if row.get("state") == "block" or service_key not in profile_blocks:
            return {
                "kind": "schedule_group",
                "label": f"schedule: {row.get('label') or group}",
                "detail": f"{group} aggregate schedule says {str(row.get('state') or '').upper()}.",
            }

    if service_key in profile_blocks:
        return {
            "kind": "profile",
            "label": f"profile: {profile.get('name') or 'assigned profile'}",
            "detail": "The concrete service is directly listed in the assigned profile.",
        }

    active_groups = [
        key for key in desired_policy.get("blocked_policy_groups") or []
        if service_key in group_members(key, groups)
    ]
    if active_groups:
        names = ", ".join(groups[key]["name"] for key in active_groups if key in groups)
        return {
            "kind": "policy_group",
            "label": f"policy group: {names}",
            "detail": "The logical group expands to concrete services; the group itself has no RouterOS firewall authority.",
        }

    if service_key in requested:
        return {
            "kind": "requested",
            "label": "configured service block",
            "detail": "A block is requested in local policy, but no more-specific source was required to explain it.",
        }

    if service_key in effective:
        return {
            "kind": "derived",
            "label": "derived policy block",
            "detail": "The service is blocked by the computed effective policy.",
        }

    if group_schedules:
        row = group_schedules[-1]
        group = groups[row["service"]]["name"]
        return {
            "kind": "schedule_group",
            "label": f"schedule: {row.get('label') or group}",
            "detail": f"{group} aggregate schedule says {str(row.get('state') or '').upper()}.",
        }

    return {
        "kind": "default",
        "label": "no active service block",
        "detail": "No profile, schedule, policy-group or quota rule currently requires this service to be blocked.",
    }


def build_policy_explanation(
    *,
    address,
    device_name,
    device_config,
    profile,
    desired_policy,
    live_plan=None,
    temporary_access=None,
    service_definitions=(),
    policy_groups=None,
    router_error=None,
    evidence_warnings=(),
    focus_service=None,
):
    """Compose a deterministic explanation from already-resolved policy evidence."""
    device_config = dict(device_config or {})
    profile = dict(profile or {}) if profile else None
    desired_policy = dict(desired_policy or {})
    live_plan = dict(live_plan or {}) if live_plan else None
    temporary_access = dict(temporary_access or {})
    groups = normalized_group_catalog(policy_groups)
    group_keys = frozenset(groups)
    definitions = {
        str(item.get("key") or ""): dict(item)
        for item in service_definitions
        if item.get("key") and item.get("key") not in group_keys
    }

    desired_mode = _mode(desired_policy.get("mode"))
    base_mode = _mode(desired_policy.get("base_mode"))
    live_mode = _mode((live_plan or {}).get("live_mode"))
    global_mode = _mode((live_plan or {}).get("global_mode"))
    effective_now = (
        _strongest_mode(live_mode, global_mode) if live_plan else "unknown"
    )

    mode_override = str(device_config.get("mode_override") or "inherit").lower()
    mode_chain = []
    if profile:
        mode_chain.append(
            {
                "stage": "profile",
                "label": profile.get("name") or "Assigned profile",
                "value": _mode(profile.get("desired_mode")).upper(),
                "active": mode_override in {"", "inherit"},
                "detail": "Profile mode is the base device policy unless a device override is configured.",
                "href": "/#policies/profiles",
            }
        )
    else:
        mode_chain.append(
            {
                "stage": "default",
                "label": "No profile assigned",
                "value": "NORMAL",
                "active": mode_override in {"", "inherit"},
                "detail": "ZEN defaults an unassigned device to NORMAL desired mode.",
                "href": "/#policies/assignments",
            }
        )

    if mode_override not in {"", "inherit"}:
        mode_chain.append(
            {
                "stage": "device_override",
                "label": "Device override",
                "value": _mode(mode_override).upper(),
                "active": True,
                "detail": "The per-device mode override replaces the profile base mode.",
                "href": f"/?focus=assignment:{address}#policies/assignments",
            }
        )

    exception = desired_policy.get("active_date_exception") or {}
    if exception:
        mode_chain.append(
            {
                "stage": "date_exception",
                "label": exception.get("label") or "Date exception",
                "value": str(
                    (desired_policy.get("quota_state") or {}).get("mode_before_quota")
                    if exception.get("mode") == "template"
                    else exception.get("mode") or desired_mode
                ).upper(),
                "active": True,
                "detail": f"Active {exception.get('start_date', '?')} → {exception.get('end_date', '?')}.",
                "href": "/#schedules/exceptions",
            }
        )
    elif desired_policy.get("schedule_reason"):
        mode_chain.append(
            {
                "stage": "schedule",
                "label": str(desired_policy.get("schedule_reason")),
                "value": str((desired_policy.get("quota_state") or {}).get("mode_before_quota") or desired_mode).upper(),
                "active": True,
                "detail": "The most recent matching mode schedule currently owns the desired device mode.",
                "href": "/#schedules/planner",
            }
        )

    quota = desired_policy.get("quota_state") or {}
    if quota.get("configured"):
        daily = quota.get("daily") or {}
        if not quota.get("enabled"):
            quota_value = "OFF"
            quota_detail = "Quota is configured but the quota engine is disabled."
        elif not quota.get("available"):
            quota_value = "FAIL-OPEN"
            quota_detail = quota.get("telemetry_error") or "Quota telemetry is unavailable; ZEN does not invent exhaustion."
        elif daily.get("exhausted"):
            quota_value = str(daily.get("action") or desired_mode).upper()
            quota_detail = f"Daily quota exhausted at {daily.get('used_human', 'unknown')} / {daily.get('limit_mb', '?')} MiB."
        elif quota.get("active_service_blocks"):
            quota_value = "SERVICE BLOCK"
            quota_detail = "One or more service/group quotas are exhausted; device mode may remain unchanged."
        else:
            quota_value = "TRACKING"
            quota_detail = "Configured quotas are currently below their enforcement threshold."
        mode_chain.append(
            {
                "stage": "quota",
                "label": "Quota evaluation",
                "value": quota_value,
                "active": bool(quota.get("active")),
                "detail": quota_detail,
                "href": "/#settings/policy",
            }
        )

    mode_chain.append(
        {
            "stage": "desired",
            "label": "Computed desired device mode",
            "value": desired_mode.upper(),
            "active": True,
            "detail": f"Source: {desired_policy.get('mode_source') or 'default'}.",
            "href": f"/?focus=device:{address}#devices/managed",
        }
    )

    if temporary_access.get("active"):
        mode_chain.append(
            {
                "stage": "temporary",
                "label": "Temporary NORMAL override",
                "value": "NORMAL",
                "active": True,
                "detail": (
                    f"RouterOS temporarily owns the device mode until {temporary_access.get('restore_time') or temporary_access.get('restore_at') or 'scheduled expiry'}, "
                    f"then restores {str(temporary_access.get('restore_mode') or 'unknown').upper()}. Global mode and service blocks still apply."
                ),
                "href": f"/?focus=device:{address}#devices/managed",
            }
        )

    if live_plan:
        mode_chain.append(
            {
                "stage": "router_device",
                "label": "Live RouterOS device mode",
                "value": live_mode.upper(),
                "active": True,
                "detail": (
                    "Matches desired device policy."
                    if not live_plan.get("mode_drift")
                    else f"Drift: ZEN desires {desired_mode.upper()}."
                ),
                "href": f"/?focus=device:{address}#devices/managed",
            }
        )
        mode_chain.append(
            {
                "stage": "global",
                "label": "Household global mode",
                "value": global_mode.upper(),
                "active": global_mode != "normal",
                "detail": "The global RouterOS MASTER policy can be more restrictive than a device mode and is never bypassed by temporary device access.",
                "href": "/#dashboard/controls",
            }
        )

    service_states = {
        row.get("key"): row for row in (live_plan or {}).get("service_states", [])
        if row.get("key")
    }
    requested = set(desired_policy.get("requested_blocked_services") or [])
    effective_blocks = set(desired_policy.get("blocked_services") or [])
    unsupported = set(desired_policy.get("unsupported_policy_keys") or [])
    unsupported_group_members = set(desired_policy.get("unsupported_policy_group_members") or [])
    unsupported_requests = unsupported | unsupported_group_members
    service_rows = []
    all_keys = set(definitions) | set(service_states) | (requested - set(group_keys)) | unsupported_requests
    for key in sorted(all_keys, key=lambda item: (_service_name(item, definitions).lower(), item)):
        state = service_states.get(key) or {}
        source = _service_decision_source(key, desired_policy, profile, definitions, groups)
        requested_block = key in requested or key in effective_blocks or key in unsupported_requests
        desired_block = bool(state.get("desired_blocked", key in effective_blocks))
        available = bool(state.get("available", False)) if state else False
        live_known = live_plan is not None
        definition = definitions.get(key) or {}
        local_contract_error = definition.get("provisioning_error")
        if state:
            live_state = "BLOCK" if state.get("live_blocked") else "ALLOW"
            live_label = live_state if available else "UNAVAILABLE"
            enforcement_state = "live" if available else "unavailable"
        elif live_known and definition.get("enforcement_approved") and local_contract_error:
            live_label = "DEGRADED"
            available = False
            enforcement_state = "degraded"
        elif live_known and not definition and key in unsupported_requests:
            live_label = "UNSUPPORTED"
            available = False
            enforcement_state = "unsupported"
        elif live_known:
            live_label = "NO CONTRACT"
            enforcement_state = "reporting_only"
        else:
            live_label = "UNKNOWN"
            available = None
            enforcement_state = "unknown"
        service_rows.append(
            {
                "key": key,
                "name": _service_name(key, definitions),
                "desired": "BLOCK" if desired_block else ("BLOCK REQUESTED" if requested_block else "ALLOW"),
                "desired_blocked": desired_block,
                "requested_block": requested_block,
                "live": live_label,
                "available": available,
                "live_known": live_known,
                "enforcement_state": enforcement_state,
                "defined": key in definitions,
                "drift": bool(state.get("drift")),
                "source": source["label"],
                "source_kind": source["kind"],
                "detail": source["detail"],
                "classification": state.get("classification") or definitions.get(key, {}).get("classification") or "reporting",
                "error": state.get("error") or local_contract_error,
                "focus": key == focus_service,
            }
        )

    next_changes = []
    if temporary_access.get("active"):
        next_changes.append(
            {
                "kind": "temporary",
                "when": temporary_access.get("restore_time") or temporary_access.get("restore_at") or "scheduled expiry",
                "label": f"Temporary access ends; restore {str(temporary_access.get('restore_mode') or 'unknown').upper()}",
            }
        )
    next_action = desired_policy.get("next_policy_action") or {}
    if next_action:
        next_changes.append(
            {
                "kind": "policy",
                "when": f"{next_action.get('date', '')} {next_action.get('time', '')}".strip(),
                "label": f"{next_action.get('label') or 'Policy event'} → {next_action.get('value') or next_action.get('mode') or 're-evaluate'}",
                "wall_resolution": next_action.get("wall_resolution") or {},
                "requested_time": next_action.get("requested_time"),
            }
        )

    bandwidth = {
        "preset": desired_policy.get("bandwidth_preset") or (live_plan or {}).get("bandwidth_preset") or "normal",
        "name": desired_policy.get("bandwidth_name") or (live_plan or {}).get("bandwidth_name") or "Normal",
        "upload": desired_policy.get("bandwidth_upload") or (live_plan or {}).get("bandwidth_upload") or "Unlimited",
        "download": desired_policy.get("bandwidth_download") or (live_plan or {}).get("bandwidth_download") or "Unlimited",
        "live_active": (live_plan or {}).get("live_bandwidth_active"),
        "live_limit": (live_plan or {}).get("live_bandwidth_limit"),
        "suspended": bool((live_plan or {}).get("bandwidth_suspended")),
        "suspension_reason": (live_plan or {}).get("bandwidth_suspension_reason"),
        "drift": bool((live_plan or {}).get("bandwidth_drift")),
    }

    focus_row = next((row for row in service_rows if row["focus"]), None)
    if focus_row:
        if focus_row["desired"] == "BLOCK" and focus_row["live"] == "BLOCK":
            headline = f"{focus_row['name']} is BLOCKED by {focus_row['source']}; live RouterOS matches."
        elif focus_row["desired"] == "BLOCK REQUESTED":
            headline = f"{focus_row['name']} is requested BLOCKED, but no trusted RouterOS enforcement contract is active."
        elif focus_row["drift"]:
            headline = f"{focus_row['name']} policy is out of sync with RouterOS."
        else:
            headline = f"{focus_row['name']} is {focus_row['desired']} by current service policy."
    elif router_error or not live_plan:
        headline = f"ZEN desires {desired_mode.upper()} from {desired_policy.get('mode_source') or 'default'}; live RouterOS state is unavailable."
    elif global_mode != "normal" and _MODE_RANK.get(global_mode, -1) >= _MODE_RANK.get(live_mode, -1):
        headline = f"Network mode is {effective_now.upper()} because household global mode is {global_mode.upper()}."
    elif temporary_access.get("active"):
        headline = f"Device mode is temporarily NORMAL in RouterOS; global and service restrictions still apply."
    elif live_plan.get("mode_drift"):
        headline = f"RouterOS is {live_mode.upper()} but ZEN currently desires {desired_mode.upper()} from {desired_policy.get('mode_source') or 'default'}."
    else:
        headline = f"Device mode is {effective_now.upper()} now; RouterOS device state matches {desired_policy.get('mode_source') or 'the effective policy'}."

    limitations = []
    if router_error:
        limitations.append(f"Live RouterOS evidence unavailable: {router_error}")
    for warning in evidence_warnings or ():
        if warning:
            limitations.append(f"Partial live-evidence warning: {warning}")
    if unsupported_requests:
        limitations.append(
            "Reporting-only/custom policy requests without a trusted RouterOS contract are shown as requested, not as enforced."
        )
    if quota.get("configured") and not quota.get("available"):
        limitations.append("Quota telemetry is unavailable or disabled, so quota enforcement is fail-open rather than inferred.")
    limitations.append("Service decisions describe ZEN/RouterOS policy state; they are not proof of foreground application use or browser history.")

    return {
        "schema_version": "zen_policy_explanation_v1",
        "device": {
            "ip": address,
            "name": device_name or device_config.get("alias") or address,
            "profile": profile.get("name") if profile else "Unassigned",
            "category": device_config.get("category") or "other",
        },
        "policy_at": desired_policy.get("policy_at"),
        "desired_contract": policy_parity_contract(desired_policy),
        "timezone": desired_policy.get("policy_timezone"),
        "summary": {
            "headline": headline,
            "desired_mode": desired_mode,
            "base_mode": base_mode,
            "mode_source": desired_policy.get("mode_source") or "default",
            "live_mode": live_mode,
            "global_mode": global_mode,
            "effective_now": effective_now,
            "sync_status": (live_plan or {}).get("status") or "unavailable",
            "temporary": bool(temporary_access.get("active")),
            "blocked_services": len([row for row in service_rows if row["desired_blocked"]]),
            "service_drift": len([row for row in service_rows if row["drift"]]),
            "conflicts": len(desired_policy.get("conflicts") or []),
        },
        "mode_chain": mode_chain,
        "services": service_rows,
        "focus_service": focus_row,
        "bandwidth": bandwidth,
        "quota": quota,
        "next_changes": next_changes,
        "conflicts": list(desired_policy.get("conflicts") or []),
        "planned_actions": [
            {
                "kind": str(action.get("kind") or "change"),
                "supported": bool(action.get("supported", True)),
                "summary": (
                    f"Device mode {str(action.get('from') or '?').upper()} → {str(action.get('to') or '?').upper()}"
                    if action.get("kind") == "mode"
                    else f"{_service_name(action.get('service'), definitions)} {str(action.get('from') or '?').upper()} → {str(action.get('to') or '?').upper()}"
                    if action.get("kind") == "service"
                    else f"Bandwidth {action.get('from') or 'unlimited'} → {action.get('to') or 'unlimited'}"
                    if action.get("kind") == "bandwidth"
                    else f"{action.get('value') or 'Service'} has no supported RouterOS enforcement contract"
                ),
            }
            for action in ((live_plan or {}).get("planned_actions") or [])
        ],
        "live_reason": (live_plan or {}).get("reason"),
        "limitations": limitations,
        "links": {
            "device": f"/?focus=device:{address}#devices/managed",
            "assignment": f"/?focus=assignment:{address}#policies/assignments",
            "schedules": "/#schedules/planner",
            "activity": f"/activity/device/{address}",
            "history": f"/activity/analytics?period=7d&client_ip={address}",
        },
    }
