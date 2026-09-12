from app.bandwidth import BandwidthRateError, build_max_limit, limits_equal
from app.service_catalog import SERVICE_ENFORCEMENT


VALID_MODES = {"normal", "slow", "blocked"}


class PolicyPlanError(ValueError):
    pass


def build_device_policy_plan(
    address: str,
    desired_policy: dict,
    live_enforcement: dict,
    temporary_access: dict | None = None,
    live_services: dict | None = None,
    live_bandwidth: dict | None = None,
    global_mode: str = "normal",
    service_catalog: dict | None = None,
) -> dict:
    """Compare effective desired policy with live RouterOS state."""
    service_catalog = service_catalog or SERVICE_ENFORCEMENT
    supported_service_keys = frozenset(service_catalog)
    temporary_access = temporary_access or {"active": False}
    live_services = live_services or {
        "blocked_services": [],
        "unavailable_services": [],
        "services": {},
    }
    live_bandwidth = live_bandwidth or {
        "active": False,
        "valid": True,
        "max_limit": None,
        "error": None,
    }

    desired_mode = str(desired_policy.get("mode", "normal")).strip().lower()
    if desired_mode not in VALID_MODES:
        raise PolicyPlanError(
            f"Invalid desired mode '{desired_mode}' for {address}"
        )

    live_mode = str(live_enforcement.get("mode", "invalid")).strip().lower()
    global_mode = str(global_mode or "normal").strip().lower()
    if global_mode not in VALID_MODES:
        raise PolicyPlanError(
            f"Invalid global RouterOS mode '{global_mode}' while planning {address}"
        )
    mode_source = str(desired_policy.get("mode_source") or "default")

    bandwidth_preset = str(
        desired_policy.get("bandwidth_preset") or "normal"
    ).strip().lower()
    bandwidth_name = str(
        desired_policy.get("bandwidth_name") or bandwidth_preset
    )
    bandwidth_upload = str(
        desired_policy.get("bandwidth_upload") or "Unlimited"
    )
    bandwidth_download = str(
        desired_policy.get("bandwidth_download") or "Unlimited"
    )

    desired_bandwidth_limit = None
    if bandwidth_preset != "normal":
        try:
            desired_bandwidth_limit = build_max_limit(
                bandwidth_upload,
                bandwidth_download,
            )
        except BandwidthRateError as exc:
            raise PolicyPlanError(
                f"Invalid bandwidth preset '{bandwidth_preset}' for {address}: {exc}"
            ) from exc

    # Profile bandwidth and the explicit SLOW mode both use simple queues. To
    # avoid two queues competing for the same target, profile bandwidth is live
    # only while the desired mode is NORMAL. SLOW/BLOCKED suspend it and expect
    # the MC-BW queue to be absent.
    bandwidth_suspension_reason = None
    if bandwidth_preset != "normal":
        if global_mode != "normal":
            bandwidth_suspension_reason = f"global {global_mode.upper()}"
        elif desired_mode != "normal":
            bandwidth_suspension_reason = f"device {desired_mode.upper()}"

    bandwidth_suspended = bandwidth_suspension_reason is not None
    bandwidth_expected_active = (
        bandwidth_preset != "normal"
        and desired_mode == "normal"
        and global_mode == "normal"
    )
    live_bandwidth_active = bool(live_bandwidth.get("active", False))
    live_bandwidth_valid = bool(live_bandwidth.get("valid", True))
    live_bandwidth_limit = live_bandwidth.get("max_limit")
    live_bandwidth_error = live_bandwidth.get("error")

    if bandwidth_expected_active:
        bandwidth_drift = (
            not live_bandwidth_active
            or not live_bandwidth_valid
            or not limits_equal(
                live_bandwidth_limit,
                desired_bandwidth_limit,
            )
        )
    else:
        bandwidth_drift = live_bandwidth_active

    blocked_services = sorted(
        {
            str(value).strip().lower()
            for value in (desired_policy.get("blocked_services") or [])
        }
    )
    desired_supported = sorted(set(blocked_services) & supported_service_keys)
    unsupported_blocked = sorted(
        set(blocked_services) - supported_service_keys
        | {
            str(value).strip().lower()
            for value in (desired_policy.get("unsupported_policy_keys") or [])
            if str(value).strip()
        }
    )
    live_supported = sorted(
        set(live_services.get("blocked_services") or [])
        & supported_service_keys
    )
    conflicts = list(desired_policy.get("conflicts") or [])

    service_states = []
    unavailable_desired = []
    service_drift = False

    for service_key, service in service_catalog.items():
        live_state = (live_services.get("services") or {}).get(service_key, {})
        available = bool(live_state.get("available", True))
        desired_blocked = service_key in desired_supported
        live_blocked = bool(live_state.get("blocked", False))
        drift = available and desired_blocked != live_blocked

        if drift:
            service_drift = True
        if desired_blocked and not available:
            unavailable_desired.append(service_key)

        service_states.append(
            {
                "key": service_key,
                "name": service["name"],
                "available": available,
                "error": live_state.get("error"),
                "desired_blocked": desired_blocked,
                "live_blocked": live_blocked,
                "drift": drift,
                "source_list": service["source_list"],
                "classification": service.get("classification", "TLS/SNI"),
                "coverage_note": service.get("coverage_note", ""),
                "detector_lists": [
                    rule["detector_list"] for rule in service["rules"]
                ],
            }
        )

    desired_service_names = [
        state["name"] for state in service_states if state["desired_blocked"]
    ]

    common = {
        "address": address,
        "desired_mode": desired_mode,
        "live_mode": live_mode,
        "mode_source": mode_source,
        "global_mode": global_mode,
        "bandwidth_preset": bandwidth_preset,
        "bandwidth_name": bandwidth_name,
        "bandwidth_upload": bandwidth_upload,
        "bandwidth_download": bandwidth_download,
        "desired_bandwidth_limit": desired_bandwidth_limit,
        "bandwidth_expected_active": bandwidth_expected_active,
        "bandwidth_suspended": bandwidth_suspended,
        "bandwidth_suspension_reason": bandwidth_suspension_reason,
        "live_bandwidth_active": live_bandwidth_active,
        "live_bandwidth_valid": live_bandwidth_valid,
        "live_bandwidth_limit": live_bandwidth_limit,
        "live_bandwidth_error": live_bandwidth_error,
        "blocked_services": blocked_services,
        "requested_blocked_services": list(
            desired_policy.get("requested_blocked_services") or blocked_services
        ),
        "blocked_policy_groups": list(
            desired_policy.get("blocked_policy_groups") or []
        ),
        "policy_group_states": list(
            desired_policy.get("policy_group_states") or []
        ),
        "desired_supported_blocked_services": desired_supported,
        "desired_service_names": desired_service_names,
        "live_supported_blocked_services": live_supported,
        "unsupported_blocked_services": unsupported_blocked,
        "unavailable_desired_services": sorted(unavailable_desired),
        "service_states": service_states,
        "conflicts": conflicts,
        "base_mode": desired_policy.get("base_mode", desired_mode),
        "base_mode_source": desired_policy.get("base_mode_source", mode_source),
        "schedule_active": bool(desired_policy.get("schedule_active", False)),
        "schedule_reason": desired_policy.get("schedule_reason"),
        "scheduled_service_overrides": list(
            desired_policy.get("scheduled_service_overrides") or []
        ),
        "active_date_exception": desired_policy.get("active_date_exception"),
        "next_policy_action": desired_policy.get("next_policy_action"),
        "policy_timezone": desired_policy.get("policy_timezone"),
        "policy_at": desired_policy.get("policy_at"),
        "quota_state": desired_policy.get("quota_state") or {},
        "quota_active": bool(desired_policy.get("quota_active", False)),
    }

    if temporary_access.get("active"):
        restore_mode = str(
            temporary_access.get("restore_mode") or "unknown"
        ).upper()
        restore_time = (
            temporary_access.get("restore_time")
            or temporary_access.get("restore_at")
            or "scheduled expiry"
        )
        return {
            **common,
            "status": "temporary",
            "temporary_override": True,
            "mode_drift": False,
            "service_drift": False,
            "bandwidth_drift": False,
            "policy_actionable": False,
            "mode_actionable": False,
            "service_actionable": False,
            "bandwidth_actionable": False,
            "reason": (
                "Temporary NORMAL override is authoritative; "
                f"RouterOS will restore {restore_mode} at {restore_time}."
            ),
            "planned_actions": [],
        }

    mode_drift = desired_mode != live_mode
    planned_actions = []

    if mode_drift:
        planned_actions.append(
            {
                "kind": "mode",
                "from": live_mode,
                "to": desired_mode,
                "supported": True,
            }
        )

    for state in service_states:
        if state["drift"]:
            planned_actions.append(
                {
                    "kind": "service",
                    "service": state["key"],
                    "from": "blocked" if state["live_blocked"] else "allowed",
                    "to": "blocked" if state["desired_blocked"] else "allowed",
                    "supported": True,
                }
            )

    if bandwidth_drift:
        planned_actions.append(
            {
                "kind": "bandwidth",
                "preset": bandwidth_preset,
                "from": live_bandwidth_limit or "unlimited",
                "to": (
                    desired_bandwidth_limit
                    if bandwidth_expected_active
                    else "unlimited"
                ),
                "suspended": bandwidth_suspended,
                "supported": True,
            }
        )

    for service in unsupported_blocked:
        planned_actions.append(
            {
                "kind": "service_block",
                "value": service,
                "supported": False,
            }
        )

    drift_reasons = []
    if mode_drift:
        drift_reasons.append(
            f"mode {live_mode.upper()}→{desired_mode.upper()}"
        )
    if service_drift:
        drift_reasons.append("service membership")
    if bandwidth_drift:
        if bandwidth_expected_active:
            drift_reasons.append(
                f"bandwidth → {bandwidth_name} ({desired_bandwidth_limit})"
            )
        else:
            drift_reasons.append("remove stale profile bandwidth queue")

    if live_mode == "invalid":
        reason = (
            "RouterOS MC enforcement state is inconsistent; "
            f"effective policy requires {desired_mode.upper()}."
        )
    elif drift_reasons:
        reason = (
            f"{mode_source} differs from live RouterOS: "
            + "; ".join(drift_reasons)
            + "."
        )
    elif unavailable_desired:
        reason = (
            "Some requested service blocks have a RouterOS TLS/SNI "
            "contract problem and were not treated as safely enforceable."
        )
    elif unsupported_blocked:
        reason = (
            "All live RouterOS-backed controls match; one or more custom service "
            "definitions still lack a trustworthy enforcement contract."
        )
    elif bandwidth_suspended:
        reason = (
            f"RouterOS controls match. {bandwidth_name} bandwidth is suspended "
            f"by {bandwidth_suspension_reason}."
        )
    else:
        reason = (
            "RouterOS mode, bandwidth and RouterOS-backed services match the "
            f"effective policy from {mode_source}."
        )

    executable_drift = mode_drift or service_drift or bandwidth_drift
    if executable_drift:
        status = "drift"
    elif unavailable_desired or unsupported_blocked:
        status = "partial"
    else:
        status = "in_sync"

    return {
        **common,
        "status": status,
        "temporary_override": False,
        "mode_drift": mode_drift,
        "service_drift": service_drift,
        "bandwidth_drift": bandwidth_drift,
        "policy_actionable": executable_drift,
        "mode_actionable": mode_drift,
        "service_actionable": service_drift,
        "bandwidth_actionable": bandwidth_drift,
        "reason": reason,
        "planned_actions": planned_actions,
    }
