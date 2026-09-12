"""Static policy quality analysis for ZEN Control.

This module does not resolve live policy and never talks to RouterOS.  It inspects
saved configuration for contradictions, precedence shadows, redundant policy and
orphaned/unused objects so operators can understand configuration quality without
creating a second policy engine.
"""

from __future__ import annotations

from collections import Counter
import re
from dataclasses import dataclass

CATEGORY_ORDER = {
    "conflict": 0,
    "warning": 1,
    "shadow": 2,
    "redundant": 3,
    "unused": 4,
}
SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}


@dataclass(frozen=True)
class _Target:
    kind: str
    value: str


def _target_specificity(kind: str) -> int:
    return {"all": 1, "profile": 2, "device": 3}.get(str(kind or ""), 0)


def _device_map(devices):
    if isinstance(devices, dict):
        return {str(key): dict(value or {}) for key, value in devices.items()}
    result = {}
    for item in devices or ():
        item = dict(item or {})
        ip = str(item.get("ip") or "")
        if ip:
            result[ip] = item
    return result


def _profile_map(profiles):
    return {str(item.get("id")): dict(item) for item in (profiles or ()) if item.get("id") is not None}


def _service_map(services):
    return {str(item.get("key") or "").lower(): dict(item) for item in (services or ()) if item.get("key")}



def _service_schedule_reference(item):
    raw = str(item.get("action_value") or "").strip().lower()
    if ":" not in raw:
        return "", ""
    key, state = [part.strip() for part in raw.split(":", 1)]
    state = {
        "block": "block", "blocked": "block", "deny": "block",
        "allow": "allow", "allowed": "allow",
    }.get(state, "")
    return key, state


def _schedule_template_findings(schedule_templates):
    findings = []
    valid_days = {"mon", "tue", "wed", "thu", "fri", "sat", "sun"}
    for template in schedule_templates or ():
        template = dict(template or {})
        name = str(template.get("name") or f"Template #{template.get('id')}")
        link = f"/?view=schedules&section=templates&focus=schedule-template:{template.get('id')}#schedules/templates"
        slots = {}
        for index, raw_entry in enumerate(template.get("entries") or (), 1):
            if not isinstance(raw_entry, dict):
                findings.append(_finding(
                    "conflict", "Schedule template contains invalid stored policy data",
                    f"{name} contains an entry that is not a valid schedule object. The template cannot be trusted for deterministic policy resolution.",
                    scope="Schedule templates", link=link, evidence=[f"Entry {index}"],
                ))
                continue
            entry = dict(raw_entry)
            clock_time = str(entry.get("time") or "").strip()
            mode = str(entry.get("mode") or "").strip().lower()
            days = [str(day).strip().lower() for day in (entry.get("days") or ())]
            invalid = (
                not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", clock_time)
                or mode not in {"normal", "slow", "blocked"}
                or not days
                or any(day not in valid_days for day in days)
            )
            if invalid:
                findings.append(_finding(
                    "conflict", "Schedule template contains invalid stored policy data",
                    f"{name} contains an invalid time, day or mode. A live date exception using it could fail deterministic policy resolution.",
                    scope="Schedule templates", link=link, evidence=[f"Entry {index}: {clock_time or 'no time'} · {mode or 'no mode'}"],
                ))
                continue
            for day in sorted(set(days)):
                slots.setdefault((day, clock_time), []).append((mode, index))

        for (day, clock_time), values in sorted(slots.items()):
            modes = sorted({mode for mode, _ in values})
            evidence = [
                f"{day} {clock_time}: " + ", ".join(f"entry {index} → {mode}" for mode, index in values)
            ]
            if len(modes) > 1:
                findings.append(_finding(
                    "conflict", "Schedule template has contradictory same-time modes",
                    f"{name} defines more than one mode for the same local weekday and time. The live resolver refuses this ambiguity rather than guessing.",
                    scope="Schedule templates", link=link, evidence=evidence,
                ))
            elif len(values) > 1:
                findings.append(_finding(
                    "redundant", "Schedule template duplicates a same-time mode",
                    f"{name} repeats the same mode for the same local weekday and time. The result is deterministic but the duplicate adds configuration noise.",
                    scope="Schedule templates", link=link, evidence=evidence,
                ))
    return findings


def _targets_overlap(a, b, devices):
    a = _Target(str(a.get("target_type") or ""), str(a.get("target_value") or ""))
    b = _Target(str(b.get("target_type") or ""), str(b.get("target_value") or ""))
    if a.kind == "all" or b.kind == "all":
        return True
    if a.kind == b.kind:
        return a.value == b.value
    # profile/device overlap only when the managed device is currently assigned
    # to that profile. This is configuration evidence, not a runtime prediction.
    if {a.kind, b.kind} == {"profile", "device"}:
        profile = a if a.kind == "profile" else b
        device = b if b.kind == "device" else a
        cfg = devices.get(device.value) or {}
        return str(cfg.get("profile_id") or "") == profile.value
    return False


def _same_schedule_dimension(a, b):
    if a.get("action_type") != b.get("action_type"):
        return False
    if a.get("action_type") == "service":
        return str(a.get("action_service") or "") == str(b.get("action_service") or "")
    return True


def _schedule_value(item):
    if item.get("action_type") == "service":
        return str(item.get("action_state") or item.get("action_value") or "")
    return str(item.get("action_value") or "")


def _finding(category, title, detail, *, scope="", link="", evidence=None, severity=None):
    if severity is None:
        severity = "critical" if category == "conflict" else "warning" if category == "warning" else "info"
    return {
        "category": category,
        "severity": severity,
        "title": title,
        "detail": detail,
        "scope": scope,
        "link": link,
        "evidence": list(evidence or ()),
    }


def _schedule_findings(schedules, profiles, devices, valid_policy_keys):
    findings = []
    enabled = [dict(item) for item in (schedules or ()) if item.get("enabled", True)]
    # Orphaned/malformed targets and service references are reported but are
    # deliberately excluded from pairwise precedence claims: an object that
    # cannot resolve cannot truthfully shadow a live target.
    for plan in enabled:
        plan["_quality_comparable"] = True
        target_type = str(plan.get("target_type") or "")
        target_value = str(plan.get("target_value") or "")
        link = f"/?view=schedules&section=planner&focus=schedule:{plan.get('id')}#schedules/planner"
        if target_type == "profile" and target_value not in profiles:
            findings.append(_finding(
                "warning",
                "Schedule targets a missing profile",
                f"{plan.get('label') or 'Unnamed schedule'} still targets profile #{target_value}, so it cannot match any current managed-device profile assignment.",
                scope="Schedules", link=link,
                evidence=[f"{plan.get('clock_time')} · {', '.join(plan.get('days') or [])}"],
            ))
            plan["_quality_comparable"] = False
        elif target_type == "device" and target_value not in devices:
            findings.append(_finding(
                "unused",
                "Schedule targets an unmanaged device",
                f"{plan.get('label') or 'Unnamed schedule'} targets {target_value}, which is not currently in ZEN's managed-device policy table.",
                scope="Schedules", link=link,
                evidence=[f"{plan.get('clock_time')} · {', '.join(plan.get('days') or [])}"],
            ))
            plan["_quality_comparable"] = False
        elif target_type not in {"all", "profile", "device"}:
            findings.append(_finding(
                "conflict", "Schedule has an invalid target",
                f"{plan.get('label') or 'Unnamed schedule'} contains an unsupported target type and cannot be resolved safely.",
                scope="Schedules", link=link, evidence=[target_type or "missing target type"],
            ))
            plan["_quality_comparable"] = False

        action_type = str(plan.get("action_type") or "")
        if action_type == "service":
            service_key, state = _service_schedule_reference(plan)
            if not service_key or not state or service_key not in valid_policy_keys:
                findings.append(_finding(
                    "conflict", "Service schedule references an invalid or missing policy service",
                    f"{plan.get('label') or 'Unnamed schedule'} cannot resolve its service action against the current concrete-service and aggregate-group catalogue.",
                    scope="Schedules", link=link, evidence=[str(plan.get("action_value") or "missing service action")],
                ))
                plan["_quality_comparable"] = False
        elif action_type == "mode":
            if str(plan.get("action_value") or "").lower() not in {"normal", "slow", "blocked"}:
                findings.append(_finding(
                    "conflict", "Mode schedule contains an invalid policy mode",
                    f"{plan.get('label') or 'Unnamed schedule'} cannot resolve its stored mode safely.",
                    scope="Schedules", link=link, evidence=[str(plan.get("action_value") or "missing mode")],
                ))
                plan["_quality_comparable"] = False
        else:
            findings.append(_finding(
                "conflict", "Schedule has an unsupported action type",
                f"{plan.get('label') or 'Unnamed schedule'} contains an action type the live resolver cannot execute.",
                scope="Schedules", link=link, evidence=[action_type or "missing action type"],
            ))
            plan["_quality_comparable"] = False

    comparable = [plan for plan in enabled if plan.get("_quality_comparable")]
    for index, a in enumerate(comparable):
        for b in comparable[index + 1:]:
            if a.get("clock_time") != b.get("clock_time"):
                continue
            overlap_days = sorted(set(a.get("days") or ()) & set(b.get("days") or ()))
            if not overlap_days or not _same_schedule_dimension(a, b):
                continue
            if not _targets_overlap(a, b, devices):
                continue
            a_value = _schedule_value(a)
            b_value = _schedule_value(b)
            a_spec = _target_specificity(a.get("target_type"))
            b_spec = _target_specificity(b.get("target_type"))
            scope = "Schedules"
            link = "/?view=schedules&section=planner#schedules/planner"
            evidence = [
                f"{a.get('label')} → {a_value}",
                f"{b.get('label')} → {b_value}",
                f"{a.get('clock_time')} · {', '.join(overlap_days)}",
            ]
            if a_spec == b_spec:
                if a_value != b_value:
                    findings.append(_finding(
                        "conflict",
                        "Ambiguous schedules have equal precedence",
                        "Two enabled schedules can apply at the same time to the same policy dimension with contradictory values. The resolver will refuse an ambiguous effective policy rather than guess.",
                        scope=scope,
                        link=link,
                        evidence=evidence,
                    ))
                else:
                    findings.append(_finding(
                        "redundant",
                        "Duplicate schedule effect",
                        "Two enabled schedules have the same target precedence, time, policy dimension and resulting value. Keeping both adds configuration noise without changing the result.",
                        scope=scope,
                        link=link,
                        evidence=evidence,
                    ))
                continue

            higher, lower = (a, b) if a_spec > b_spec else (b, a)
            higher_value, lower_value = _schedule_value(higher), _schedule_value(lower)
            if higher_value == lower_value:
                category = "redundant"
                title = "More-specific schedule duplicates a broader schedule"
                detail = (
                    f"{higher.get('label')} has higher target precedence than {lower.get('label')} at the same time, "
                    "but both produce the same value for the overlapping target."
                )
            else:
                category = "shadow"
                title = "More-specific schedule overrides a broader schedule"
                detail = (
                    f"{higher.get('label')} wins over {lower.get('label')} for the overlapping target because "
                    "device/profile specificity is higher. This is deterministic, but worth reviewing if the override is not intentional."
                )
            findings.append(_finding(category, title, detail, scope=scope, link=link, evidence=evidence))
    return findings


def _exception_findings(exceptions, profiles, devices):
    findings = []
    items = [dict(item) for item in (exceptions or ())]
    for item in items:
        item["_quality_comparable"] = True
        target_type = str(item.get("target_type") or "")
        target_value = str(item.get("target_value") or "")
        if target_type == "profile" and target_value not in profiles:
            findings.append(_finding(
                "warning", "Date exception targets a missing profile",
                f"{item.get('label') or 'Unnamed exception'} references profile #{target_value}, which no longer exists.",
                scope="Date exceptions", link=f"/?view=schedules&section=exceptions&focus=exception:{item.get('id')}#schedules/exceptions",
            ))
            item["_quality_comparable"] = False
        elif target_type == "device" and target_value not in devices:
            findings.append(_finding(
                "unused", "Date exception targets an unmanaged device",
                f"{item.get('label') or 'Unnamed exception'} targets {target_value}, which is not currently managed by ZEN.",
                scope="Date exceptions", link=f"/?view=schedules&section=exceptions&focus=exception:{item.get('id')}#schedules/exceptions",
            ))
            item["_quality_comparable"] = False
        elif target_type not in {"all", "profile", "device"}:
            findings.append(_finding(
                "conflict", "Date exception has an invalid target",
                f"{item.get('label') or 'Unnamed exception'} contains a target type the live resolver cannot match safely.",
                scope="Date exceptions", link=f"/?view=schedules&section=exceptions&focus=exception:{item.get('id')}#schedules/exceptions",
            ))
            item["_quality_comparable"] = False
        if str(item.get("mode") or "") == "template" and not item.get("template_name"):
            findings.append(_finding(
                "conflict", "Date exception references a missing template",
                f"{item.get('label') or 'Unnamed exception'} is configured for template mode but its template can no longer be resolved.",
                scope="Date exceptions", link=f"/?view=schedules&section=exceptions&focus=exception:{item.get('id')}#schedules/exceptions",
            ))
            item["_quality_comparable"] = False

    comparable = [item for item in items if item.get("_quality_comparable")]
    for index, a in enumerate(comparable):
        for b in comparable[index + 1:]:
            if a.get("end_date") < b.get("start_date") or b.get("end_date") < a.get("start_date"):
                continue
            if not _targets_overlap(a, b, devices):
                continue
            a_spec = _target_specificity(a.get("target_type"))
            b_spec = _target_specificity(b.get("target_type"))
            a_value = (a.get("mode"), a.get("template_id"))
            b_value = (b.get("mode"), b.get("template_id"))
            evidence = [
                f"{a.get('label')} · {a.get('start_date')} → {a.get('end_date')}",
                f"{b.get('label')} · {b.get('start_date')} → {b.get('end_date')}",
            ]
            if a_spec == b_spec:
                if a_value != b_value:
                    findings.append(_finding(
                        "conflict", "Overlapping date exceptions have equal precedence",
                        "Two date exceptions can apply to the same target and date with different outcomes. ZEN will fail closed rather than select one arbitrarily.",
                        scope="Date exceptions", link="/?view=schedules&section=exceptions#schedules/exceptions", evidence=evidence,
                    ))
                else:
                    findings.append(_finding(
                        "redundant", "Overlapping date exceptions duplicate the same outcome",
                        "These exceptions overlap for the same target and produce the same outcome, so one may be unnecessary.",
                        scope="Date exceptions", link="/?view=schedules&section=exceptions#schedules/exceptions", evidence=evidence,
                    ))
            else:
                higher, lower = (a, b) if a_spec > b_spec else (b, a)
                category = "shadow" if a_value != b_value else "redundant"
                title = (
                    "More-specific date exception overrides a broader exception"
                    if category == "shadow" else
                    "More-specific date exception duplicates a broader exception"
                )
                findings.append(_finding(
                    category, title,
                    f"{higher.get('label')} has higher target specificity than {lower.get('label')} during the overlapping date range.",
                    scope="Date exceptions", link="/?view=schedules&section=exceptions#schedules/exceptions", evidence=evidence,
                ))
    return findings


def build_policy_quality_report(*, profiles, devices, schedules, date_exceptions,
                                service_groups, services, settings,
                                policy_groups, schedule_templates=None):
    """Return the stable ``zen_policy_quality_v1`` configuration report."""
    profiles_by_id = _profile_map(profiles)
    devices_by_ip = _device_map(devices)
    services_by_key = _service_map(services)
    settings = dict(settings or {})
    policy_groups = {
        str(key).strip().lower(): dict(value or {})
        for key, value in (policy_groups or {}).items()
        if str(key).strip()
    }
    valid_policy_keys = set(services_by_key) | set(policy_groups)
    findings = []

    assigned = Counter(str(cfg.get("profile_id")) for cfg in devices_by_ip.values() if cfg.get("profile_id"))

    # Profile/device precedence and profile-level redundancy.
    quota_engine_enabled = str(settings.get("quota_engine_enabled", "0")) == "1"
    for profile_id, profile in profiles_by_id.items():
        name = str(profile.get("name") or f"Profile #{profile_id}")
        profile_link = f"/?view=policies&section=profiles&focus=profile:{profile_id}#policies/profiles"
        if not assigned.get(profile_id):
            findings.append(_finding(
                "unused", "Profile is not assigned to any managed device",
                f"{name} currently has no device assignments. Keeping it may be intentional as a template-like profile, but it has no current device effect.",
                scope=name, link=profile_link,
            ))

        blocked = [str(value).strip().lower() for value in (profile.get("blocked_services") or ())]
        blocked_set = set(blocked)
        missing_blocks = sorted(blocked_set - valid_policy_keys)
        if missing_blocks:
            findings.append(_finding(
                "conflict", "Profile references missing policy services",
                f"{name} contains blocked-service keys that no longer exist. The saved intent cannot be resolved completely against the current policy catalogue.",
                scope=name, link=profile_link,
                evidence=["Missing: " + ", ".join(missing_blocks)],
            ))

        quota_keys = {
            str(value).strip().lower()
            for value in (profile.get("service_quotas") or {}).keys()
            if str(value).strip()
        }
        missing_quota_keys = sorted(quota_keys - valid_policy_keys)
        if missing_quota_keys:
            findings.append(_finding(
                "conflict", "Profile quota references missing policy services",
                f"{name} contains service/group quota keys that no longer exist. Quota intent cannot be interpreted reliably until the references are corrected.",
                scope=name, link=profile_link,
                evidence=["Missing: " + ", ".join(missing_quota_keys)],
            ))

        for group_key, group in policy_groups.items():
            if group_key not in blocked_set:
                continue
            duplicate_members = sorted(blocked_set & set(group.get("members") or ()))
            if duplicate_members:
                findings.append(_finding(
                    "redundant", "Profile blocks an aggregate group and explicit member services",
                    f"{name} blocks {group.get('name') or group_key}; explicit member blocks are redundant while the aggregate group remains selected.",
                    scope=name, link=profile_link,
                    evidence=["Explicit duplicates: " + ", ".join(duplicate_members)],
                ))

        for service_key in sorted(blocked_set - set(policy_groups)):
            service = services_by_key.get(service_key)
            if service and not service.get("builtin") and not service.get("enforcement_approved"):
                findings.append(_finding(
                    "warning", "Profile requests a reporting-only custom service block",
                    f"{name} requests {service.get('name') or service_key}, but that custom service has no approved RouterOS enforcement contract. The intent remains visible but is not safely enforceable.",
                    scope=name,
                    link=f"/?view=policies&section=services&focus=service:{service_key}#policies/services",
                ))

        quota_configured = bool(profile.get("daily_quota_mb") or profile.get("service_quotas"))
        if quota_configured and not quota_engine_enabled:
            findings.append(_finding(
                "warning", "Profile quotas are configured while the quota engine is disabled",
                f"{name} contains quota policy, but Settings → Policy defaults currently has the daily quota engine disabled.",
                scope=name, link="/?view=settings&section=policy#settings/policy",
            ))

        if str(profile.get("desired_mode") or "normal") != "normal" and str(profile.get("bandwidth_preset") or "normal") != "normal":
            findings.append(_finding(
                "shadow", "Profile bandwidth is suspended by its base mode",
                f"{name} uses {str(profile.get('desired_mode')).upper()} as its base mode and also configures a non-normal bandwidth preset. ZEN intentionally suspends the profile queue while the device/global mode is not NORMAL.",
                scope=name, link=profile_link,
            ))

    for ip, cfg in devices_by_ip.items():
        override = str(cfg.get("mode_override") or "inherit")
        profile_id = str(cfg.get("profile_id") or "")
        if override != "inherit" and profile_id and profile_id in profiles_by_id:
            profile = profiles_by_id[profile_id]
            profile_mode = str(profile.get("desired_mode") or "normal")
            same_value = override == profile_mode
            findings.append(_finding(
                "redundant" if same_value else "shadow",
                "Device mode override duplicates its profile mode" if same_value else "Device mode override shadows its profile mode",
                (
                    f"{cfg.get('alias') or ip} explicitly selects {override.upper()}, which is already the mode supplied by profile {profile.get('name')}. The override adds configuration noise without changing the current result."
                    if same_value else
                    f"{cfg.get('alias') or ip} uses explicit {override.upper()} mode, so profile {profile.get('name')} does not currently decide the base device mode."
                ),
                scope=cfg.get("alias") or ip,
                link=f"/?view=policies&section=assignments&focus=assignment:{ip}#policies/assignments",
            ))
        if profile_id and profile_id not in profiles_by_id:
            findings.append(_finding(
                "conflict", "Managed device references a missing profile",
                f"{cfg.get('alias') or ip} still references profile #{profile_id}. The policy relation is malformed and should be corrected before relying on inherited policy.",
                scope=cfg.get("alias") or ip,
                link=f"/?view=policies&section=assignments&focus=assignment:{ip}#policies/assignments",
            ))

    findings.extend(_schedule_findings(
        schedules, profiles_by_id, devices_by_ip, valid_policy_keys
    ))
    findings.extend(_exception_findings(date_exceptions, profiles_by_id, devices_by_ip))
    findings.extend(_schedule_template_findings(schedule_templates))

    # Aggregate policy-group integrity. Groups are live policy objects, so an
    # empty/stale membership is more significant than an authoring collection.
    valid_service_keys = set(services_by_key)
    for group_key, group in policy_groups.items():
        members = [str(item).strip().lower() for item in (group.get("members") or ()) if str(item).strip()]
        group_link = f"/?view=policies&section=tools&focus=policy-group:{group_key}#policies/tools"
        if not members:
            findings.append(_finding(
                "warning", "Aggregate policy group has no concrete members",
                f"{group.get('name') or group_key} is a live policy key but currently expands to no concrete services.",
                scope="Aggregate policy groups", link=group_link,
            ))
        stale = sorted(set(members) - valid_service_keys)
        if stale:
            findings.append(_finding(
                "conflict", "Aggregate policy group contains missing services",
                f"{group.get('name') or group_key} references service keys that no longer exist, so its intended expansion is incomplete.",
                scope="Aggregate policy groups", link=group_link,
                evidence=["Missing: " + ", ".join(stale)],
            ))
        reporting = sorted(
            key for key in members
            if key in services_by_key
            and not services_by_key[key].get("builtin")
            and not services_by_key[key].get("enforcement_approved")
        )
        if reporting:
            findings.append(_finding(
                "warning", "Aggregate policy group includes reporting-only services",
                f"{group.get('name') or group_key} includes custom services without approved RouterOS enforcement. The group remains valid policy intent, but those members cannot currently be enforced safely.",
                scope="Aggregate policy groups", link=group_link,
                evidence=["Reporting-only: " + ", ".join(reporting)],
            ))

    valid_service_keys = set(services_by_key) | set(policy_groups)
    for group in service_groups or ():
        group = dict(group or {})
        name = str(group.get("name") or f"Collection #{group.get('id')}")
        members = [str(item).strip().lower() for item in (group.get("services") or ()) if str(item).strip()]
        link = f"/?view=policies&section=tools&focus=collection:{group.get('id')}#policies/tools"
        if not members:
            findings.append(_finding(
                "unused", "Reusable service collection is empty",
                f"{name} contains no services and cannot currently change a profile.",
                scope="Service collections", link=link,
            ))
        stale = sorted(set(members) - valid_service_keys)
        if stale:
            findings.append(_finding(
                "warning", "Reusable service collection contains missing services",
                f"{name} contains service keys that no longer exist in the catalogue. Applying the collection cannot reproduce the original intended set reliably.",
                scope="Service collections", link=link,
                evidence=["Missing: " + ", ".join(stale)],
            ))

    # Stable ordering and deterministic ids are useful to UI filters and tests.
    findings.sort(key=lambda item: (
        SEVERITY_ORDER.get(item["severity"], 9),
        CATEGORY_ORDER.get(item["category"], 9),
        item["title"].lower(), item.get("scope", "").lower(),
    ))
    for idx, finding in enumerate(findings, 1):
        finding["id"] = f"PQ-{idx:03d}"

    category_counts = Counter(item["category"] for item in findings)
    severity_counts = Counter(item["severity"] for item in findings)
    if severity_counts["critical"]:
        state = "conflict"
    elif findings:
        state = "review"
    else:
        state = "clean"

    return {
        "schema_version": "zen_policy_quality_v1",
        "state": state,
        "counts": {
            "total": len(findings),
            "conflict": category_counts["conflict"],
            "warning": category_counts["warning"],
            "shadow": category_counts["shadow"],
            "redundant": category_counts["redundant"],
            "unused": category_counts["unused"],
            "critical": severity_counts["critical"],
        },
        "inventory": {
            "profiles": len(profiles_by_id),
            "managed_devices": len(devices_by_ip),
            "schedules": len(list(schedules or ())),
            "schedule_templates": len(list(schedule_templates or ())),
            "date_exceptions": len(list(date_exceptions or ())),
            "service_collections": len(list(service_groups or ())),
            "aggregate_policy_groups": len(policy_groups),
        },
        "findings": findings,
        "evidence_note": (
            "Policy Quality is static configuration analysis. It highlights deterministic precedence, "
            "contradictions, redundancy and unused objects; it does not replace effective-policy resolution, "
            "read RouterOS, score child behaviour, or change configuration."
        ),
    }
