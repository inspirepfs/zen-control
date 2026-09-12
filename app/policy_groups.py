"""Logical aggregate policy groups built from concrete services.

Aggregate policy groups express household intent without pretending RouterOS can
classify a whole category directly. A group expands into explicit concrete
services that have their own enforcement contracts. The group itself never
becomes a firewall/address-list primitive.

``POLICY_GROUPS`` remains the product-default catalogue for compatibility and
fresh database seeding. Runtime policy resolution can receive an operator-
managed catalogue from :class:`PolicyStore`, which is the v0.35 source of truth.
"""

from app.service_catalog import SERVICE_ENFORCEMENT, SUPPORTED_SERVICE_KEYS


POLICY_GROUPS = {
    "gaming": {
        "key": "gaming",
        "name": "Gaming",
        "members": ("roblox", "steam", "xbox", "playstation"),
        "description": (
            "Aggregate policy for the concrete gaming services currently backed "
            "by RouterOS. It does not claim to block every game or gaming protocol."
        ),
        "builtin": True,
    },
    "social_media": {
        "key": "social_media",
        "name": "Social media",
        "members": ("tiktok", "discord"),
        "description": (
            "Conservative social/communications aggregate using the concrete "
            "TikTok and Discord contracts. Other social platforms can be added "
            "when they have trusted classifiers."
        ),
        "builtin": True,
    },
}

POLICY_GROUP_KEYS = frozenset(POLICY_GROUPS)


def normalized_group_catalog(catalog=None):
    source = catalog if catalog is not None else POLICY_GROUPS
    result = {}
    for raw_key, raw in (source or {}).items():
        key = str(raw_key or "").strip().lower()
        if not key:
            continue
        item = dict(raw or {})
        members = tuple(sorted({
            str(value or "").strip().lower()
            for value in item.get("members", ())
            if str(value or "").strip()
        }))
        result[key] = {
            **item,
            "key": key,
            "name": str(item.get("name") or key),
            "description": str(item.get("description") or ""),
            "members": members,
            "builtin": bool(item.get("builtin", False)),
        }
    return result


def group_name(key, catalog=None):
    groups = normalized_group_catalog(catalog)
    item = groups.get(str(key or "").strip().lower())
    return item["name"] if item else str(key or "")


def group_members(key, catalog=None):
    groups = normalized_group_catalog(catalog)
    item = groups.get(str(key or "").strip().lower())
    return tuple(item.get("members", ())) if item else ()


def expand_policy_keys(values, supported_service_keys=None, policy_groups=None):
    """Expand logical policy keys into concrete RouterOS-backed services.

    Unknown custom-service intent remains visible rather than being silently
    converted into authority. Group members without a supported enforcement
    contract are returned separately as ``unsupported_group_members``.
    """
    requested = {
        str(value).strip().lower()
        for value in (values or ())
        if str(value).strip()
    }
    supported = frozenset(supported_service_keys or SUPPORTED_SERVICE_KEYS)
    groups_catalog = normalized_group_catalog(policy_groups)
    group_keys = frozenset(groups_catalog)
    groups = sorted(requested & group_keys)
    effective = set(requested & supported)
    unsupported_group_members = set()
    for key in groups:
        for member in group_members(key, groups_catalog):
            if member in supported:
                effective.add(member)
            else:
                unsupported_group_members.add(member)
    unsupported = sorted(requested - supported - group_keys)
    return {
        "requested": sorted(requested),
        "groups": groups,
        "effective_services": sorted(effective),
        "unsupported": unsupported,
        "unsupported_group_members": sorted(unsupported_group_members),
    }


def policy_group_states(
    requested_groups,
    blocked_services,
    quota_active_groups=(),
    policy_groups=None,
    service_names=None,
):
    requested_groups = set(requested_groups or ())
    blocked_services = set(blocked_services or ())
    quota_active_groups = set(quota_active_groups or ())
    groups = normalized_group_catalog(policy_groups)
    names = dict(service_names or {})
    result = []
    for key, item in groups.items():
        members = list(item["members"])
        blocked_members = [member for member in members if member in blocked_services]
        result.append(
            {
                "key": key,
                "name": item["name"],
                "description": item["description"],
                "members": members,
                "member_names": [
                    names.get(member)
                    or SERVICE_ENFORCEMENT.get(member, {}).get("name")
                    or member
                    for member in members
                ],
                "requested": key in requested_groups,
                "quota_active": key in quota_active_groups,
                "blocked_members": blocked_members,
                "active": bool(blocked_members),
                "fully_blocked": bool(members) and len(blocked_members) == len(members),
                "builtin": bool(item.get("builtin", False)),
            }
        )
    return result
