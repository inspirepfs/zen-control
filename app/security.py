from __future__ import annotations

import ipaddress
import re
from typing import Iterable


MANAGED_LIST_PREFIXES = ("MC_Mode_", "MC_Block_")
MANAGED_QUEUE_PREFIXES = ("MC-SLOW-", "MC-BW-")
MANAGED_TEMP_PREFIXES = ("MC-TEMP-DEV-", "MC-TEMP-RESTORE-DEV-")


def rule_enabled(rule: dict) -> bool:
    return str(rule.get("disabled", "false")).lower() not in {"true", "yes", "1"}


def fasttrack_excludes_restricted(rule: dict, restricted_list: str = "Restricted_Devices") -> bool:
    """Return True only for the narrow FastTrack form we can prove safe.

    FastTrack is connection-wide, so a managed connection must be excluded in
    both directions. We therefore only accept a rule that explicitly excludes
    Restricted_Devices as both source and destination.
    """
    expected = f"!{restricted_list}"
    return (
        str(rule.get("src-address-list", "")) == expected
        and str(rule.get("dst-address-list", "")) == expected
    )


def queue_target_ipv4(target: str) -> str | None:
    """Extract a single /32 IPv4 target from an app-owned simple queue."""
    text = str(target or "").strip()
    if not text or "," in text:
        return None
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None
    if network.version != 4 or network.prefixlen != 32:
        return None
    return str(network.network_address)


def encoded_ipv4_from_name(name: str, prefixes: Iterable[str] = MANAGED_TEMP_PREFIXES) -> str | None:
    text = str(name or "")
    for prefix in prefixes:
        if not text.startswith(prefix):
            continue
        suffix = text[len(prefix):]
        if not re.fullmatch(r"\d{1,3}(?:-\d{1,3}){3}", suffix):
            return None
        candidate = suffix.replace("-", ".")
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            return None
    return None



def infer_global_mode(master_enabled: bool, slow_enabled: bool) -> tuple[str, bool]:
    """Return the effective global mode and whether the runtime state is valid.

    The MASTER drop rule is deliberately disabled in NORMAL and SLOW.  The
    global slow queue is enabled only in SLOW.  Both being enabled at once is
    an invalid authority state because BLOCKED and SLOW would be active
    simultaneously.
    """
    if master_enabled and slow_enabled:
        return "invalid", False
    if master_enabled:
        return "blocked", True
    if slow_enabled:
        return "slow", True
    return "normal", True


def chain_rules(rules: Iterable[dict], chain: str) -> list[dict]:
    """Return rules for one RouterOS filter chain while preserving API order.

    RouterOS permits the same comment text to exist in more than one chain.
    The default configuration commonly reuses established/related wording in
    INPUT and FORWARD.  Ordering checks must therefore be chain-local; comparing
    a FORWARD rule to an INPUT rule's list position is meaningless and can
    falsely close the enforcement gate.
    """
    wanted = str(chain or "").strip().lower()
    return [
        rule for rule in rules
        if str(rule.get("chain", "")).strip().lower() == wanted
    ]


def rule_comment_positions(rules: Iterable[dict], comments: Iterable[str]) -> tuple[dict[str, int], dict[str, int]]:
    """Return unique comment positions and duplicate counts for an ordered rule list."""
    ordered = list(rules)
    positions: dict[str, int] = {}
    duplicates: dict[str, int] = {}
    for comment in dict.fromkeys(comments):
        matches = [i for i, rule in enumerate(ordered) if rule.get("comment") == comment]
        if len(matches) == 1:
            positions[comment] = matches[0]
        elif len(matches) > 1:
            duplicates[comment] = len(matches)
    return positions, duplicates


def same_comment_other_chains(rules: Iterable[dict], comment: str, chain: str) -> list[str]:
    """List other chains that reuse ``comment`` for diagnostics only."""
    wanted = str(chain or "").strip().lower()
    found: list[str] = []
    for rule in rules:
        if rule.get("comment") != comment:
            continue
        candidate = str(rule.get("chain", "")).strip().lower()
        if candidate and candidate != wanted and candidate not in found:
            found.append(candidate)
    return found


def connection_states(rule: dict) -> set[str]:
    """Normalise RouterOS ``connection-state`` into a lowercase set.

    RouterOS/API representations are normally comma-separated strings, but
    treating the field structurally rather than by comment text makes the
    authority validator resilient to renamed/default-localised comments.
    """
    raw = rule.get("connection-state", "")
    if isinstance(raw, (list, tuple, set)):
        values = raw
    else:
        values = str(raw or "").split(",")
    return {str(value).strip().lower() for value in values if str(value).strip()}


def established_related_accept_candidates(
    rules: Iterable[dict],
    *,
    chain: str = "forward",
) -> list[tuple[int, dict]]:
    """Return active established+related ACCEPT anchors in chain-local order.

    The security boundary is behavioural, not a comment contract.  RouterOS
    defaults are commonly renamed, imported from older releases, or stripped
    of comments.  Any enabled FORWARD accept that includes both ``established``
    and ``related`` can permit packets past later managed policy, so the
    earliest such rule is the conservative ordering boundary.

    ``untracked`` is intentionally optional: configurations vary on whether it
    is included with established/related.
    """
    scoped = chain_rules(rules, chain)
    candidates: list[tuple[int, dict]] = []
    for index, rule in enumerate(scoped):
        if not rule_enabled(rule):
            continue
        if str(rule.get("action", "")).strip().lower() != "accept":
            continue
        states = connection_states(rule)
        if {"established", "related"}.issubset(states):
            candidates.append((index, rule))
    return candidates


def forward_authority_order(
    rules: list[dict],
    managed_comments: Iterable[str],
    established_comment: str,
    *,
    required_comments: Iterable[str] = (),
    chain: str = "forward",
) -> dict:
    """Evaluate managed authority ordering inside one RouterOS filter chain.

    Managed app-owned rules remain identified by exact comments because those
    comments are part of our static contract.  The general established/related
    ACCEPT boundary is discovered from rule *behaviour* (FORWARD + ACCEPT +
    established + related), not from the default MikroTik comment.

    A narrow legacy-comment fallback is retained only for incomplete/mock API
    rows that omit action/connection-state fields.  Real RouterOS rows with a
    renamed or commentless established/related rule are therefore still found
    structurally so renamed or commentless defaults are handled correctly.
    """
    scoped = chain_rules(rules, chain)
    managed_wanted = list(dict.fromkeys(managed_comments))
    positions, duplicates = rule_comment_positions(scoped, managed_wanted)

    legacy_positions, legacy_duplicates = rule_comment_positions(scoped, [established_comment])
    legacy_position = legacy_positions.get(established_comment)
    if legacy_position is not None:
        # Compatibility/diagnostic alias only; authority discovery below is
        # structural whenever the rule exposes enough RouterOS fields.
        positions[established_comment] = legacy_position
    if established_comment in legacy_duplicates:
        duplicates[established_comment] = legacy_duplicates[established_comment]

    missing_required = [comment for comment in required_comments if comment not in positions]

    candidates = established_related_accept_candidates(rules, chain=chain)
    anchor_source = "structural"
    if candidates:
        established_index, established_rule = candidates[0]
    elif legacy_position is not None:
        # Some unit fixtures and occasionally restricted API responses expose
        # only comment/chain fields.  If the canonical comment exists uniquely
        # in FORWARD, retain the historical anchor as a bounded fallback.
        established_index = legacy_position
        established_rule = scoped[legacy_position]
        candidates = [(legacy_position, established_rule)]
        anchor_source = "legacy-comment-fallback"
    else:
        established_index = None
        established_rule = None
        missing_required.append(established_comment)
        anchor_source = "missing"

    late: list[str] = []
    if established_index is not None:
        for comment in required_comments:
            index = positions.get(comment)
            if index is not None and index >= established_index:
                late.append(comment)

    legacy_other_chains = same_comment_other_chains(rules, established_comment, chain)

    ok = not missing_required and not duplicates and not late
    return {
        "ok": ok,
        "chain": chain,
        "chain_rule_count": len(scoped),
        "positions": positions,
        "duplicates": duplicates,
        "missing_required": list(dict.fromkeys(missing_required)),
        "late": late,
        "established_index": established_index,
        "established_anchor": ({
            "index": established_index,
            "comment": str(established_rule.get("comment") or "") if established_rule else "",
            "connection_state": sorted(connection_states(established_rule)) if established_rule else [],
            "candidate_count": len(candidates),
            "source": anchor_source,
        } if established_rule is not None else None),
        "established_candidates": [
            {
                "index": index,
                "comment": str(rule.get("comment") or ""),
                "connection_state": sorted(connection_states(rule)),
            }
            for index, rule in candidates
        ],
        "legacy_comment_position": legacy_position,
        "legacy_comment_duplicates": legacy_duplicates.get(established_comment, 0),
        "other_chain_collisions": ({established_comment: legacy_other_chains} if legacy_other_chains else {}),
    }

def posture_score(checks: list[dict]) -> int:
    """Weighted 0-100 score; critical checks count twice warnings."""
    possible = 0
    earned = 0
    for check in checks:
        severity = str(check.get("severity") or "warning")
        weight = 2 if severity == "critical" else 1
        possible += weight
        status = check.get("status")
        if status == "pass":
            earned += weight
        elif status == "warn":
            earned += weight * 0.5
    if not possible:
        return 100
    return int(round(earned * 100 / possible))


def make_check(
    key: str,
    name: str,
    *,
    ok: bool,
    severity: str = "critical",
    detail: str = "",
    warning: bool = False,
    remediation: str = "",
) -> dict:
    return {
        "key": key,
        "name": name,
        "severity": severity,
        "status": "warn" if warning else ("pass" if ok else "fail"),
        "detail": detail,
        "remediation": remediation,
    }
