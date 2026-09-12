"""Evidence-led classification workbench helpers.

This module never mutates policy or RouterOS state and never promotes a hostname
hint into a classification.  It only compares retained telemetry with the
*current* service catalogue so an operator can decide what to review next.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path


def _domain(value: str) -> str:
    return str(value or "").strip().lower().rstrip(".")


def _token(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").strip().lower())


def _domain_matches_suffix(domain: str, suffix: str) -> bool:
    domain = _domain(domain)
    suffix = _domain(suffix).removeprefix("*.")
    return bool(domain and suffix and (domain == suffix or domain.endswith("." + suffix)))


def _service_name_tokens(service: dict) -> set[str]:
    values = {service.get("key"), service.get("name")}
    tokens = set()
    for value in values:
        compact = _token(value)
        if len(compact) >= 4:
            tokens.add(compact)
        for part in re.split(r"[^a-z0-9]+", str(value or "").lower()):
            if len(part) >= 4:
                tokens.add(part)
    return tokens



def read_classifier_consumer_status(path=None, now=None, stale_after_seconds=30):
    """Read the sanitized telemetry-consumer heartbeat without inferring health."""
    target = Path(path or os.getenv("CLASSIFIER_STATUS_FILE", "/telemetry-state/classifier-status.json"))
    base = {
        "schema": "zen_classifier_consumer_status_v1",
        "availability": "unavailable",
        "source": "unknown",
        "services": 0,
        "signatures": 0,
        "has_live": False,
        "degraded": True,
        "error": "Classifier consumer heartbeat is unavailable",
        "observed_at": None,
        "age_seconds": None,
    }
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or payload.get("schema") != "zen_classifier_consumer_status_v1":
            raise ValueError("Unsupported classifier consumer status document")
        observed = datetime.fromisoformat(str(payload.get("observed_at") or ""))
        if observed.tzinfo is None:
            observed = observed.replace(tzinfo=timezone.utc)
        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None:
            current = current.replace(tzinfo=timezone.utc)
        age = max(0.0, (current.astimezone(timezone.utc) - observed.astimezone(timezone.utc)).total_seconds())
        source = str(payload.get("source") or "unknown")
        availability = "stale" if age > max(1, int(stale_after_seconds)) else "available"
        degraded = availability != "available" or source != "live"
        return {
            "schema": "zen_classifier_consumer_status_v1",
            "availability": availability,
            "source": source,
            "services": max(0, int(payload.get("services") or 0)),
            "signatures": max(0, int(payload.get("signatures") or 0)),
            "has_live": bool(payload.get("has_live")),
            "degraded": degraded,
            "error": str(payload.get("error") or ""),
            "observed_at": observed.astimezone(timezone.utc).isoformat(),
            "age_seconds": round(age, 1),
        }
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        base["error"] = f"{type(exc).__name__}: {exc}"
        return base

def build_candidate_reviews(candidates, services, unknown_queries_total=0):
    """Annotate unknown DNS rows with current-catalogue review evidence.

    ``signature_match`` is deterministic against the current DNS suffix
    catalogue. ``name_hint`` is intentionally weaker and exists only to make
    manual review faster. Neither state rewrites retained telemetry or changes
    policy/enforcement.
    """
    concrete = [
        dict(item) for item in (services or [])
        if str(item.get("key") or "") and not item.get("members")
    ]
    total = max(0, int(unknown_queries_total or 0))
    result = []
    for raw in candidates or []:
        item = dict(raw)
        domain = _domain(item.get("domain"))
        queries = max(0, int(item.get("queries") or 0))
        signature_matches = []
        for service in concrete:
            matching = [
                suffix for suffix in (service.get("dns_suffixes") or [])
                if _domain_matches_suffix(domain, suffix)
            ]
            if matching:
                signature_matches.append({
                    "key": str(service.get("key") or ""),
                    "name": str(service.get("name") or service.get("key") or ""),
                    "suffixes": matching,
                    "classifier_enabled": bool(service.get("classifier_enabled", True)),
                    "builtin": bool(service.get("builtin")),
                })

        name_hints = []
        if not signature_matches:
            compact_domain = _token(domain)
            for service in concrete:
                tokens = _service_name_tokens(service)
                matched = sorted(token for token in tokens if token in compact_domain)
                if matched:
                    name_hints.append({
                        "key": str(service.get("key") or ""),
                        "name": str(service.get("name") or service.get("key") or ""),
                        "tokens": matched,
                    })

        if signature_matches:
            state = "signature_match"
            enabled = any(match["classifier_enabled"] for match in signature_matches)
            action = "Check catalogue timing / telemetry consumer" if enabled else "Review disabled classifier"
        elif name_hints:
            state = "name_hint"
            action = "Review existing service signatures"
        else:
            state = "unmatched"
            action = "Review as a custom-service candidate"

        item.update({
            "domain": domain,
            "queries": queries,
            "unknown_query_share": round(queries * 100 / total, 1) if total else None,
            "review_state": state,
            "signature_matches": signature_matches,
            "name_hints": name_hints,
            "recommended_action": action,
            "prefill_dns": domain,
        })
        result.append(item)
    return result


def _pp_delta(current, previous):
    if current is None or previous is None:
        return None
    return round(float(current) - float(previous), 1)


def _metric_direction(value):
    if value is None:
        return None
    if value > 0.2:
        return "up"
    if value < -0.2:
        return "down"
    return "flat"


def build_classification_workbench(
    current,
    previous,
    daily,
    candidates,
    services,
    service_changes=None,
    hours=24,
):
    """Compose the read-only classification intelligence contract."""
    current = dict(current or {})
    previous = dict(previous or {})
    services = [dict(item) for item in (services or [])]
    concrete = [item for item in services if not item.get("members")]
    enabled = [item for item in concrete if item.get("classifier_enabled", True)]
    dns_signatures = sum(len(item.get("dns_suffixes") or []) for item in enabled)
    tls_signatures = sum(len(item.get("tls_patterns") or []) for item in enabled)
    unknown_queries = max(0, int(current.get("dns_unclassified_queries") or 0))
    candidate_rows = build_candidate_reviews(
        candidates,
        services,
        unknown_queries,
    )
    states = {"signature_match": 0, "name_hint": 0, "unmatched": 0}
    for item in candidate_rows:
        states[item["review_state"]] += 1

    traffic_delta = _pp_delta(current.get("traffic_percent"), previous.get("traffic_percent"))
    dns_delta = _pp_delta(current.get("dns_percent"), previous.get("dns_percent"))
    directions = {_metric_direction(value) for value in (traffic_delta, dns_delta)} - {None}
    if not directions:
        trend = "unknown"
    elif "up" in directions:
        trend = "improving"
    elif "down" in directions:
        trend = "declining"
    else:
        trend = "stable"

    listed_queries = sum(max(0, int(item.get("queries") or 0)) for item in candidate_rows)
    candidate_accounting_valid = listed_queries <= unknown_queries if unknown_queries else listed_queries == 0
    candidate_computed_share_percent = (
        round(listed_queries * 100 / unknown_queries, 1) if unknown_queries else None
    )
    candidate_coverage_percent = (
        candidate_computed_share_percent if candidate_accounting_valid else None
    )
    if not candidate_accounting_valid:
        for item in candidate_rows:
            item["unknown_query_share"] = None

    traffic_available = bool(current.get("traffic_available", True))
    dns_available = bool(current.get("dns_available", True))
    traffic_accounting_valid = bool(current.get("traffic_accounting_valid", True))
    dns_accounting_valid = bool(current.get("dns_accounting_valid", True))
    available_accounting_valid = (
        (not traffic_available or traffic_accounting_valid)
        and (not dns_available or dns_accounting_valid)
    )

    return {
        "schema": "zen_classification_intelligence_v1",
        "hours": int(hours),
        "current": current,
        "previous": previous,
        "deltas": {
            "traffic_pp": traffic_delta,
            "dns_pp": dns_delta,
        },
        "trend": trend,
        "daily": list(daily or []),
        "candidates": candidate_rows,
        "candidate_counts": states,
        "candidate_accounting": {
            "unknown_queries": unknown_queries,
            "listed_queries": listed_queries,
            "listed_share_percent": candidate_coverage_percent,
            "computed_share_percent": candidate_computed_share_percent,
            "valid": candidate_accounting_valid,
        },
        "evidence": {
            "status": current.get("evidence_status") or ("measured" if (current.get("traffic_observed") or current.get("dns_observed")) else "no_evidence"),
            "traffic_available": traffic_available,
            "dns_available": dns_available,
            "traffic_observed": bool(current.get("traffic_observed")),
            "dns_observed": bool(current.get("dns_observed")),
            "traffic_status": current.get("traffic_evidence_status") or (
                "unavailable" if not traffic_available else
                "inconsistent" if not traffic_accounting_valid else
                "measured" if current.get("traffic_observed") else "no_evidence"
            ),
            "dns_status": current.get("dns_evidence_status") or (
                "unavailable" if not dns_available else
                "inconsistent" if not dns_accounting_valid else
                "measured" if current.get("dns_observed") else "no_evidence"
            ),
            "traffic_accounting_valid": traffic_accounting_valid,
            "dns_accounting_valid": dns_accounting_valid,
            "accounting_valid": available_accounting_valid and candidate_accounting_valid,
            "errors": list(current.get("evidence_errors") or []),
        },
        "catalogue": {
            "services": len(concrete),
            "classifier_enabled": len(enabled),
            "classifier_disabled": len(concrete) - len(enabled),
            "dns_signatures": dns_signatures,
            "tls_signatures": tls_signatures,
        },
        "service_changes": list(service_changes or []),
        "evidence_note": (
            "Classification is derived from retained DNS/IPFIX labels and the current service catalogue. "
            "A hostname name-hint is only a manual-review clue; it is never promoted to service attribution, "
            "browser history, foreground application usage or proof of user intent."
        ),
    }
