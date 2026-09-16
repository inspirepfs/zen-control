"""Commissioning diagnostics and privacy-bounded support bundles for ZEN Control.

This module is intentionally read-only. It composes already-sanitized runtime
contracts, applies a second defensive redaction layer, and creates deterministic
support artefacts. It has no RouterOS mutation or policy-write authority.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import hmac
import io
import json
import os
import re
from typing import Any, Iterable, Mapping
import zipfile


COMMISSIONING_SCHEMA = "zen_commissioning_report_v1"
SUPPORT_BUNDLE_SCHEMA = "zen_support_bundle_v1"
SUPPORT_RELEASE = "v0.59.0.10"
_REDACTION_SALT = os.urandom(32)

_SECRET_KEY_FRAGMENTS = (
    "password", "passwd", "secret", "token", "cookie", "session",
    "authorization", "private_key", "p256dh", "endpoint", "webhook_url",
)
_IDENTITY_KEYS = {
    "host", "hostname", "router", "router_host", "username", "user",
    "ip", "ip_address", "address", "bind_ip", "lan_bind_ip", "local_host",
    "public_host", "origin", "url", "device", "device_name", "alias",
    "email", "from_address", "destination",
}
_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(password|passwd|secret|token|cookie|session|authorization|api[_-]?key)\s*[:=]\s*([^\s,;]+)"
)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_URL_QUERY_RE = re.compile(r"(https?://[^\s?#]+)\?[^\s#]*")


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _stable_marker(kind: str, value: str) -> str:
    # A process-local secret prevents low-entropy identifiers such as private
    # IPv4 addresses from being recovered by hashing a small candidate space.
    # Markers remain stable within one running ZEN process/bundle for correlation.
    digest = hmac.new(
        _REDACTION_SALT, str(value).encode("utf-8", "replace"), hashlib.sha256
    ).hexdigest()[:10]
    return f"<{kind}:{digest}>"


def _scrub_string(value: str, counters: Counter[str]) -> str:
    text = str(value)

    def assignment(match: re.Match[str]) -> str:
        counters["secret_assignments"] += 1
        return f"{match.group(1)}=<redacted>"

    text = _ASSIGNMENT_RE.sub(assignment, text)
    text, n = _URL_QUERY_RE.subn(r"\1?<redacted>", text)
    counters["url_queries"] += n
    text, n = _EMAIL_RE.subn("<email:redacted>", text)
    counters["emails"] += n
    text, n = _MAC_RE.subn("<mac:redacted>", text)
    counters["mac_addresses"] += n

    def ip_replace(match: re.Match[str]) -> str:
        candidate = match.group(0)
        parts = candidate.split(".")
        if all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
            counters["ip_addresses"] += 1
            return _stable_marker("ip", candidate)
        return candidate

    return _IPV4_RE.sub(ip_replace, text)


def sanitize_support_payload(payload: Any, *, counters: Counter[str] | None = None) -> Any:
    """Recursively redact sensitive values from a support payload.

    Curated support inputs should already be sanitized. This is a defence-in-
    depth boundary that prevents later fields or exception text from silently
    turning a public support bundle into a credential/household-data export.
    """
    counters = counters if counters is not None else Counter()
    if isinstance(payload, Mapping):
        result: dict[str, Any] = {}
        for raw_key, value in payload.items():
            key = str(raw_key)
            normalized = key.strip().lower().replace("-", "_")
            if any(fragment in normalized for fragment in _SECRET_KEY_FRAGMENTS):
                counters["secret_fields"] += 1
                result[key] = "<redacted>"
                continue
            if normalized in _IDENTITY_KEYS and value not in (None, "", False):
                counters["identity_fields"] += 1
                result[key] = _stable_marker("identity", str(value))
                continue
            result[key] = sanitize_support_payload(value, counters=counters)
        return result
    if isinstance(payload, (list, tuple, set)):
        return [sanitize_support_payload(item, counters=counters) for item in payload]
    if isinstance(payload, str):
        return _scrub_string(payload, counters)
    if payload is None or isinstance(payload, (bool, int, float)):
        return payload
    return _scrub_string(str(payload), counters)


def environment_presence(env: Mapping[str, str] | None = None) -> dict:
    """Return environment contract presence only; never environment values."""
    source = os.environ if env is None else env

    groups = {
        "application_auth": ("ADMIN_USER", "ADMIN_PASSWORD", "SESSION_SECRET"),
        "routeros": ("MIKROTIK_HOST", "MIKROTIK_PORT", "MIKROTIK_USER", "MIKROTIK_PASSWORD"),
        "telemetry": ("TELEMETRY_DB_NAME", "TELEMETRY_DB_USER", "TELEMETRY_DB_PASSWORD"),
        "local_https": ("ZEN_LOCAL_HOST", "ZEN_LAN_BIND_IP", "ZEN_SECURE_COOKIES"),
        "remote_access": ("ZEN_REMOTE_ACCESS_ENABLED", "ZEN_PUBLIC_HOST", "ZEN_ALLOWED_HOSTS"),
        "smtp": ("ZEN_SMTP_ENABLED", "ZEN_SMTP_HOST", "ZEN_SMTP_FROM", "ZEN_SMTP_TO"),
    }
    result = {}
    for name, keys in groups.items():
        configured = sum(1 for key in keys if str(source.get(key) or "").strip())
        result[name] = {
            "configured_fields": configured,
            "expected_fields": len(keys),
            "complete": configured == len(keys),
        }
    return {"schema": "zen_support_environment_presence_v1", "groups": result}


def audit_event_summary(rows: Iterable[Mapping[str, Any]]) -> dict:
    """Summarize recent audit metadata without actors, details or subjects."""
    event_counts: Counter[str] = Counter()
    severity_counts: Counter[str] = Counter()
    retained = 0
    for row in rows:
        retained += 1
        event = re.sub(r"[^A-Z0-9_]+", "_", str(row.get("event") or "UNKNOWN").upper())[:80]
        severity = re.sub(r"[^a-z]+", "", str(row.get("severity") or "info").lower())[:20] or "info"
        event_counts[event] += 1
        severity_counts[severity] += 1
    return {
        "schema": "zen_support_audit_summary_v1",
        "retained": retained,
        "events": dict(sorted(event_counts.items())),
        "severities": dict(sorted(severity_counts.items())),
    }


def _diag_state(row: Mapping[str, Any], *, required: bool) -> str:
    state = str(row.get("state") or "offline").lower()
    if state == "healthy":
        return "pass"
    if state == "warning":
        return "warn"
    if state == "critical":
        return "blocked" if required else "warn"
    return "unavailable"


def _commissioning_check(
    key: str,
    label: str,
    state: str,
    summary: str,
    *,
    required: bool,
    remediation: str = "",
    evidence: Mapping[str, Any] | None = None,
) -> dict:
    allowed = {"pass", "warn", "blocked", "unavailable", "not_configured"}
    normalized = state if state in allowed else "unavailable"
    return {
        "key": key,
        "label": label,
        "state": normalized,
        "required": bool(required),
        "summary": str(summary or "Evidence unavailable"),
        "remediation": str(remediation or ""),
        "evidence": dict(evidence or {}),
    }


def build_commissioning_report(
    *,
    version: str,
    diagnostics: Mapping[str, Any],
    runtime_health: Mapping[str, Any],
    operations: Mapping[str, Any],
    secure_transport: Mapping[str, Any],
    pwa: Mapping[str, Any],
    push: Mapping[str, Any] | None = None,
) -> dict:
    """Build a user-facing commissioning decision from independent evidence."""
    by_key = {str(row.get("key")): row for row in diagnostics.get("checks", []) if isinstance(row, Mapping)}
    checks: list[dict] = []

    specs = (
        ("application", "Application", True, "Check the application container and runtime logs."),
        ("policy_database", "Policy database", True, "Run database integrity/recovery checks before policy changes."),
        ("routeros_api", "RouterOS connectivity", True, "Check RouterOS API reachability and credentials, then re-run diagnostics."),
        ("security_authority", "RouterOS security & authority", True, "Resolve critical RouterOS security posture failures before enforcement."),
        ("managed_inventory", "Managed RouterOS inventory", False, "Re-run the read-only RouterOS inventory after connectivity is restored."),
        ("service_contracts", "Service enforcement contracts", False, "Open Service Intelligence and resolve degraded or unavailable contracts."),
        ("telemetry", "Telemetry database", False, "Check telemetry-db health and PostgreSQL connectivity."),
        ("traffic_ingest", "Traffic ingest", False, "Check the traffic-ingest container and its heartbeat."),
        ("dns_source", "DNS classification source", False, "Check Pi-hole/DNS source availability to traffic-ingest."),
        ("ipfix_source", "IPFIX flow source", False, "Check RouterOS IPFIX export and the goflow2 ingest path."),
        ("classifier_consumer", "Classifier consumer", False, "Check classifier heartbeat/catalogue publication."),
        ("reconciler", "Policy reconciler", True, "Check the reconciliation worker and clear any bounded hold only after the cause is understood."),
        ("incidents", "Incident monitor", False, "Open Incident Centre and inspect active incidents."),
        ("summary_delivery", "Summary delivery", False, "Check delivery configuration if scheduled summaries are expected."),
        ("durable_evidence", "Backup & durable evidence", True, "Create/verify a configuration snapshot before further changes."),
    )
    for key, label, required, remediation in specs:
        row = by_key.get(key)
        if not row:
            checks.append(_commissioning_check(key, label, "unavailable", "Evidence not present in diagnostic capture", required=required, remediation=remediation))
            continue
        checks.append(_commissioning_check(
            key,
            label,
            _diag_state(row, required=required),
            str(row.get("summary") or ""),
            required=required,
            remediation=remediation if str(row.get("state")) != "healthy" else "",
            evidence={"diagnostic_state": row.get("state")},
        ))

    runtime_ok = bool(runtime_health.get("ok"))
    checks.append(_commissioning_check(
        "runtime_workers",
        "Runtime workers",
        "pass" if runtime_ok else "blocked",
        "Required runtime workers and durable read models are healthy" if runtime_ok else "Required runtime worker/read-model health is degraded",
        required=True,
        remediation="Open runtime health and resolve stopped workers, failed prepared work or database health failures.",
        evidence={
            "status": runtime_health.get("status", "unknown"),
            "failed_prepared": int((runtime_health.get("background_read_models") or {}).get("failed_latest") or 0),
            "retrying_prepared": int((runtime_health.get("background_read_models") or {}).get("retrying_latest") or 0),
        },
    ))

    readiness_ok = bool(operations.get("ok"))
    checks.append(_commissioning_check(
        "operations_readiness",
        "Operational readiness",
        "pass" if readiness_ok else "blocked",
        "Core operational readiness is proven" if readiness_ok else "One or more core operational readiness checks failed",
        required=True,
        remediation="Open Settings → Operations and resolve each failed readiness component.",
        evidence={"issue_count": len(operations.get("issues") or [])},
    ))

    transport_ready = bool(secure_transport.get("commissioning_ready"))
    local = secure_transport.get("local_https") or {}
    checks.append(_commissioning_check(
        "https",
        "HTTPS transport",
        "pass" if transport_ready else ("warn" if local.get("configured") else "not_configured"),
        "HTTPS transport is configured and hardened" if transport_ready else "HTTPS is not fully commissioned",
        required=False,
        remediation="Complete local HTTPS/secure-cookie/Host-allowlist commissioning if browser installation or remote access is required.",
        evidence={"state": secure_transport.get("state", "unknown"), "local_state": local.get("state", "unknown")},
    ))

    secure_origin = bool((secure_transport.get("pwa") or {}).get("secure_origin_configured"))
    checks.append(_commissioning_check(
        "pwa",
        "PWA server prerequisites",
        "pass" if secure_origin else "not_configured",
        "Secure-origin server prerequisite is configured" if secure_origin else "PWA secure-origin prerequisite is not configured",
        required=False,
        remediation="Use the device-side PWA diagnostics after HTTPS is working; installability remains a browser/device decision.",
        evidence={"mode": pwa.get("mode", "unknown"), "secure_origin_configured": secure_origin},
    ))

    push = dict(push or {})
    subscriptions = push.get("subscriptions") or {}
    subscription_count = int(subscriptions.get("enabled") or subscriptions.get("active") or subscriptions.get("total") or 0)
    worker_running = bool(push.get("worker_running"))
    if subscription_count > 0 and worker_running:
        push_state, push_summary = "pass", "Browser push worker is running with active subscriptions"
    elif worker_running:
        push_state, push_summary = "not_configured", "Browser push worker is available but no active subscription is commissioned"
    else:
        push_state, push_summary = "warn", "Browser push delivery worker is not running"
    checks.append(_commissioning_check(
        "push_notifications", "Push notifications", push_state, push_summary,
        required=False,
        remediation="Use notification/PWA commissioning if browser push is required.",
        evidence={"worker_running": worker_running, "subscriptions": subscription_count},
    ))

    counts = {state: sum(1 for item in checks if item["state"] == state) for state in ("pass", "warn", "blocked", "unavailable", "not_configured")}
    required_bad = [item for item in checks if item["required"] and item["state"] in {"blocked", "unavailable"}]
    advisory_bad = [item for item in checks if not item["required"] and item["state"] in {"warn", "blocked", "unavailable"}]
    if required_bad:
        overall = "blocked"
    elif advisory_bad:
        overall = "ready_with_warnings"
    else:
        overall = "ready"

    return {
        "schema": COMMISSIONING_SCHEMA,
        "release": SUPPORT_RELEASE,
        "version": str(version),
        "captured_at": _now_iso(),
        "overall": overall,
        "counts": counts,
        "checks": checks,
        "authority": "read_only_no_routeros_write_authority",
        "notes": [
            "Missing evidence is never converted to PASS.",
            "Optional NOT_CONFIGURED features do not block core commissioning.",
            "RouterOS policy mutations remain owned by the existing reconciler/adapter authority path.",
        ],
    }


def commissioning_summary(report: Mapping[str, Any]) -> str:
    title = "ZEN Control Commissioning"
    lines = [title, "=" * len(title), "", f"Release: {report.get('release', SUPPORT_RELEASE)}", f"Application: {report.get('version', 'unknown')}", f"Captured: {report.get('captured_at', 'unknown')}", ""]
    for item in report.get("checks", []):
        label = str(item.get("label") or item.get("key") or "Check")[:34]
        state = str(item.get("state") or "unavailable").upper()
        lines.append(f"{label:<36} {state}")
    lines.extend(["", f"Overall: {str(report.get('overall') or 'unknown').replace('_', ' ').upper()}"])
    actionable = [item for item in report.get("checks", []) if item.get("state") in {"warn", "blocked", "unavailable"}]
    if actionable:
        lines.extend(["", "Actions:"])
        for index, item in enumerate(actionable, 1):
            remediation = str(item.get("remediation") or item.get("summary") or "Review this check")
            lines.append(f"{index}. {item.get('label')}: {remediation}")
    lines.extend(["", "Privacy: this summary contains no credentials, household device identities, raw DNS/activity data or raw exception text."])
    return "\n".join(lines) + "\n"


def build_support_bundle(
    *,
    version: str,
    commissioning: Mapping[str, Any],
    diagnostics: Mapping[str, Any],
    runtime_health: Mapping[str, Any],
    secure_transport: Mapping[str, Any],
    pwa: Mapping[str, Any],
    environment: Mapping[str, Any],
    audit_summary: Mapping[str, Any],
) -> tuple[bytes, dict]:
    """Create a ZIP support bundle with a defence-in-depth redaction pass."""
    counters: Counter[str] = Counter()
    curated = {
        "commissioning.json": commissioning,
        "diagnostics.json": diagnostics,
        "runtime-health.json": runtime_health,
        "secure-transport.json": secure_transport,
        "pwa.json": pwa,
        "environment-presence.json": environment,
        "audit-summary.json": audit_summary,
    }
    sanitized = {name: sanitize_support_payload(payload, counters=counters) for name, payload in curated.items()}
    summary = sanitize_support_payload(commissioning_summary(sanitized["commissioning.json"]), counters=counters)
    generated_at = _now_iso()
    manifest = {
        "schema": SUPPORT_BUNDLE_SCHEMA,
        "release": SUPPORT_RELEASE,
        "version": str(version),
        "generated_at": generated_at,
        "files": ["manifest.json", "summary.txt", *sorted(sanitized)],
        "redaction": {
            "applied": True,
            "counts": dict(sorted(counters.items())),
            "policy": "credentials/tokens/session material removed; household/network identifiers pseudonymized or omitted",
        },
        "privacy": {
            "safe_for_public_issue_by_design": True,
            "omitted": [
                "passwords, tokens, cookies and session material",
                "push endpoints and cryptographic keys",
                "raw device names, IP/MAC addresses and RouterOS host identity",
                "raw DNS queries, traffic records, audit details and incident details",
                "raw Docker/application logs",
            ],
        },
        "authority": "read_only_no_routeros_write_authority",
    }

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        archive.writestr("summary.txt", summary)
        for name in sorted(sanitized):
            archive.writestr(name, json.dumps(sanitized[name], indent=2, sort_keys=True) + "\n")
    return buffer.getvalue(), manifest
