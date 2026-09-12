"""Evidence-led managed-device bypass detection.

Bypass monitoring deliberately separates *evidence* from *proof*. Some signals are strong
(e.g. a managed client reaching a known DoH endpoint or an Internet resolver on
port 53), while default VPN/proxy ports are only heuristics because applications
can move to arbitrary ports and unrelated software can reuse common ports.

The module therefore provides:

* a small, explicit RouterOS SNI hardening contract for well-known DoH hosts;
* flow/domain classifiers with confidence/severity labels;
* a bounded risk summary used only for operator visibility.

None of the VPN/proxy heuristics are automatic enforcement authority.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable


# Direct TLS-host drop rules. These are intentionally narrow and are validated
# by the app as a warning-level hardening contract rather than a prerequisite
# for the core RouterOS policy write gate. ECH, IP-literal DoH and unknown
# providers can evade SNI inspection, so this list must never be presented as
# complete DoH coverage.
DOH_ROUTER_RULES = (
    {
        "comment": "MC - Block DoH Google",
        "tls_host": "dns.google",
        "provider": "Google Public DNS",
    },
    {
        "comment": "MC - Block DoH Cloudflare",
        "tls_host": "*cloudflare-dns.com",
        "provider": "Cloudflare",
    },
    {
        "comment": "MC - Block DoH Quad9",
        "tls_host": "dns.quad9.net",
        "provider": "Quad9",
    },
    {
        "comment": "MC - Block DoH Quad9 Secure",
        "tls_host": "dns10.quad9.net",
        "provider": "Quad9",
    },
    {
        "comment": "MC - Block DoH Quad9 ECS",
        "tls_host": "dns11.quad9.net",
        "provider": "Quad9",
    },
    {
        "comment": "MC - Block DoH OpenDNS",
        "tls_host": "doh.opendns.com",
        "provider": "OpenDNS",
    },
    {
        "comment": "MC - Block DoH NextDNS",
        "tls_host": "dns.nextdns.io",
        "provider": "NextDNS",
    },
    {
        "comment": "MC - Block DoH AdGuard",
        "tls_host": "dns.adguard-dns.com",
        "provider": "AdGuard DNS",
    },
    {
        "comment": "MC - Block DoH CleanBrowsing",
        "tls_host": "doh.cleanbrowsing.org",
        "provider": "CleanBrowsing",
    },
)


# Suffixes used for telemetry correlation. A flow that has been enriched with
# one of these domains is stronger evidence than a DNS lookup alone.
DOH_DOMAIN_SUFFIXES = (
    "dns.google",
    "cloudflare-dns.com",
    "dns.quad9.net",
    "dns10.quad9.net",
    "dns11.quad9.net",
    "doh.opendns.com",
    "dns.nextdns.io",
    "dns.adguard-dns.com",
    "doh.cleanbrowsing.org",
)


# Common defaults only. These are awareness heuristics, not protocol proof.
PORT_SIGNALS = {
    ("TCP", 53): {
        "key": "external_dns",
        "label": "External DNS",
        "category": "dns",
        "confidence": "high",
        "severity": "high",
        "weight": 16,
        "detail": "Managed client contacted an Internet DNS server directly on TCP/53.",
    },
    ("UDP", 53): {
        "key": "external_dns",
        "label": "External DNS",
        "category": "dns",
        "confidence": "high",
        "severity": "high",
        "weight": 16,
        "detail": "Managed client contacted an Internet DNS server directly on UDP/53.",
    },
    ("TCP", 853): {
        "key": "dot_attempt",
        "label": "Encrypted DNS / DoT attempt",
        "category": "dns",
        "confidence": "high",
        "severity": "high",
        "weight": 14,
        "detail": "Outbound TCP/853 is consistent with DNS-over-TLS. The restricted-device hardening policy should block it.",
    },
    ("UDP", 853): {
        "key": "doq_attempt",
        "label": "Encrypted DNS / DoQ attempt",
        "category": "dns",
        "confidence": "high",
        "severity": "high",
        "weight": 14,
        "detail": "Outbound UDP/853 is consistent with DNS-over-QUIC. The restricted-device hardening policy should block it.",
    },
    ("UDP", 500): {
        "key": "ipsec_ike",
        "label": "IPsec / IKE default port",
        "category": "vpn",
        "confidence": "medium",
        "severity": "medium",
        "weight": 8,
        "detail": "UDP/500 is commonly used for IKE/IPsec, but the port alone is not proof of a VPN.",
    },
    ("UDP", 4500): {
        "key": "ipsec_natt",
        "label": "IPsec NAT-T default port",
        "category": "vpn",
        "confidence": "medium",
        "severity": "medium",
        "weight": 9,
        "detail": "UDP/4500 is commonly used for IPsec NAT-T, but the port alone is not proof of a VPN.",
    },
    ("UDP", 51820): {
        "key": "wireguard_default",
        "label": "WireGuard default port",
        "category": "vpn",
        "confidence": "medium",
        "severity": "medium",
        "weight": 8,
        "detail": "UDP/51820 is WireGuard's common default; WireGuard can use any UDP port.",
    },
    ("UDP", 1194): {
        "key": "openvpn_default",
        "label": "OpenVPN default port",
        "category": "vpn",
        "confidence": "medium",
        "severity": "medium",
        "weight": 8,
        "detail": "UDP/1194 is a common OpenVPN default; OpenVPN can use other ports.",
    },
    ("TCP", 1194): {
        "key": "openvpn_default",
        "label": "OpenVPN default port",
        "category": "vpn",
        "confidence": "medium",
        "severity": "medium",
        "weight": 8,
        "detail": "TCP/1194 is a common OpenVPN default; OpenVPN can use other ports.",
    },
    ("UDP", 1701): {
        "key": "l2tp_default",
        "label": "L2TP default port",
        "category": "vpn",
        "confidence": "medium",
        "severity": "medium",
        "weight": 7,
        "detail": "UDP/1701 is commonly associated with L2TP.",
    },
    ("TCP", 1723): {
        "key": "pptp_default",
        "label": "PPTP control port",
        "category": "vpn",
        "confidence": "medium",
        "severity": "medium",
        "weight": 7,
        "detail": "TCP/1723 is the PPTP control port; GRE data-plane visibility is separate.",
    },
    ("TCP", 1080): {
        "key": "socks_proxy",
        "label": "SOCKS proxy default port",
        "category": "proxy",
        "confidence": "low",
        "severity": "low",
        "weight": 3,
        "detail": "TCP/1080 is a common SOCKS proxy port; this is a weak heuristic only.",
    },
    ("TCP", 3128): {
        "key": "http_proxy",
        "label": "HTTP proxy common port",
        "category": "proxy",
        "confidence": "low",
        "severity": "low",
        "weight": 3,
        "detail": "TCP/3128 is commonly used by HTTP proxies; this is a weak heuristic only.",
    },
    ("TCP", 8080): {
        "key": "http_proxy",
        "label": "HTTP proxy common port",
        "category": "proxy",
        "confidence": "low",
        "severity": "low",
        "weight": 2,
        "detail": "TCP/8080 is used by proxies and many unrelated web services; low-confidence only.",
    },
    ("TCP", 8118): {
        "key": "http_proxy",
        "label": "HTTP proxy common port",
        "category": "proxy",
        "confidence": "low",
        "severity": "low",
        "weight": 3,
        "detail": "TCP/8118 is commonly associated with local/HTTP proxies; low-confidence only.",
    },
    ("TCP", 8888): {
        "key": "http_proxy",
        "label": "HTTP proxy common port",
        "category": "proxy",
        "confidence": "low",
        "severity": "low",
        "weight": 2,
        "detail": "TCP/8888 is sometimes used by proxies and unrelated services; low-confidence only.",
    },
}

BYPASS_PORTS = tuple(sorted({port for _, port in PORT_SIGNALS}))


def normalize_domain(value: str | None) -> str:
    return str(value or "").strip().lower().rstrip(".")


def matches_domain_suffix(domain: str | None, suffixes: Iterable[str]) -> str | None:
    value = normalize_domain(domain)
    if not value:
        return None
    for suffix in suffixes:
        suffix = normalize_domain(suffix)
        if value == suffix or value.endswith("." + suffix):
            return suffix
    return None


def classify_port_signal(protocol: str | None, dst_port: int | str | None) -> dict | None:
    proto = str(protocol or "").strip().upper()
    try:
        port = int(dst_port or 0)
    except (TypeError, ValueError):
        return None
    signal = PORT_SIGNALS.get((proto, port))
    if not signal:
        return None
    return {**signal, "protocol": proto, "dst_port": port, "evidence": "port"}


def classify_doh_domain(domain: str | None, *, source: str = "flow") -> dict | None:
    suffix = matches_domain_suffix(domain, DOH_DOMAIN_SUFFIXES)
    if not suffix:
        return None
    if source == "flow":
        return {
            "key": "known_doh_flow",
            "label": "Known DoH endpoint traffic",
            "category": "dns",
            "confidence": "high",
            "severity": "high",
            "weight": 18,
            "detail": (
                "Telemetry associated an outbound flow with a known DoH endpoint. "
                "This is strong endpoint evidence, but not cryptographic proof of the HTTP request type."
            ),
            "evidence": "domain-flow",
            "matched_suffix": suffix,
        }
    return {
        "key": "known_doh_lookup",
        "label": "Known DoH endpoint lookup",
        "category": "dns",
        "confidence": "medium",
        "severity": "medium",
        "weight": 5,
        "detail": (
            "Pi-hole observed a lookup for a known DoH endpoint. A lookup shows intent/interest, "
            "not proof that a DoH tunnel was established."
        ),
        "evidence": "dns-query",
        "matched_suffix": suffix,
    }


def _score_status(score: int) -> str:
    if score <= 0:
        return "clear"
    if score < 20:
        return "watch"
    if score < 45:
        return "elevated"
    return "high"


def summarize_bypass_evidence(evidence: Iterable[dict]) -> dict:
    """Return a bounded operator-facing risk summary.

    Repeated packets do not linearly inflate the score. We score unique signal
    keys per device and add a small bounded recurrence bonus. This prevents one
    chatty flow from dominating the posture while still making repeated evidence
    visible.
    """
    rows = [dict(item) for item in evidence or []]
    by_device: dict[str, dict] = {}
    global_unique: dict[tuple[str, str], int] = {}

    for row in rows:
        ip = str(row.get("client_ip") or "unknown")
        key = str(row.get("key") or "unknown")
        weight = max(0, int(row.get("weight") or 0))
        flows = max(0, int(row.get("flows") or 0))
        bucket = by_device.setdefault(
            ip,
            {
                "client_ip": ip,
                "score": 0,
                "status": "clear",
                "signals": 0,
                "flows": 0,
                "last_seen": None,
                "categories": set(),
                "_unique": {},
            },
        )
        bucket["signals"] += 1
        bucket["flows"] += flows
        bucket["categories"].add(str(row.get("category") or "other"))
        seen_weight = bucket["_unique"].get(key, 0)
        bucket["_unique"][key] = max(seen_weight, weight)
        last_seen = row.get("last_seen")
        if last_seen and (not bucket["last_seen"] or str(last_seen) > str(bucket["last_seen"])):
            bucket["last_seen"] = last_seen
        global_unique[(ip, key)] = max(global_unique.get((ip, key), 0), weight)

    for bucket in by_device.values():
        base = sum(bucket.pop("_unique").values())
        recurrence = min(10, max(0, bucket["signals"] - 1) * 2)
        bucket["score"] = min(100, base + recurrence)
        bucket["status"] = _score_status(bucket["score"])
        bucket["categories"] = sorted(bucket["categories"])

    overall_score = min(100, sum(global_unique.values()) + min(15, max(0, len(rows) - len(global_unique))))
    affected = sorted(by_device.values(), key=lambda item: (-item["score"], item["client_ip"]))
    return {
        "score": overall_score,
        "status": _score_status(overall_score),
        "signals": len(rows),
        "affected_devices": len(by_device),
        "high_confidence": sum(1 for row in rows if row.get("confidence") == "high"),
        "medium_confidence": sum(1 for row in rows if row.get("confidence") == "medium"),
        "low_confidence": sum(1 for row in rows if row.get("confidence") == "low"),
        "devices": affected,
        "limitations": (
            "Network telemetry cannot prove or exclude arbitrary VPN/proxy/DoH traffic hidden inside generic HTTPS/443, "
            "custom ports, ECH or application-specific tunnelling. Signals are operator evidence, not identity proof."
        ),
    }
